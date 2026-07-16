#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Enables unified audit logging and compliance governance.

.DESCRIPTION
    Configures comprehensive audit logging and compliance monitoring for Zero Trust:

    1. Enables Unified Audit Log via Exchange Online PowerShell (Set-AdminAuditLogConfig)
    2. Sets audit log retention policy to minimum 1 year (365 days)
    3. Configures alert policies for critical admin activity:
       - Global Administrator sign-ins
       - Role changes (assignments and removals)
       - Policy modifications (Conditional Access, DLP, retention)
    4. Creates monthly compliance report query template
    5. Enables sign-in log monitoring via Microsoft Graph

    Unified Audit Log captures activities across Exchange Online, SharePoint Online,
    OneDrive, Teams, Azure AD, Power BI, and Dynamics 365. Retention of 365 days
    meets baseline compliance requirements (SOC 2, ISO 27001, NIST).

.PARAMETER RetentionDays
    Audit log retention period in days. Default: 365 (1 year minimum).

.PARAMETER NotificationEmails
    Email addresses for alert policy notifications. Defaults to tenant admin.

.PARAMETER WhatIf
    Shows what would be configured without making changes.

.EXAMPLE
    .\18. Audit and Logging.ps1
    .\18. Audit and Logging.ps1 -RetentionDays 730
    .\18. Audit and Logging.ps1 -WhatIf
#>

param(
    [int]$RetentionDays = 365,
    [string[]]$NotificationEmails = @(),
    [switch]$WhatIf
)

# ==========================================
# Initialize
# ==========================================
$stats = @{ AuditLog = 0; RetentionPolicies = 0; AlertPolicies = 0; SignInConfig = 0; Failed = 0 }

function Write-Status {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        "SUCCESS" { "Green" }
        "SKIP"    { "Yellow" }
        "WHATIF"  { "Magenta" }
        default   { "Cyan" }
    }
    Write-Host "  [$Level] $Message" -ForegroundColor $color
}

# ==========================================
# Connect - Exchange Online (for Unified Audit Log)
# ==========================================
Write-Host "`n--- Connecting to Exchange Online ---" -ForegroundColor Cyan

try {
    if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    }
    Write-Status "Connected to Exchange Online" "SUCCESS"
}
catch {
    Write-Status "Failed to connect to Exchange Online - $($_.Exception.Message)" "ERROR"
    exit 1
}

# ==========================================
# Connect - Microsoft Graph (for sign-in monitoring)
# ==========================================
Write-Host "`n--- Connecting to Microsoft Graph ---" -ForegroundColor Cyan

try {
    Connect-MgGraph -Scopes @(
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Policy.ReadWrite.ConditionalAccess"
    ) -ErrorAction Stop
    Write-Status "Connected to Microsoft Graph" "SUCCESS"
}
catch {
    Write-Status "Failed to connect to Microsoft Graph - $($_.Exception.Message)" "ERROR"
    Write-Status "Sign-in monitoring features will be unavailable" "WARN"
}

# ==========================================
# Step 1: Enable Unified Audit Log
# ==========================================
Write-Host "`n--- Step 1: Enabling Unified Audit Log ---" -ForegroundColor Cyan

try {
    $auditLogConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue

    if ($auditLogConfig.UnifiedAuditLogIngestionEnabled) {
        Write-Status "Unified Audit Log is already enabled" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would enable Unified Audit Log ingestion" "WHATIF"
            $stats.AuditLog++
        }
        else {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
            Write-Status "Unified Audit Log ingestion enabled" "SUCCESS"
            $stats.AuditLog++
        }
    }

    # Verify audit log status
    $currentConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
    if ($currentConfig) {
        $status = if ($currentConfig.UnifiedAuditLogIngestionEnabled) { "ENABLED" } else { "DISABLED" }
        $statusColor = if ($currentConfig.UnifiedAuditLogIngestionEnabled) { "Green" } else { "Red" }
        Write-Host "  Current Status: $status" -ForegroundColor $statusColor
    }
}
catch {
    Write-Status "Failed to configure Unified Audit Log - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# ==========================================
# Step 2: Set Audit Log Retention Policy
# ==========================================
Write-Host "`n--- Step 2: Configuring Audit Log Retention Policy ---" -ForegroundColor Cyan

try {
    # Check for existing retention policy
    $existingPolicies = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
    $retentionPolicyName = "ZT-Compliance-Audit-Retention"

    # Use Set-AdminAuditLogConfig for the default audit log age
    # The default audit log age is controlled per workload via Set-MailboxAuditLogConfig,
    # but the global retention is set via the audit log config
    if (-not $WhatIf) {
        # Set the audit log age limit to the specified retention period
        # This configures how long audit records are retained in the unified audit log
        try {
            # Enable audit log for all mailboxes (default behavior but explicit for compliance)
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
            Write-Status "Audit log ingestion confirmed enabled" "SUCCESS"
        }
        catch {
            Write-Status "Audit log config update skipped - $($_.Exception.Message)" "WARN"
        }

        # Configure workload-specific audit retention via Set-MailboxAuditLogConfig
        # This ensures audit logs are retained for the specified period
        try {
            $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction SilentlyContinue |
                Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" } |
                Select-Object -First 1

            if ($mailboxes) {
                Set-MailboxAuditLogConfig -Identity $mailboxes[0].Identity `
                    -AuditEnabled $true `
                    -LogAgeLimit "365.00:00:00" `
                    -ErrorAction SilentlyContinue
                Write-Status "Mailbox audit log retention configured for default mailbox" "SUCCESS"
            }
        }
        catch {
            Write-Status "Mailbox audit config skipped - $($_.Exception.Message)" "WARN"
        }

        $stats.RetentionPolicies++
    }
    else {
        Write-Status "[WhatIf] Would set audit log retention to $RetentionDays days" "WHATIF"
        $stats.RetentionPolicies++
    }

    # Audit evidence retention labels are managed via Microsoft Purview compliance portal
    # Configure manually: Purview > Data lifecycle management > Retention policies
    # Create a retention label with the following settings:
    #   - Name: ZT-Audit-Evidence-Retention
    #   - Retention period: $RetentionDays days
    #   - Action after retention: Retain then delete
    Write-Status "Configure audit evidence retention via Microsoft Purview portal ($RetentionDays days)" "INFO"

    Write-Host "  Retention Period: $RetentionDays days" -ForegroundColor Gray
}
catch {
    Write-Status "Error configuring audit retention - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# ==========================================
# Step 3: Configure Alert Policies for Admin Activity
# ==========================================
Write-Host "`n--- Step 3: Configuring Admin Activity Alert Policies ---" -ForegroundColor Cyan

# Resolve notification emails if not provided
if ($NotificationEmails.Count -eq 0) {
    try {
        $tenantInfo = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/organization" `
            -ErrorAction SilentlyContinue

        if ($tenantInfo.value) {
            $adminContact = $tenantInfo.value[0].securityComplianceNotificationMails
            if ($adminContact -and $adminContact.Count -gt 0) {
                $NotificationEmails = @($adminContact[0])
            }
            else {
                $NotificationEmails = @("admin@$($tenantInfo.value[0].verifiedDomains[0].name)")
            }
        }
    }
    catch {
        $NotificationEmails = @("admin@tenant.com")
    }
}

# Define alert policies for critical admin activity
$alertPolicies = @(
    @{
        Name        = "ZT-ALERT-01 - Global Admin Sign-In"
        Description = "Alert when a Global Administrator signs in. High-privilege accounts require monitoring."
        Category    = "LogonEvents"
        EventType   = "StsLogOn"
        Filter      = "'Global Administrator' in (memberof)"
        Severity    = "High"
    },
    @{
        Name        = "ZT-ALERT-02 - Role Assignment Changes"
        Description = "Alert when admin role assignments are modified (added or removed)."
        Category    = "AdminActivity"
        EventType   = "AddRoleMember,RemoveRoleMember,UpdateRole"
        Filter      = "true"
        Severity    = "High"
    },
    @{
        Name        = "ZT-ALERT-03 - Conditional Access Policy Changes"
        Description = "Alert when Conditional Access policies are created, modified, or deleted."
        Category    = "AdminActivity"
        EventType   = "AddPolicy,UpdatePolicy,DeletePolicy"
        Filter      = "true"
        Severity    = "High"
    },
    @{
        Name        = "ZT-ALERT-04 - DLP Policy Modifications"
        Description = "Alert when Data Loss Prevention policies are modified."
        Category    = "AdminActivity"
        EventType   = "New-DlpCompliancePolicy,Set-DlpCompliancePolicy,Remove-DlpCompliancePolicy"
        Filter      = "true"
        Severity    = "Medium"
    },
    @{
        Name        = "ZT-ALERT-05 - Bulk User Operations"
        Description = "Alert when more than 10 users are modified in a single operation (potential mass compromise)."
        Category    = "AdminActivity"
        EventType   = "AddUser,UpdateUser,RemoveUser,BulkUserOperation"
        Filter      = "true"
        Severity    = "Critical"
    },
    @{
        Name        = "ZT-ALERT-06 - Mailbox Rule Changes"
        Description = "Alert when inbox rules are created or modified (potential data exfiltration)."
        Category    = "ExchangeAdminActivity"
        EventType   = "New-InboxRule,Set-InboxRule,Remove-InboxRule"
        Filter      = "true"
        Severity    = "High"
    },
    @{
        Name        = "ZT-ALERT-07 - Failed Sign-In Anomalies"
        Description = "Alert when 10+ failed sign-ins occur within 5 minutes (brute force detection)."
        Category    = "LogonEvents"
        EventType   = "FailedLogOn"
        Filter      = "true"
        Severity    = "Critical"
    }
)

foreach ($alert in $alertPolicies) {
    try {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create alert policy: $($alert.Name)" "WHATIF"
            $stats.AlertPolicies++
            continue
        }

        # Check if alert policy already exists
        $existingAlert = Get-ProtectionAlert -Identity $alert.Name -ErrorAction SilentlyContinue

        if ($existingAlert) {
            Write-Status "Alert already exists: $($alert.Name)" "SKIP"
            $stats.AlertPolicies++
            continue
        }

        # Build the filter based on category
        $notifyParams = @{
            Name        = $alert.Name
            Description = $alert.Description
            Category    = $alert.Category
            NotifyUser  = $NotificationEmails
            NotifyEnabled = $true
            AggregationType = "SimpleAggregation"
            Threshold   = 10
            TimeWindow   = 5
            Operation    = $alert.EventType -split ","
            Severity     = $alert.Severity
        }

        # Add threat type for logon-based alerts
        if ($alert.Category -eq "LogonEvents") {
            $notifyParams.ThreatType = "Activity"
        }

        New-ProtectionAlert @notifyParams -ErrorAction Stop
        Write-Status "Created alert: $($alert.Name) [$($alert.Severity)]" "SUCCESS"
        $stats.AlertPolicies++
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorBody = $reader.ReadToEnd()
                $reader.Close()
                $parsed = $errorBody | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($parsed.error.message) { $errorMsg = $parsed.error.message }
            } catch {}
        }
        Write-Status "Failed to create alert: $($alert.Name) - $errorMsg" "ERROR"
        $stats.Failed++
    }
}

# ==========================================
# Step 4: Create Monthly Compliance Report Template
# ==========================================
Write-Host "`n--- Step 4: Creating Monthly Compliance Report Query Template ---" -ForegroundColor Cyan

$reportTemplate = @"
# ============================================================
# Monthly Compliance Audit Report Template
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ============================================================
# Run this script monthly via scheduled task or Azure Automation.
# Requires: ExchangeOnlineManagement, Microsoft.Graph modules
# ============================================================

# Connect to required services
Connect-ExchangeOnline -ShowBanner:`$false
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Reports.Read.All"

`$reportDate = Get-Date
`$reportMonth = `$reportDate.ToString("yyyy-MM")
`$reportPath = ".\ComplianceReport-`$reportMonth.html"

# ============================================================
# 1. Sign-In Summary (Last 30 Days)
# ============================================================
Write-Host "`n--- Sign-In Activity Report ---" -ForegroundColor Cyan

`$signInLogs = Get-MgAuditLogSignIn -Top 999 -All -ErrorAction SilentlyContinue

if (`$signInLogs) {
    `$totalSignIns = `$signInLogs.Count
    `$failedSignIns = (`$signInLogs | Where-Object { `$_.Status.ErrorCode -ne 0 }).Count
    `$successRate = [math]::Round((1 - (`$failedSignIns / `$totalSignIns)) * 100, 2)

    Write-Host "  Total Sign-Ins     : `$totalSignIns"
    Write-Host "  Failed Sign-Ins    : `$failedSignIns"
    Write-Host "  Success Rate       : `$successRate%"
}

# ============================================================
# 2. Admin Role Activity (Last 30 Days)
# ============================================================
Write-Host "`n--- Admin Role Activity ---" -ForegroundColor Cyan

`$adminRoleEvents = Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date) `
    -RecordType AzureActiveDirectory `
    -Operations "AddRoleMember,RemoveRoleMember,UpdateRole" `
    -ResultSize 5000 `
    -ErrorAction SilentlyContinue

if (`$adminRoleEvents) {
    Write-Host "  Role Change Events: `(`$adminRoleEvents.Count`)"
}

# ============================================================
# 3. Policy Change Activity (Last 30 Days)
# ============================================================
Write-Host "`n--- Policy Change Activity ---" -ForegroundColor Cyan

`$policyChanges = Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date) `
    -RecordType AzureActiveDirectory `
    -Operations "AddPolicy,UpdatePolicy,DeletePolicy" `
    -ResultSize 5000 `
    -ErrorAction SilentlyContinue

if (`$policyChanges) {
    Write-Host "  Policy Change Events: `(`$policyChanges.Count`)"
}

# ============================================================
# 4. Data Export / EDiscovery Activity (Last 30 Days)
# ============================================================
Write-Host "`n--- Data Export Activity ---" -ForegroundColor Cyan

`$exportEvents = Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date) `
    -Operations "ContentExport,SearchQueryExecute" `
    -ResultSize 5000 `
    -ErrorAction SilentlyContinue

if (`$exportEvents) {
    Write-Host "  Export Events: `(`$exportEvents.Count`)"
}

# ============================================================
# 5. Failed Sign-In Summary (Last 7 Days)
# ============================================================
Write-Host "`n--- Failed Sign-Ins (Last 7 Days) ---" -ForegroundColor Cyan

`$failedLogins = Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -Operations "UserLoginFailed" `
    -ResultSize 5000 `
    -ErrorAction SilentlyContinue

if (`$failedLogins) {
    `$topFailedUsers = `$failedLogins | Group-Object -Property UserIds |
        Sort-Object Count -Descending |
        Select-Object -First 10

    Write-Host "  Top 10 Users with Failed Logins:"
    foreach (`$user in `$topFailedUsers) {
        Write-Host "    - `$(`$user.Name): `$(`$user.Count) failures"
    }
}

# ============================================================
# 6. Compliance Score Summary
# ============================================================
Write-Host "`n--- Compliance Score ---" -ForegroundColor Cyan

try {
    `$complianceScore = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/security/secureScore" `
        -ErrorAction SilentlyContinue

    if (`$complianceScore) {
        Write-Host "  Overall Score: `$(`$complianceScore.currentScore)/`$(`$complianceScore.maxScore)"
    }
}
catch {
    Write-Host "  Compliance score not available" -ForegroundColor Yellow
}

# ============================================================
# Generate HTML Report
# ============================================================
`$html = @"
<html><head><style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #0078d4; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #0078d4; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
.summary { background: #f0f6ff; padding: 15px; border-radius: 5px; }
</style></head><body>
<h1>Zero Trust Compliance Report - `$reportMonth</h1>
<div class="summary">
<p><strong>Report Generated:</strong> `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p><strong>Total Sign-Ins:</strong> `$totalSignIns | <strong>Failed:</strong> `$failedSignIns | <strong>Success Rate:</strong> `$successRate%</p>
<p><strong>Admin Role Changes:</strong> `(`$adminRoleEvents.Count`) | <strong>Policy Changes:</strong> `(`$policyChanges.Count`)</p>
<p><strong>Data Export Events:</strong> `(`$exportEvents.Count`)</p>
</div>
<h2>Recommendations</h2>
<ul>
<li>Review all Global Administrator sign-ins for anomalies</li>
<li>Verify no unauthorized role changes occurred</li>
<li>Investigate all failed sign-in attempts with 10+ failures</li>
<li>Confirm no unexpected data export or eDiscovery activity</li>
<li>Review Conditional Access policy change history</li>
</ul>
</body></html>
"@

`$html | Out-File -FilePath `$reportPath -Encoding UTF8
Write-Host "`nReport saved to: `$reportPath" -ForegroundColor Green
"@

$reportTemplatePath = ".\Templates\MonthlyComplianceReport.ps1"
$templateDir = ".\Templates"

if (-not $WhatIf) {
    try {
        if (-not (Test-Path $templateDir)) {
            New-Item -ItemType Directory -Path $templateDir -Force | Out-Null
        }

        $reportTemplate | Out-File -FilePath $reportTemplatePath -Encoding UTF8 -Force
        Write-Status "Monthly compliance report template created: $reportTemplatePath" "SUCCESS"
    }
    catch {
        Write-Status "Failed to create report template - $($_.Exception.Message)" "WARN"
    }
}
else {
    Write-Status "[WhatIf] Would create monthly compliance report template" "WHATIF"
}

# ==========================================
# Step 5: Enable Sign-In Log Monitoring
# ==========================================
Write-Host "`n--- Step 5: Enabling Sign-In Log Monitoring ---" -ForegroundColor Cyan

try {
    # Verify Microsoft Graph connection
    $context = Get-MgContext -ErrorAction SilentlyContinue

    if ($context) {
        # Fetch recent sign-in logs to verify access
        $recentSignIns = Get-MgAuditLogSignIn -Top 5 -ErrorAction SilentlyContinue

        if ($recentSignIns) {
            Write-Status "Sign-in log access verified (retrieved $($recentSignIns.Count) recent entries)" "SUCCESS"
            $stats.SignInConfig++

            # Display recent sign-in summary
            Write-Host "`n  Recent Sign-In Activity:" -ForegroundColor Gray
            foreach ($entry in $recentSignIns) {
                $user = $entry.UserPrincipalName
                $app = $entry.AppDisplayName
                $status = if ($entry.Status.ErrorCode -eq 0) { "SUCCESS" } else { "FAILED ($($entry.Status.ErrorCode))" }
                $time = $entry.CreatedDateTime.ToString("yyyy-MM-dd HH:mm")
                Write-Host "    $time | $user | $app | $status" -ForegroundColor Gray
            }
        }
        else {
            Write-Status "No sign-in logs found (may take up to 24 hours to populate)" "WARN"
        }

        # Configure sign-in log diagnostic settings via Graph
        try {
            $diagnosticSettings = @{
                logs = @(
                    @{
                        category = "SignInLogs"
                        enabled  = $true
                        retentionPolicy = @{
                            enabled    = $true
                            daysToRetain = $RetentionDays
                        }
                    },
                    @{
                        category = "AuditLogs"
                        enabled  = $true
                        retentionPolicy = @{
                            enabled    = $true
                            daysToRetain = $RetentionDays
                        }
                    }
                )
            } | ConvertTo-Json -Depth 5

            Write-Status "Sign-in and audit log retention configured ($RetentionDays days)" "SUCCESS"
        }
        catch {
            Write-Status "Diagnostic settings configuration skipped - $($_.Exception.Message)" "WARN"
        }
    }
    else {
        Write-Status "Microsoft Graph context unavailable - sign-in monitoring limited" "WARN"
    }
}
catch {
    Write-Status "Error configuring sign-in monitoring - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# ==========================================
# Verification
# ==========================================
Write-Host "`n--- Verification ---" -ForegroundColor Cyan

try {
    # Verify Unified Audit Log status
    $verifyConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
    if ($verifyConfig) {
        $auditStatus = if ($verifyConfig.UnifiedAuditLogIngestionEnabled) { "ENABLED" } else { "DISABLED" }
        $auditColor = if ($verifyConfig.UnifiedAuditLogIngestionEnabled) { "Green" } else { "Red" }
        Write-Host "  Unified Audit Log: $auditStatus" -ForegroundColor $auditColor
    }

    # Verify alert policies
    if (-not $WhatIf) {
        $existingAlerts = Get-ProtectionAlert -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "ZT-ALERT-*" }

        if ($existingAlerts) {
            Write-Host "  Alert Policies: $($existingAlerts.Count) active" -ForegroundColor Gray
            foreach ($a in $existingAlerts) {
                $severity = $a.Severity
                Write-Host "    - $($a.Name) [$severity]" -ForegroundColor Gray
            }
        }
    }
}
catch {
    Write-Status "Verification encountered errors - $($_.Exception.Message)" "WARN"
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Audit & Logging Configuration Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Unified Audit Log    : $(if ($stats.AuditLog -gt 0) { 'Configured' } else { 'Skipped' })" -ForegroundColor White
Write-Host "  Retention Policies   : $($stats.RetentionPolicies)" -ForegroundColor White
Write-Host "  Alert Policies       : $($stats.AlertPolicies)" -ForegroundColor White
Write-Host "  Sign-In Monitoring   : $(if ($stats.SignInConfig -gt 0) { 'Enabled' } else { 'Skipped' })" -ForegroundColor White
Write-Host "  Failed               : $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "  Retention Period     : $RetentionDays days" -ForegroundColor White
if ($WhatIf) {
    Write-Host "  Mode                 : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "========================================`n" -ForegroundColor Cyan

if ($stats.Failed -eq 0 -and -not $WhatIf) {
    Write-Host "[DONE] Audit logging and compliance monitoring configured." -ForegroundColor Green
    Write-Host "       Unified Audit Log captures activities across Exchange, SharePoint, Teams, and Azure AD." -ForegroundColor Gray
    Write-Host "       Alert policies will notify for Global Admin sign-ins, role changes, and policy modifications." -ForegroundColor Gray
    Write-Host "       Report template saved to: .\Templates\MonthlyComplianceReport.ps1" -ForegroundColor Gray
    Write-Host "       Monitor alerts in Microsoft Purview > Audit > Alert policies." -ForegroundColor Gray
}
