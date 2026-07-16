#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights

<#
.SYNOPSIS
    Creates Sentinel analytics rules for Zero Trust threat detection.

.DESCRIPTION
    Deploys scheduled analytics rules that detect:
    - Impossible travel sign-ins (stolen credentials)
    - Privileged role abuse (unexpected GA activation)
    - Suspicious file downloads (data exfiltration)
    - Malware outbreak (multiple endpoint detections)
    - High-risk sign-ins (anonymous IP, TOR, malicious IPs)
    - Failed sign-in brute force attempts

    All rules are created in disabled state for review before activation.
    Rules query Log Analytics and generate incidents automatically.

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER WhatIf
    Shows what would happen without creating rules.

.EXAMPLE
    .\26. Create Analytics Rules.ps1
    .\26. Create Analytics Rules.ps1 -WorkspaceName "MyWorkspace"
    .\26. Create Analytics Rules.ps1 -WhatIf
#>

param(
    [string]$WorkspaceName = "Sentinel-ZeroTrust-Workspace",
    [string]$ResourceGroup = "rg-sentinel-zerotrust",
    [switch]$WhatIf
)

# ==========================================
# Step 1: Connect to Azure
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 1: Connecting to Azure" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Connect-AzAccount -UseDeviceAuthentication
    Write-Host "[OK] Connected to Azure" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to connect to Azure: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# ==========================================
# Step 2: Verify Workspace
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 2: Verifying Sentinel Workspace" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    $workspace = Get-AzOperationalInsightsWorkspace `
        -ResourceGroupName $ResourceGroup `
        -Name $WorkspaceName `
        -ErrorAction Stop
    Write-Host "[OK] Workspace: $($workspace.Name)" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Workspace not found. Run Script 9 first." -ForegroundColor Red
    return
}

# ==========================================
# Rule Definitions
# ==========================================
$rules = @(
    # Rule 1: Impossible Travel
    @{
        Name        = "ZeroTrust - Impossible Travel Detection"
        Description = "Detects sign-ins from geographically distant locations within a short timeframe, indicating possible credential theft."
        Query       = @"
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
| serialize
| extend prevTimeGenerated = prev(TimeGenerated), prevLocation = prev(LocationDetails)
| extend timeDiff = datetime_diff('minute', TimeGenerated, prevTimeGenerated)
| extend locationDiff = geo_distance(
    prevLocation.geoCoordinates.longitude, prevLocation.geoCoordinates.latitude,
    LocationDetails.geoCoordinates.longitude, LocationDetails.geoCoordinates.latitude)
| where timeDiff between (0 .. 720) and locationDiff > 500
| project TimeGenerated, UserPrincipalName, IPAddress, Location, prevLocation = prevLocation.city, timeDiffMinutes = timeDiff, distanceKm = round(locationDiff/1000, 0)
"@
        Severity    = "High"
        Frequency   = 4 hours
        Period      = 5 minutes
    },

    # Rule 2: Privileged Role Abuse
    @{
        Name        = "ZeroTrust - Privileged Role Activation Anomaly"
        Description = "Detects unexpected Global Administrator role activations, especially outside business hours or from unusual locations."
        Query       = @"
AuditLogs
| where OperationName == "Add member to role" or OperationName == "Add eligible member to role"
| where toint(Properties.targetResources[0].modifiedProperties[0].newValue) contains "Global Administrator"
| extend TimeGenerated = todatetime(Properties.activityDateTime)
| extend Actor = InitiatedBy.user.userPrincipalName
| extend Target = Properties.targetResources[0].displayName
| extend Hour = hourofday(TimeGenerated)
| where Hour < 7 or Hour > 19
| project TimeGenerated, Actor, Target, OperationName, Location = Properties.initiatedBy.user.ipAddress
"@
        Severity    = "High"
        Frequency   = 1 hour
        Period      = 5 minutes
    },

    # Rule 3: Suspicious File Download
    @{
        Name        = "ZeroTrust - Suspicious SharePoint File Download"
        Description = "Detects large volumes of SharePoint file downloads in a short period, indicating potential data exfiltration."
        Query       = @"
CloudAppEvents
| where TimeGenerated > ago(1d)
| where Application == "SharePoint" and ActionType == "FileDownloaded"
| summarize DownloadCount = count(), UniqueFiles = dcount(ActivityObject), TotalSize = sum(FileSize) by Account, bin(TimeGenerated, 15m)
| where DownloadCount > 20 or TotalSize > 104857600
| project TimeGenerated, Account, DownloadCount, UniqueFiles, TotalSizeMB = round(TotalSize/1048576, 2)
"@
        Severity    = "Medium"
        Frequency   = 1 hour
        Period      = 15 minutes
    },

    # Rule 4: Malware Outbreak
    @{
        Name        = "ZeroTrust - Malware Outbreak Detection"
        Description = "Detects multiple endpoints detecting malware simultaneously, indicating a potential outbreak."
        Query       = @"
SecurityAlert
| where ProviderName == "MDATP"
| where TimeGenerated > ago(1d)
| where AlertName contains "malware" or AlertName contains "virus" or AlertName contains "trojan"
| summarize DeviceCount = dcount(DeviceName), AlertCount = count() by bin(TimeGenerated, 1h)
| where DeviceCount >= 3
| project TimeGenerated, AlertCount, DeviceCount
"@
        Severity    = "Critical"
        Frequency   = 30 minutes
        Period      = 15 minutes
    },

    # Rule 5: High-Risk Sign-In
    @{
        Name        = "ZeroTrust - High Risk Sign-In Detection"
        Description = "Detects sign-ins from anonymous IPs, TOR network, or known malicious IP addresses."
        Query       = @"
SigninLogs
| where TimeGenerated > ago(1d)
| where RiskLevelDuringSignIn == "high" or RiskLevelDuringSignIn == "critical"
    or IPAddress in ("TorExitNodes")
    or LocationDetails.geoCoordinates.latitude == 0.0
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn, Location,
    DeviceDetail = DeviceDetail.displayName, AppDisplayName, ResultType
| extend RiskReason = case(
    IPAddress in ("TorExitNodes"), "TOR Network",
    LocationDetails.geoCoordinates.latitude == 0.0, "Anonymous IP",
    RiskLevelDuringSignIn == "critical", "Critical Risk",
    "High Risk")
"@
        Severity    = "High"
        Frequency   = 1 hour
        Period      = 5 minutes
    },

    # Rule 6: Brute Force
    @{
        Name        = "ZeroTrust - Brute Force Sign-In Attempts"
        Description = "Detects multiple failed sign-in attempts followed by a success, indicating brute force activity."
        Query       = @"
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 10
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | project SuccessfulUser = UserPrincipalName, SuccessTime = TimeGenerated, SuccessIP = IPAddress
) on $left.UserPrincipalName == $right.SuccessfulUser
| where SuccessTime between (TimeGenerated .. datetime_add('minute', 30, TimeGenerated))
| project TimeGenerated, UserPrincipalName, FailedAttempts, SuccessTime, SuccessIP
"@
        Severity    = "Medium"
        Frequency   = 1 hour
        Period      = 15 minutes
    }
)

# ==========================================
# Step 3: Create Analytics Rules
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Creating Analytics Rules" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$createdCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($rule in $rules) {
    Write-Host "Processing: $($rule.Name)" -ForegroundColor White

    try {
        $existing = Get-AzSentinelAlertRule `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $rule.Name }

        if ($existing) {
            Write-Host "  [SKIP] Already exists" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        if ($WhatIf) {
            Write-Host "  [WhatIf] Would create rule: $($rule.Name)" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        $schedule = @{
            DisplayName    = $rule.Name
            Description    = $rule.Description
            Enabled        = $false
            Query          = $rule.Query
            QueryFrequency = $rule.Frequency
            QueryPeriod    = $rule.Period
            Severity       = $rule.Severity
            TriggerOperator = "GreaterThan"
            TriggerThreshold = 0
            SuppressionDuration = "PT1H"
            SuppressionEnabled  = $false
        }

        New-AzSentinelAlertRule @schedule `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName

        Write-Host "  [OK] Created (disabled — enable after review)" -ForegroundColor Green
        $createdCount++
    }
    catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "ANALYTICS RULES SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Created : $createdCount rules" -ForegroundColor Green
    Write-Host "Skipped : $skippedCount (already exist)" -ForegroundColor Yellow
    Write-Host "Errors  : $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Gray" })
    Write-Host "`nAll rules created in DISABLED state." -ForegroundColor Yellow
    Write-Host "Review each rule in Sentinel > Analytics, then enable." -ForegroundColor Yellow
    Write-Host "`nRules deployed:" -ForegroundColor Cyan
    foreach ($rule in $rules) {
        Write-Host "  - $($rule.Name) [$($rule.Severity)]" -ForegroundColor White
    }
}
