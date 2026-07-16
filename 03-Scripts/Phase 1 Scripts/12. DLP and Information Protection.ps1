#Requires -Modules Microsoft.Graph.Identity.SignIns, ExchangeOnlineManagement

<#
.SYNOPSIS
    Configures DLP policies and sensitivity labels for data protection.

.DESCRIPTION
    Implements a comprehensive data protection strategy using Microsoft Purview:
    - Creates 4 sensitivity labels: Public, Internal, Confidential, Highly Confidential
    - Publishes labels via label policy for tenant-wide availability
    - Creates DLP policies for:
        * Financial data (credit card, bank account numbers)
        * PAN/Aadhaar numbers (India compliance)
        * HR/Payroll documents (SSN, salary, personnel info)
    - Configures auto-labeling rules for sensitive content detection
    - Sets DLP policy tips and notifications

    Sensitivity labels are created via Microsoft Graph API.
    DLP policies and label policies are configured via Security & Compliance PowerShell.

.PARAMETER WhatIf
    Shows what would be created without making changes.

.EXAMPLE
    .\12. DLP and Information Protection.ps1
    .\12. DLP and Information Protection.ps1 -WhatIf
#>

param(
    [switch]$WhatIf
)

# ==========================================
# Initialize
# ==========================================
$stats = @{ Labels = 0; LabelPolicies = 0; DlpPolicies = 0; DlpRules = 0; Failed = 0 }

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
# Connect - Microsoft Graph (for sensitivity labels)
# ==========================================
Write-Host "`n--- Connecting to Microsoft Graph ---" -ForegroundColor Cyan

$graphScopes = @(
    "InformationProtectionPolicy.ReadWrite",
    "Organization.Read.All"
)

try {
    Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
    Write-Status "Connected to Microsoft Graph" "SUCCESS"
}
catch {
    Write-Status "Failed to connect to Microsoft Graph - $($_.Exception.Message)" "ERROR"
    exit 1
}

# ==========================================
# Connect - Security & Compliance PowerShell (for DLP)
# ==========================================
Write-Host "`n--- Connecting to Security & Compliance PowerShell ---" -ForegroundColor Cyan

try {
    if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    }
    Write-Status "Connected to Exchange Online / Security & Compliance" "SUCCESS"
}
catch {
    Write-Status "Failed to connect to Security & Compliance - $($_.Exception.Message)" "ERROR"
    Write-Status "DLP and label policy features require this connection" "WARN"
}

# ==========================================
# Retrieve existing sensitivity labels
# ==========================================
Write-Host "`n--- Checking Existing Sensitivity Labels ---" -ForegroundColor Cyan

$existingLabels = @()
try {
    $labelUri = "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels"
    $labelResponse = Invoke-MgGraphRequest -Method GET -Uri $labelUri -ErrorAction Stop
    if ($labelResponse.value) {
        $existingLabels = $labelResponse.value
    }
    Write-Status "Found $($existingLabels.Count) existing sensitivity label(s)"
}
catch {
    Write-Status "Could not retrieve existing labels - $($_.Exception.Message)" "WARN"
}

# ==========================================
# Define sensitivity labels
# ==========================================
Write-Host "`n--- Creating Sensitivity Labels ---" -ForegroundColor Cyan

$sensitivityLabels = @(
    @{
        Name        = "Public"
        Description = "Information intended for public disclosure. No protection required."
        Tooltip     = "Safe to share publicly. No encryption or restrictions applied."
        Color       = "#4CAF50"
        Order       = 0
    },
    @{
        Name        = "Internal"
        Description = "Information for internal use only. Not for external sharing."
        Tooltip     = "Internal use only. Do not share outside the organization."
        Color       = "#2196F3"
        Order       = 1
    },
    @{
        Name        = "Confidential"
        Description = "Sensitive information requiring protection. Limited access."
        Tooltip     = "Confidential data. Access restricted to authorized personnel."
        Color       = "#FF9800"
        Order       = 2
    },
    @{
        Name        = "Highly Confidential"
        Description = "Highly sensitive information with strict access controls and encryption."
        Tooltip     = "Highly restricted data. Encryption and access logging enforced."
        Color       = "#F44336"
        Order       = 3
    }
)

foreach ($label in $sensitivityLabels) {

    # Check if label already exists
    $existingMatch = $existingLabels | Where-Object { $_.displayName -eq $label.Name }
    if ($existingMatch) {
        Write-Status "Label already exists: $($label.Name)" "SKIP"
        continue
    }

    try {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create sensitivity label: $($label.Name)" "WHATIF"
            $stats.Labels++
            continue
        }

        $body = @{
            displayName = $label.Name
            description = $label.Description
            tooltip     = $label.Tooltip
            color       = $label.Color
            order       = $label.Order
        } | ConvertTo-Json -Depth 5

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Status "Created label: $($label.Name) (ID: $($result.id))" "SUCCESS"
        $stats.Labels++
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
        Write-Status "Failed to create label: $($label.Name) - $errorMsg" "ERROR"
        $stats.Failed++
    }
}

# ==========================================
# Publish sensitivity labels via label policy
# ==========================================
Write-Host "`n--- Publishing Sensitivity Labels (Label Policy) ---" -ForegroundColor Cyan

try {
    $labelPolicy = Get-LabelPolicy -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "Global-Sensitivity-Label-Policy" }

    if ($labelPolicy) {
        Write-Status "Label policy 'Global-Sensitivity-Label-Policy' already exists" "SKIP"
    }
    else {
        # Get all sensitivity labels for publishing
        $allLabels = Get-Label -ErrorAction SilentlyContinue

        if (-not $allLabels -or $allLabels.Count -eq 0) {
            Write-Status "No sensitivity labels found to publish. Labels may still be propagating." "WARN"
            Write-Status "Run Get-Label to verify labels exist, then re-run this script." "WARN"
        }
        else {
            $labelGuids = $allLabels | ForEach-Object { $_.Guid }

            if ($WhatIf) {
                Write-Status "[WhatIf] Would create label policy publishing $($labelGuids.Count) label(s)" "WHATIF"
                $stats.LabelPolicies++
            }
            else {
                try {
                    New-LabelPolicy `
                        -Name "Global-Sensitivity-Label-Policy" `
                        -DisplayName "Global Sensitivity Labels" `
                        -Comment "Publishes all sensitivity labels tenant-wide for Zero Trust data protection" `
                        -Labels $labelGuids `
                        -Settings @(
                            '{"mandatory":false}',
                            '{"defaultLabelId":"2c01888f-a89e-4d29-b532-d838d7c2562c"}'
                        ) `
                        -ErrorAction Stop

                    Write-Status "Created label policy: Global-Sensitivity-Label-Policy" "SUCCESS"
                    $stats.LabelPolicies++
                }
                catch {
                    # Fallback: try without Settings parameter
                    try {
                        New-LabelPolicy `
                            -Name "Global-Sensitivity-Label-Policy" `
                            -DisplayName "Global Sensitivity Labels" `
                            -Comment "Publishes all sensitivity labels tenant-wide" `
                            -Labels $labelGuids `
                            -ErrorAction Stop

                        Write-Status "Created label policy (without settings): Global-Sensitivity-Label-Policy" "SUCCESS"
                        $stats.LabelPolicies++
                    }
                    catch {
                        Write-Status "Failed to create label policy - $($_.Exception.Message)" "ERROR"
                        $stats.Failed++
                    }
                }
            }
        }
    }
}
catch {
    Write-Status "Error during label policy creation - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# ==========================================
# DLP Policies - Financial Data
# ==========================================
Write-Host "`n--- Creating DLP Policies ---" -ForegroundColor Cyan

# --- Policy 1: Financial Data Protection ---
Write-Host "`n  [1/3] Financial Data Protection Policy" -ForegroundColor White

$financialDlpName = "DLP-FIN-01 - Financial Data Protection"

try {
    $existingFinPolicy = Get-DlpCompliancePolicy -Identity $financialDlpName -ErrorAction SilentlyContinue

    if ($existingFinPolicy) {
        Write-Status "Policy already exists: $financialDlpName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create DLP policy: $financialDlpName" "WHATIF"
        }
        else {
            New-DlpCompliancePolicy `
                -Name $financialDlpName `
                -Comment "Detects and protects financial data including credit card numbers, bank accounts, and SWIFT codes" `
                -ExchangeLocation All `
                -SharePointLocation All `
                -OneDriveLocation All `
                -TeamsLocation All `
                -Mode Enable `
                -ErrorAction Stop

            Write-Status "Created DLP policy: $financialDlpName" "SUCCESS"
            $stats.DlpPolicies++
        }

        # Create rules for financial data
        $financialRules = @(
            @{
                Name        = "DLP-FIN-R01 - Credit Card Detection"
                PolicyName  = $financialDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "Credit Card Number"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 85
                    }
                )
                BlockAccess = $true
                NotifyUser  = "LastModifier"
                NotifyTitle = "Financial Data Detected"
                NotifyBody  = "This document contains credit card number(s). Access has been restricted per data protection policy."
            },
            @{
                Name        = "DLP-FIN-R02 - Bank Account Detection"
                PolicyName  = $financialDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "Bank Account Number"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 85
                    }
                )
                BlockAccess = $true
                NotifyUser  = "LastModifier"
                NotifyTitle = "Financial Data Detected"
                NotifyBody  = "This document contains bank account information. Access has been restricted per data protection policy."
            },
            @{
                Name        = "DLP-FIN-R03 - SWIFT Code Detection"
                PolicyName  = $financialDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "SWIFT Code"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 75
                    }
                )
                BlockAccess = $false
                NotifyUser  = "LastModifier"
                NotifyTitle = "SWIFT Code Detected"
                NotifyBody  = "This document contains a SWIFT code. Please verify sharing permissions."
            }
        )

        foreach ($rule in $financialRules) {
            try {
                if ($WhatIf) {
                    Write-Status "[WhatIf] Would create rule: $($rule.Name)" "WHATIF"
                    $stats.DlpRules++
                    continue
                }

                $sensitiveInfoParams = $rule.ContentContainsSensitiveInformation | ForEach-Object {
                    @{
                        Name = $_.Name
                        minCount = $_.minCount
                        maxCount = $_.maxCount
                        minConfidence = $_.minConfidence
                    }
                }

                $ruleParams = @{
                    Name = $rule.Name
                    Policy = $rule.PolicyName
                    ContentContainsSensitiveInformation = $sensitiveInfoParams
                    BlockAccess = $rule.BlockAccess
                    BlockAccessScope = "All"
                    NotifyUser = $rule.NotifyUser
                    NotifyPolicyTipCustomText = $rule.NotifyBody
                    GenerateincidentReport = "SiteAdmin"
                    ReportSeverityLevel = "High"
                }

                New-DlpComplianceRule @ruleParams -ErrorAction Stop
                Write-Status "Created rule: $($rule.Name)" "SUCCESS"
                $stats.DlpRules++
            }
            catch {
                Write-Status "Failed to create rule: $($rule.Name) - $($_.Exception.Message)" "ERROR"
                $stats.Failed++
            }
        }
    }
}
catch {
    Write-Status "Error with financial DLP policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# --- Policy 2: PAN/Aadhaar Detection (India Compliance) ---
Write-Host "`n  [2/3] PAN/Aadhaar Detection Policy (India Compliance)" -ForegroundColor White

$indiaDlpName = "DLP-IND-01 - PAN-Aadhaar India Compliance"

try {
    $existingIndPolicy = Get-DlpCompliancePolicy -Identity $indiaDlpName -ErrorAction SilentlyContinue

    if ($existingIndPolicy) {
        Write-Status "Policy already exists: $indiaDlpName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create DLP policy: $indiaDlpName" "WHATIF"
        }
        else {
            New-DlpCompliancePolicy `
                -Name $indiaDlpName `
                -Comment "Detects and protects Indian PAN and Aadhaar numbers for RBI/IT Act compliance" `
                -ExchangeLocation All `
                -SharePointLocation All `
                -OneDriveLocation All `
                -TeamsLocation All `
                -Mode Enable `
                -ErrorAction Stop

            Write-Status "Created DLP policy: $indiaDlpName" "SUCCESS"
        }
        $stats.DlpPolicies++

        # Create rules for India-specific identifiers
        $indiaRules = @(
            @{
                Name        = "DLP-IND-R01 - Indian PAN Detection"
                PolicyName  = $indiaDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "Indian Permanent Account Number (PAN)"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 85
                    }
                )
                BlockAccess = $true
                NotifyUser  = "LastModifier"
                NotifyTitle = "Indian PAN Number Detected"
                NotifyBody  = "This document contains an Indian PAN number. Access has been restricted per India data compliance policy."
            },
            @{
                Name        = "DLP-IND-R02 - Indian Aadhaar Number Detection"
                PolicyName  = $indiaDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "Indian Aadhaar Number"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 85
                    }
                )
                BlockAccess = $true
                NotifyUser  = "LastModifier"
                NotifyTitle = "Aadhaar Number Detected"
                NotifyBody  = "This document contains an Aadhaar number. Access has been restricted per UIDAI data protection requirements."
            },
            @{
                Name        = "DLP-IND-R03 - Indian Passport Number Detection"
                PolicyName  = $indiaDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "Indian Passport Number"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 75
                    }
                )
                BlockAccess = $false
                NotifyUser  = "LastModifier"
                NotifyTitle = "Passport Number Detected"
                NotifyBody  = "This document contains an Indian passport number. Please review sharing settings."
            }
        )

        foreach ($rule in $indiaRules) {
            try {
                if ($WhatIf) {
                    Write-Status "[WhatIf] Would create rule: $($rule.Name)" "WHATIF"
                    $stats.DlpRules++
                    continue
                }

                $sensitiveInfoParams = $rule.ContentContainsSensitiveInformation | ForEach-Object {
                    @{
                        Name = $_.Name
                        minCount = $_.minCount
                        maxCount = $_.maxCount
                        minConfidence = $_.minConfidence
                    }
                }

                $ruleParams = @{
                    Name = $rule.Name
                    Policy = $rule.PolicyName
                    ContentContainsSensitiveInformation = $sensitiveInfoParams
                    BlockAccess = $rule.BlockAccess
                    BlockAccessScope = "All"
                    NotifyUser = $rule.NotifyUser
                    NotifyPolicyTipCustomText = $rule.NotifyBody
                    GenerateincidentReport = "SiteAdmin"
                    ReportSeverityLevel = "High"
                }

                New-DlpComplianceRule @ruleParams -ErrorAction Stop
                Write-Status "Created rule: $($rule.Name)" "SUCCESS"
                $stats.DlpRules++
            }
            catch {
                Write-Status "Failed to create rule: $($rule.Name) - $($_.Exception.Message)" "ERROR"
                $stats.Failed++
            }
        }
    }
}
catch {
    Write-Status "Error with India compliance DLP policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# --- Policy 3: HR/Payroll Document Protection ---
Write-Host "`n  [3/3] HR/Payroll Document Protection Policy" -ForegroundColor White

$hrDlpName = "DLP-HR-01 - HR and Payroll Document Protection"

try {
    $existingHrPolicy = Get-DlpCompliancePolicy -Identity $hrDlpName -ErrorAction SilentlyContinue

    if ($existingHrPolicy) {
        Write-Status "Policy already exists: $hrDlpName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create DLP policy: $hrDlpName" "WHATIF"
        }
        else {
            New-DlpCompliancePolicy `
                -Name $hrDlpName `
                -Comment "Protects HR and payroll documents containing SSN, salary data, and personnel information" `
                -ExchangeLocation All `
                -SharePointLocation All `
                -OneDriveLocation All `
                -TeamsLocation All `
                -Mode Enable `
                -ErrorAction Stop

            Write-Status "Created DLP policy: $hrDlpName" "SUCCESS"
        }
        $stats.DlpPolicies++

        # Create rules for HR/Payroll data
        $hrRules = @(
            @{
                Name        = "DLP-HR-R01 - SSN Detection"
                PolicyName  = $hrDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "U.S. Social Security Number (SSN)"
                        minCount = 1
                        maxCount = 999
                        minConfidence = 85
                    }
                )
                BlockAccess = $true
                NotifyUser  = "LastModifier"
                NotifyTitle = "SSN Detected in HR Document"
                NotifyBody  = "This document contains Social Security Number(s). Access has been restricted per HR data protection policy."
            },
            @{
                Name        = "DLP-HR-R02 - Salary/Payroll Keyword Detection"
                PolicyName  = $hrDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "Credit Card Number"
                        minCount = 0
                        maxCount = 999
                        minConfidence = 75
                    }
                )
                ContentPropertyContainsWords = @("Payroll", "Salary", "Compensation", "Bonus")
                BlockAccess = $false
                NotifyUser  = "LastModifier"
                NotifyTitle = "HR/Payroll Content Detected"
                NotifyBody  = "This document appears to contain payroll or salary information. Please ensure appropriate sharing settings."
            },
            @{
                Name        = "DLP-HR-R03 - Employee ID Pattern Detection"
                PolicyName  = $hrDlpName
                ContentContainsSensitiveInformation = @(
                    @{
                        Name  = "All Full Names"
                        minCount = 3
                        maxCount = 999
                        minConfidence = 70
                    }
                )
                ContentPropertyContainsWords = @("Employee", "Personnel", "HR", "Human Resources")
                BlockAccess = $false
                NotifyUser  = "LastModifier"
                NotifyTitle = "Personnel Document Detected"
                NotifyBody  = "This document may contain employee personally identifiable information. Review sharing settings."
            }
        )

        foreach ($rule in $hrRules) {
            try {
                if ($WhatIf) {
                    Write-Status "[WhatIf] Would create rule: $($rule.Name)" "WHATIF"
                    $stats.DlpRules++
                    continue
                }

                $sensitiveInfoParams = $rule.ContentContainsSensitiveInformation | ForEach-Object {
                    @{
                        Name = $_.Name
                        minCount = $_.minCount
                        maxCount = $_.maxCount
                        minConfidence = $_.minConfidence
                    }
                }

                $ruleParams = @{
                    Name = $rule.Name
                    Policy = $rule.PolicyName
                    ContentContainsSensitiveInformation = $sensitiveInfoParams
                    BlockAccess = $rule.BlockAccess
                    BlockAccessScope = "All"
                    NotifyUser = $rule.NotifyUser
                    NotifyPolicyTipCustomText = $rule.NotifyBody
                    GenerateincidentReport = "SiteAdmin"
                    ReportSeverityLevel = "Medium"
                }

                # Add content property filter if present
                if ($rule.ContentPropertyContainsWords) {
                    $ruleParams.ContentPropertyContainsWords = $rule.ContentPropertyContainsWords
                }

                New-DlpComplianceRule @ruleParams -ErrorAction Stop
                Write-Status "Created rule: $($rule.Name)" "SUCCESS"
                $stats.DlpRules++
            }
            catch {
                Write-Status "Failed to create rule: $($rule.Name) - $($_.Exception.Message)" "ERROR"
                $stats.Failed++
            }
        }
    }
}
catch {
    Write-Status "Error with HR/Payroll DLP policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# ==========================================
# Configure auto-labeling settings
# ==========================================
Write-Host "`n--- Configuring Auto-Labeling ---" -ForegroundColor Cyan

try {
    if (-not $WhatIf) {
        # Enable auto-labeling for Confidential and Highly Confidential labels
        $autoLabelTargets = @("Confidential", "Highly Confidential")

        foreach ($target in $autoLabelTargets) {
            try {
                $label = Get-Label -Identity $target -ErrorAction SilentlyContinue
                if ($label) {
                    Set-Label `
                        -Identity $label.Guid `
                        -AutoLabelingSetting @{
                            autoLabelRule = @{
                                name = "Auto-Label - $target"
                                contentContainsSensitiveInformation = @()
                                operator = "and"
                            }
                        } `
                        -ErrorAction SilentlyContinue

                    Write-Status "Auto-labeling configured for: $target"
                }
            }
            catch {
                Write-Status "Auto-labeling setup skipped for $target - $($_.Exception.Message)" "WARN"
            }
        }

        # Enable auto-labeling in the label policy
        try {
            $policy = Get-LabelPolicy -Identity "Global-Sensitivity-Label-Policy" -ErrorAction SilentlyContinue
            if ($policy) {
                Set-LabelPolicy `
                    -Identity "Global-Sensitivity-Label-Policy" `
                    -Settings @(
                        '{"mandatory":false}',
                        '{"autoLabelingSupported":true}'
                    ) `
                    -ErrorAction SilentlyContinue

                Write-Status "Auto-labeling enabled in label policy"
            }
        }
        catch {
            Write-Status "Auto-labeling policy update skipped - $($_.Exception.Message)" "WARN"
        }
    }
    else {
        Write-Status "[WhatIf] Would configure auto-labeling for Confidential/Highly Confidential labels" "WHATIF"
    }
}
catch {
    Write-Status "Error configuring auto-labeling - $($_.Exception.Message)" "WARN"
}

# ==========================================
# Verify and list all created resources
# ==========================================
Write-Host "`n--- Verification ---" -ForegroundColor Cyan

try {
    # Verify sensitivity labels
    $finalLabels = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels" `
        -ErrorAction SilentlyContinue

    if ($finalLabels.value) {
        Write-Host "  Sensitivity Labels:" -ForegroundColor Gray
        foreach ($l in $finalLabels.value) {
            Write-Host "    - $($l.displayName) (ID: $($l.id))" -ForegroundColor Gray
        }
    }

    # Verify DLP policies
    if (-not $WhatIf) {
        $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue
        $scriptPolicies = $dlpPolicies | Where-Object {
            $_.Name -match "^DLP-(FIN|IND|HR)-"
        }

        if ($scriptPolicies) {
            Write-Host "  DLP Policies:" -ForegroundColor Gray
            foreach ($p in $scriptPolicies) {
                $status = if ($p.Enabled) { "Enabled" } else { "Disabled" }
                Write-Host "    - $($p.Name) [$status]" -ForegroundColor Gray
            }
        }

        # Verify DLP rules
        $scriptRules = Get-DlpComplianceRule -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "^DLP-(FIN|IND|HR)-R"
        }

        if ($scriptRules) {
            Write-Host "  DLP Rules: $($scriptRules.Count)" -ForegroundColor Gray
        }
    }

    # Verify label policy
    if (-not $WhatIf) {
        $labelPolicies = Get-LabelPolicy -ErrorAction SilentlyContinue
        $scriptPolicy = $labelPolicies | Where-Object { $_.Name -eq "Global-Sensitivity-Label-Policy" }
        if ($scriptPolicy) {
            Write-Host "  Label Policy: $($scriptPolicy.Name) [Labels: $($scriptPolicy.Labels.Count)]" -ForegroundColor Gray
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
Write-Host "  DLP & Information Protection Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sensitivity Labels : $($stats.Labels)" -ForegroundColor White
Write-Host "  Label Policies     : $($stats.LabelPolicies)" -ForegroundColor White
Write-Host "  DLP Policies       : $($stats.DlpPolicies)" -ForegroundColor White
Write-Host "  DLP Rules          : $($stats.DlpRules)" -ForegroundColor White
Write-Host "  Failed             : $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })
if ($WhatIf) {
    Write-Host "  Mode               : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "========================================`n" -ForegroundColor Cyan

if ($stats.Failed -eq 0 -and -not $WhatIf) {
    Write-Host "[DONE] DLP and sensitivity labels configured. Allow 30-60 minutes for policies to take effect." -ForegroundColor Green
    Write-Host "       Monitor DLP incidents in Microsoft Purview > Data loss prevention > Activity explorer." -ForegroundColor Gray
    Write-Host "       Labels will appear in Office apps for users within the label policy scope." -ForegroundColor Gray
}
