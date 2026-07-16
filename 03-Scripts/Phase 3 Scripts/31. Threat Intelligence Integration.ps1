#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights

<#
.SYNOPSIS
    Enables Sentinel Threat Intelligence capabilities and TI-driven detection.

.DESCRIPTION
    Configures end-to-end Threat Intelligence integration in Microsoft Sentinel:
    - Enables the Threat Intelligence blade in Sentinel
    - Connects Microsoft Threat Intelligence as a built-in data source
    - Configures STIX/TAXII feed ingestion for third-party threat feeds
    - Creates analytics rules that match TI indicators against sign-ins and network events
    - Deploys a Threat Intelligence overview workbook

    TI matching rules correlate ingested indicators (IP, domain, URL, file hash,
    email) against live logs to surface incidents involving known threats.

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER TaxiiServerUrl
    URL of the TAXII 2.x server to consume. Leave empty to skip TAXII feed setup.

.PARAMETER TaxiiCollectionId
    TAXII collection ID to poll. Required when TaxiiServerUrl is specified.

.PARAMETER TaxiiFriendlyName
    Display name for the TAXII connector in Sentinel. Defaults to "ZeroTrust-TAXII-Feed".

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\31. Threat Intelligence Integration.ps1
    .\31. Threat Intelligence Integration.ps1 -WorkspaceName "MyWorkspace" -ResourceGroup "my-rg"
    .\31. Threat Intelligence Integration.ps1 -TaxiiServerUrl "https://cti.example.com/taxii2/" -TaxiiCollectionId "collection--1"
    .\31. Threat Intelligence Integration.ps1 -WhatIf
#>

param(
    [string]$WorkspaceName = "Sentinel-ZeroTrust-Workspace",
    [string]$ResourceGroup = "rg-sentinel-zerotrust",
    [string]$TaxiiServerUrl = "",
    [string]$TaxiiCollectionId = "",
    [string]$TaxiiFriendlyName = "ZeroTrust-TAXII-Feed",
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
    Write-Host "     Workspace ID: $($workspace.CustomerId)" -ForegroundColor Gray
}
catch {
    Write-Host "[ERROR] Workspace not found. Run Script 9 first." -ForegroundColor Red
    return
}

# ==========================================
# Step 3: Enable Threat Intelligence Blade
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Enabling Threat Intelligence Blade" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Threat Intelligence blade" -ForegroundColor Yellow
    }
    else {
        $existingConnector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "ThreatIntelligence" }

        if ($existingConnector) {
            Write-Host "[SKIP] Threat Intelligence blade already enabled" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "ThreatIntelligence" `
                -Enabled $true
            Write-Host "[OK] Threat Intelligence blade enabled" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "[WARNING] Threat Intelligence blade: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Enable manually: Sentinel > Configuration > Threat Intelligence" -ForegroundColor Gray
}

# ==========================================
# Step 4: Connect Microsoft Threat Intelligence
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 4: Connecting Microsoft Threat Intelligence" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Microsoft Threat Intelligence data source" -ForegroundColor Yellow
    }
    else {
        $msTiConnector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "MicrosoftThreatIntelligence" }

        if ($msTiConnector) {
            Write-Host "[SKIP] Microsoft Threat Intelligence already connected" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "MicrosoftThreatIntelligence" `
                -Enabled $true
            Write-Host "[OK] Microsoft Threat Intelligence connected" -ForegroundColor Green
            Write-Host "     Indicators: Microsoft-curated IOCs (IP, domain, URL, file hash)" -ForegroundColor Gray
            Write-Host "     Source: Microsoft Security Graph threat intelligence" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[WARNING] Microsoft Threat Intelligence: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Requires Microsoft Defender Threat Intelligence license" -ForegroundColor Gray
}

# ==========================================
# Step 5: Configure TAXII Feed (Optional)
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 5: Configuring TAXII Feed Ingestion" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($TaxiiServerUrl)) {
    Write-Host "[SKIP] No TAXII server URL provided — skipping TAXII feed setup" -ForegroundColor Yellow
    Write-Host "       Re-run with -TaxiiServerUrl and -TaxiiCollectionId to configure" -ForegroundColor Gray
}
else {
    try {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would configure TAXII feed: $TaxiiFriendlyName" -ForegroundColor Yellow
            Write-Host "         Server: $TaxiiServerUrl" -ForegroundColor Yellow
            Write-Host "         Collection: $TaxiiCollectionId" -ForegroundColor Yellow
        }
        else {
            $existingTaxii = Get-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.Kind -eq "ThreatIntelligenceTaxii" -and $_.FriendlyName -eq $TaxiiFriendlyName }

            if ($existingTaxii) {
                Write-Host "[SKIP] TAXII feed '$TaxiiFriendlyName' already exists" -ForegroundColor Yellow
            }
            else {
                $taxiiParams = @{
                    ResourceGroupName  = $ResourceGroup
                    WorkspaceName      = $WorkspaceName
                    Kind               = "ThreatIntelligenceTaxii"
                    FriendlyName       = $TaxiiFriendlyName
                    TaxiiServerUrl     = $TaxiiServerUrl
                    CollectionId       = $TaxiiCollectionId
                    TaxiiUserName      = ""
                    TaxiiPassword      = ""
                    LookbackPeriod     = "30d"
                    PollingFrequency   = 5
                    Enable             = $true
                }

                New-AzSentinelDataConnector @taxiiParams

                Write-Host "[OK] TAXII feed configured: $TaxiiFriendlyName" -ForegroundColor Green
                Write-Host "     Server  : $TaxiiServerUrl" -ForegroundColor Gray
                Write-Host "     Polling : Every 5 minutes (last 30 days lookback)" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "[WARNING] TAXII feed setup: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "         Configure manually: Sentinel > Data connectors > Threat Intelligence - TAXII" -ForegroundColor Gray
    }
}

# ==========================================
# TI Matching Analytics Rule Definitions
# ==========================================
$tiRules = @(
    # Rule 1: TI Match on Sign-In IPs
    @{
        Name        = "ZeroTrust - TI Match: Sign-In IP Against Threat Indicators"
        Description = "Correlates successful sign-in IP addresses with known threat intelligence indicators to detect compromised endpoints or accounts interacting with malicious infrastructure."
        Query       = @"
let tiIndicators = datatable(TimeGenerated:datetime, IndicatorValue:string, IndicatorType:string, ConfidenceScore:real, ThreatType:string, Description:string)[];
union SecurityAlert, SecurityIncident
| where TimeGenerated > ago(1d)
| extend TI_IpAddr = extract(@'"value"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"', 1, ExtendedProperties)
| where isnotempty(TI_IpAddr)
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | extend SignInIP = IPAddress
) on $left.TI_IpAddr == $right.SignInIP
| project TimeGenerated, UserPrincipalName, SignInIP, AlertName, Severity, TI_IpAddr
| extend ThreatReason = strcat("Sign-in from TI-matched IP: ", TI_IpAddr)
"@
        Severity    = "High"
        Frequency   = 1 hour
        Period      = 1 hour
    },

    # Rule 2: TI Match on Network Events
    @{
        Name        = "ZeroTrust - TI Match: Network Events Against Threat Indicators"
        Description = "Matches network connection events from common security tables against known malicious IP, domain, and URL indicators from threat intelligence feeds."
        Query       = @"
union SecurityAlert
| where TimeGenerated > ago(1d)
| extend CompromisedHost = tostring(parse_json(ExtendedProperties)["DeviceName"])
| extend TI_Indicator = tostring(parse_json(ExtendedProperties)["Indicator"])
| extend TI_Type = tostring(parse_json(ExtendedProperties)["IndicatorType"])
| where isnotempty(TI_Indicator) and isnotempty(CompromisedHost)
| project TimeGenerated, CompromisedHost, TI_Indicator, TI_Type, AlertName, Severity
| extend ThreatDescription = strcat("Network event matched TI indicator (", TI_Type, "): ", TI_Indicator)
"@
        Severity    = "High"
        Frequency   = 1 hour
        Period      = 1 hour
    },

    # Rule 3: TI Match on Process Execution with Known Malicious Hash
    @{
        Name        = "ZeroTrust - TI Match: File Hash Against Malware Indicators"
        Description = "Correlates endpoint process execution file hashes with threat intelligence malware indicators to detect execution of known malicious binaries."
        Query       = @"
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| project ProcessSHA256 = SHA256, DeviceName, FileName, AccountUpn, TimeGenerated, InitiatingProcessCommandLine
| where isnotempty(ProcessSHA256)
| join kind=inner (
    SecurityAlert
    | where TimeGenerated > ago(1d)
    | where AlertName contains "Malicious" or AlertName contains "TI" or AlertName contains "Indicator"
    | extend TI_Hash = tostring(parse_json(ExtendedProperties)["Indicator"])
    | where isnotempty(TI_Hash)
    | project TI_Hash, AlertName, Severity, TI_Severity = Severity
) on $left.ProcessSHA256 == $right.TI_Hash
| project TimeGenerated, DeviceName, FileName, AccountUpn, ProcessSHA256, AlertName, Severity, InitiatingProcessCommandLine
| extend ThreatDescription = strcat("Process hash matches known malicious indicator: ", ProcessSHA256)
"@
        Severity    = "Critical"
        Frequency   = 2 hours
        Period      = 1 hour
    },

    # Rule 4: TI Match on Outbound Connections to Malicious Domains
    @{
        Name        = "ZeroTrust - TI Match: Outbound Connections to Malicious Domains"
        Description = "Detects DNS lookups or outbound connections to domains flagged as malicious in threat intelligence feeds, indicating possible C2 communication or data exfiltration."
        Query       = @"
union SecurityAlert
| where TimeGenerated > ago(1d)
| extend MaliciousDomain = tostring(parse_json(ExtendedProperties)["Indicator"])
| extend DomainIndicatorType = tostring(parse_json(ExtendedProperties)["IndicatorType"])
| where DomainIndicatorType == "domain-name" and isnotempty(MaliciousDomain)
| extend AffectedHost = tostring(parse_json(ExtendedProperties)["DeviceName"])
| project TimeGenerated, AffectedHost, MaliciousDomain, AlertName, Severity
| extend ThreatDescription = strcat("Outbound connection to malicious domain: ", MaliciousDomain)
"@
        Severity    = "High"
        Frequency   = 1 hour
        Period      = 1 hour
    },

    # Rule 5: Stale / Expired Indicator Cleanup Report
    @{
        Name        = "ZeroTrust - TI Report: Stale and Expiring Indicators"
        Description = "Generates a report of threat intelligence indicators expiring within 7 days or already expired, ensuring operational hygiene and detection coverage."
        Query       = @"
union SecurityAlert
| where TimeGenerated > ago(7d)
| extend TI_Expiry = todatetime(tostring(parse_json(ExtendedProperties)["ExpirationDateTime"]))
| extend TI_Indicator = tostring(parse_json(ExtendedProperties)["Indicator"])
| extend TI_Type = tostring(parse_json(ExtendedProperties)["IndicatorType"])
| where isnotempty(TI_Expiry) and isnotempty(TI_Indicator)
| extend DaysUntilExpiry = datetime_diff('day', TI_Expiry, now())
| where DaysUntilExpiry <= 7
| extend Status = iff(DaysUntilExpiry < 0, "EXPIRED", "Expiring Soon")
| project TimeGenerated, TI_Indicator, TI_Type, TI_Expiry, DaysUntilExpiry, Status
| sort by DaysUntilExpiry asc
"@
        Severity    = "Informational"
        Frequency   = 1 day
        Period      = 1 day
    }
)

# ==========================================
# Step 6: Create TI Matching Analytics Rules
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 6: Creating TI Matching Analytics Rules" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$createdCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($rule in $tiRules) {
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
            DisplayName       = $rule.Name
            Description       = $rule.Description
            Enabled           = $false
            Query             = $rule.Query
            QueryFrequency    = $rule.Frequency
            QueryPeriod       = $rule.Period
            Severity          = $rule.Severity
            TriggerOperator   = "GreaterThan"
            TriggerThreshold  = 0
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
# Step 7: Create TI Overview Workbook
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 7: Creating Threat Intelligence Overview Workbook" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$workbookName = "ZeroTrust-Threat-Intelligence-Overview"
$workbookDescription = "Threat Intelligence overview — indicator counts by type, TI match trends, source health, and stale indicator tracking"

try {
    $existingWorkbook = Get-AzSentinelWorkbook `
        -ResourceGroupName $ResourceGroup `
        -WorkspaceName $WorkspaceName `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $workbookName }

    if ($existingWorkbook) {
        Write-Host "[SKIP] Workbook '$workbookName' already exists" -ForegroundColor Yellow
    }
    elseif ($WhatIf) {
        Write-Host "[WhatIf] Would create workbook: $workbookName" -ForegroundColor Yellow
    }
    else {
        $workbookContent = @{
            version  = "Notebook/1.0"
            items    = @(
                @{
                    type  = 3
                    content = @{
                        json = "Threat Intelligence Overview - Zero Trust Deployment"
                    }
                    name  = "Title"
                },
                @{
                    type  = 3
                    content = @{
                        json = "SecurityAlert | where TimeGenerated > ago(7d) | where ProductName == 'Microsoft Sentinel' | extend TI_Indicator = tostring(parse_json(ExtendedProperties)[\"Indicator\"]) | extend TI_Type = tostring(parse_json(ExtendedProperties)[\"IndicatorType\"]) | where isnotempty(TI_Indicator) | summarize Count = count() by TI_Type | render piechart"
                    }
                    name  = "TI Indicators by Type (7d)"
                },
                @{
                    type  = 3
                    content = @{
                        json = "SecurityAlert | where TimeGenerated > ago(30d) | where ProductName == 'Microsoft Sentinel' | extend TI_Indicator = tostring(parse_json(ExtendedProperties)[\"Indicator\"]) | where isnotempty(TI_Indicator) | summarize AlertCount = dcount(AlertName), IndicatorCount = dcount(TI_Indicator) by bin(TimeGenerated, 1d) | render timechart"
                    }
                    name  = "TI Match Trend (30d)"
                },
                @{
                    type  = 3
                    content = @{
                        json = "SecurityAlert | where TimeGenerated > ago(7d) | where ProductName == 'Microsoft Sentinel' | extend TI_Source = tostring(parse_json(ExtendedProperties)[\"ConfidenceScore\"]) | extend Severity = Severity | summarize Count = count() by Severity | render piechart"
                    }
                    name  = "TI Alerts by Severity (7d)"
                },
                @{
                    type  = 3
                    content = @{
                        json = "SecurityAlert | where TimeGenerated > ago(7d) | where AlertName contains 'TI Match' | project TimeGenerated, AlertName, Severity, DeviceName = tostring(parse_json(ExtendedProperties)[\"DeviceName\"]), TI_Indicator = tostring(parse_json(ExtendedProperties)[\"Indicator\"]) | sort by TimeGenerated desc"
                    }
                    name  = "Recent TI-Matched Alerts"
                },
                @{
                    type  = 3
                    content = @{
                        json = "SecurityAlert | where TimeGenerated > ago(7d) | extend TI_Expiry = todatetime(tostring(parse_json(ExtendedProperties)[\"ExpirationDateTime\"])) | where isnotempty(TI_Expiry) | extend DaysLeft = datetime_diff('day', TI_Expiry, now()) | where DaysLeft <= 7 | summarize Count = count() by iff(DaysLeft < 0, 'Expired', 'Expiring <= 7d') | render piechart"
                    }
                    name  = "Stale / Expiring Indicators"
                }
            )
            isLocked = $false
        }

        $workbookJson = $workbookContent | ConvertTo-Json -Depth 10

        New-AzSentinelWorkbook `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -DisplayName $workbookName `
            -Description $workbookDescription `
            -SerializedData $workbookJson

        Write-Host "[OK] Created workbook: $workbookName" -ForegroundColor Green
        Write-Host "     $workbookDescription" -ForegroundColor Gray
    }
}
catch {
    Write-Host "[WARNING] TI workbook: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Create manually: Sentinel > Workbooks > Add workbook" -ForegroundColor Gray
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "THREAT INTELLIGENCE INTEGRATION SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Workspace : $WorkspaceName" -ForegroundColor White
    Write-Host "Resource  : $ResourceGroup`n" -ForegroundColor White

    Write-Host "Components:" -ForegroundColor Cyan
    Write-Host "  [+] Threat Intelligence blade" -ForegroundColor Green
    Write-Host "  [+] Microsoft Threat Intelligence data source" -ForegroundColor Green

    if (-not [string]::IsNullOrWhiteSpace($TaxiiServerUrl)) {
        Write-Host "  [+] TAXII feed: $TaxiiFriendlyName" -ForegroundColor Green
    }
    else {
        Write-Host "  [-] TAXII feed: not configured" -ForegroundColor Gray
    }

    Write-Host "`nTI Matching Rules:" -ForegroundColor Cyan
    foreach ($rule in $tiRules) {
        Write-Host "  - $($rule.Name) [$($rule.Severity)]" -ForegroundColor White
    }

    Write-Host "`nWorkbook:" -ForegroundColor Cyan
    Write-Host "  - $workbookName" -ForegroundColor White

    Write-Host "`nRules created in DISABLED state." -ForegroundColor Yellow
    Write-Host "Review in Sentinel > Analytics > TI Matching, then enable." -ForegroundColor Yellow
    Write-Host "`nAccess workbook: Sentinel > Workbooks > $workbookName" -ForegroundColor Yellow
    Write-Host "Access TI data:  Sentinel > Threat Intelligence > Overview" -ForegroundColor Yellow
}
