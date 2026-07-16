#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights

<#
.SYNOPSIS
    Deploys a guided incident investigation workbook in Microsoft Sentinel.

.DESCRIPTION
    Creates a structured workbook called "ZeroTrust-Incident-Investigation" with KQL
    queries mapped to 8 investigation workflow steps:

    1. Scope the Incident       - Timeline overview, affected entities
    2. Identify Affected Users  - Sign-in anomalies, risk events
    3. Identify Affected Devices - Device alerts, non-compliant devices
    4. Collect Evidence          - Process executions, network connections, file modifications
    5. Timeline Reconstruction   - Unified timeline across all data sources
    6. Root Cause Analysis       - Initial access vector, persistence mechanisms
    7. Containment Actions       - Disable accounts, isolate devices, block IPs
    8. Post-Incident Review      - Lessons learned, policy improvements

    Each section contains 2-3 KQL queries designed for SOC analyst workflows.
    The workbook is deployed via the Microsoft Graph API.

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER TenantId
    Azure AD tenant ID. If not provided, uses the current session tenant.

.PARAMETER WhatIf
    Shows what would happen without creating the workbook.

.EXAMPLE
    .\30. Incident Investigation Workflow.ps1
    .\30. Incident Investigation Workflow.ps1 -WorkspaceName "MyWorkspace"
    .\30. Incident Investigation Workflow.ps1 -WhatIf
#>

param(
    [string]$WorkspaceName = "Sentinel-ZeroTrust-Workspace",
    [string]$ResourceGroup = "rg-sentinel-zerotrust",
    [string]$TenantId,
    [switch]$WhatIf
)

# ==========================================
# Step 1: Connect to Azure
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 1: Connecting to Azure" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($TenantId) {
        Connect-AzAccount -UseDeviceAuthentication -TenantId $TenantId
    }
    else {
        Connect-AzAccount -UseDeviceAuthentication
    }
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
# Step 3: Obtain Graph API Token
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Obtaining Graph API Access Token" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    $context = Get-AzContext
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    Write-Host "[OK] Graph API token acquired" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to obtain Graph API token: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# ==========================================
# Step 4: Build Workbook Content
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 4: Building Investigation Workbook" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$workbookDescription = "Guided incident investigation workflow with KQL queries mapped to 8 investigation steps"

# Define investigation sections with KQL queries
$investigationSections = @(
    # Section 1: Scope the Incident
    @{
        Title       = "1. Scope the Incident"
        Description = "Timeline overview and affected entities"
        Queries     = @(
            @{
                Title = "Incident Timeline Overview"
                Query = @"
SecurityIncident
| where TimeGenerated > ago(7d)
| project Number, Title, Severity, Status, CreatedTime, ModifiedTime
| sort by CreatedTime desc
| render timechart
"@
            },
            @{
                Title = "Affected Entities by Type"
                Query = @"
SecurityIncident
| where TimeGenerated > ago(7d)
| extend EntityData = parse_json(AdditionalData).entities
| extend EntityCount = array_length(EntityData)
| summarize EntityCount = sum(EntityCount) by IncidentNumber, Title, Severity
| sort by EntityCount desc
| render barchart
"@
            },
            @{
                Title = "Alert Distribution by Product"
                Query = @"
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount = count() by ProductName, Severity
| sort by AlertCount desc
| render piechart
"@
            }
        )
    },

    # Section 2: Identify Affected Users
    @{
        Title       = "2. Identify Affected Users"
        Description = "Sign-in anomalies and risk events"
        Queries     = @(
            @{
                Title = "Users with Failed Sign-Ins"
                Query = @"
SigninLogs
| where TimeGenerated > ago(7d) and ResultType != 0
| summarize
    FailedCount = count(),
    Locations = dcount(Location),
    Apps = dcount(AppDisplayName)
  by UserPrincipalName, IPAddress
| where FailedCount > 5
| sort by FailedCount desc
"@
            },
            @{
                Title = "High-Risk User Sign-Ins"
                Query = @"
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, RiskLevelDuringSignIn, IPAddress, Location, AppDisplayName
| sort by TimeGenerated desc
"@
            },
            @{
                Title = "IdentityRiskEvents"
                Query = @"
IdentityInfo
| where TimeGenerated > ago(30d)
| where RiskLevel != "none" and RiskLevel != ""
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project AccountUPN, RiskLevel, RiskEventType, RiskLastUpdatedDateTime
| sort by RiskLevel desc
"@
            }
        )
    },

    # Section 3: Identify Affected Devices
    @{
        Title       = "3. Identify Affected Devices"
        Description = "Device alerts and non-compliant devices"
        Queries     = @(
            @{
                Title = "Devices with Security Alerts"
                Query = @"
SecurityAlert
| where TimeGenerated > ago(7d)
| where ProductName == "Microsoft Defender for Endpoint"
| summarize AlertCount = count(), MaxSeverity = max(Severity) by DeviceName, DeviceIP
| sort by AlertCount desc
| render barchart
"@
            },
            @{
                Title = "Non-Compliant Devices"
                Query = @"
IntuneDeviceComplianceOrg
| where ComplianceState == "Noncompliant"
| project DeviceName, UserPrincipalName, OS, ComplianceState, LastCheckInTime
| sort by LastCheckInTime desc
"@
            },
            @{
                Title = "Device Logon Events"
                Query = @"
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624 and LogonType in (2, 10, 11)
| summarize LogonCount = count() by ComputerName, Account, LogonType
| where LogonCount > 10
| sort by LogonCount desc
"@
            }
        )
    },

    # Section 4: Collect Evidence
    @{
        Title       = "4. Collect Evidence"
        Description = "Process executions, network connections, file modifications"
        Queries     = @(
            @{
                Title = "Suspicious Process Executions"
                Query = @"
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where NewProcessName endswith ".exe"
| where NewProcessName has_any ("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
| summarize ExecutionCount = count() by Account, ComputerName, NewProcessName, CommandLine
| where ExecutionCount > 3
| sort by ExecutionCount desc
"@
            },
            @{
                Title = "Outbound Network Connections"
                Query = @"
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceAction == "connection-success"
| where DestinationPort !in (80, 443, 53)
| summarize ConnectionCount = count() by DeviceExternalID, DestinationIP, DestinationPort, DestinationHostName
| where ConnectionCount > 5
| sort by ConnectionCount desc
"@
            },
            @{
                Title = "File Modifications on Endpoints"
                Query = @"
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4663, 4656)
| where ObjectType == "File"
| where AccessMask has_any ("0x2", "0x4", "0x10000")
| summarize ModificationCount = count() by ComputerName, Account, ObjectName
| where ModificationCount > 10
| sort by ModificationCount desc
"@
            }
        )
    },

    # Section 5: Timeline Reconstruction
    @{
        Title       = "5. Timeline Reconstruction"
        Description = "Unified timeline across all data sources"
        Queries     = @(
            @{
                Title = "Unified Security Event Timeline"
                Query = @"
let incidentId = "INCIDENT-NUMBER-HERE";
let timeRange = ago(7d);
let alerts = SecurityAlert
| where TimeGenerated > timeRange
| extend Source = "Alert", EventTime = TimeGenerated
| project EventTime, Source, Title = AlertName, Details = ProductName;
let signins = SigninLogs
| where TimeGenerated > timeRange
| extend Source = "SignIn", EventTime = TimeGenerated
| project EventTime, Source, Title = AppDisplayName, Details = tostring(ResultDescription);
let events = SecurityEvent
| where TimeGenerated > timeRange
| where EventID in (4624, 4625, 4688, 4720, 4732, 4698, 4697)
| extend Source = "Event", EventTime = TimeGenerated
| project EventTime, Source, Title = tostring(EventID), Details = Account;
alerts | union signins | union events | sort by EventTime desc
"@
            },
            @{
                Title = "User Activity Timeline"
                Query = @"
let targetUser = "USER@DOMAIN.COM";
let timeRange = ago(7d);
let userSignins = SigninLogs
| where TimeGenerated > timeRange and UserPrincipalName == targetUser
| extend Source = "SignIn", Activity = strcat(AppDisplayName, " - ", Location);
let userEvents = SecurityEvent
| where TimeGenerated > timeRange and Account == targetUser
| extend Source = "SecurityEvent", Activity = strcat("EventID: ", tostring(EventID), " - ", ComputerName);
let userAlerts = SecurityAlert
| where TimeGenerated > timeRange
| where ExtendedProperties has targetUser
| extend Source = "Alert", Activity = AlertName;
userSignins | union userEvents | union userAlerts | sort by TimeGenerated desc
"@
            }
        )
    },

    # Section 6: Root Cause Analysis
    @{
        Title       = "6. Root Cause Analysis"
        Description = "Initial access vector and persistence mechanisms"
        Queries     = @(
            @{
                Title = "Initial Access Vector"
                Query = @"
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertName has_any ("phishing", "malicious", "compromise", "suspicious")
| extend Entities = parse_json(Entities)
| extend AccountUPN = tostring(Entities[0].Properties.userPrincipalName)
| extend IPAddress = tostring(Entities[1].Properties.address)
| project TimeGenerated, AlertName, Severity, AccountUPN, IPAddress
| sort by TimeGenerated asc
| take 20
"@
            },
            @{
                Title = "Persistence Mechanisms Detected"
                Query = @"
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID in (
    4698,
    4697,
    4657,
    4720,
    4732
)
| extend Mechanism = case(
    EventID == 4698, "Scheduled Task Created",
    EventID == 4697, "Service Installed",
    EventID == 4657, "Registry Modified",
    EventID == 4720, "User Account Created",
    EventID == 4732, "Group Membership Changed",
    "Unknown")
| project TimeGenerated, Account, ComputerName, EventID, Mechanism
| sort by TimeGenerated desc
"@
            },
            @{
                Title = "Credential Dumping Indicators"
                Query = @"
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4688)
| where NewProcessName has_any ("procdump", "mimikatz", "lsass", "comsvcs", "tasklist")
    or CommandLine has_any ("sekurlsa", "lsass.exe", "procdump", "minidump")
| summarize ExecutionCount = count() by ComputerName, Account, NewProcessName, CommandLine
| sort by ExecutionCount desc
"@
            }
        )
    },

    # Section 7: Containment Actions
    @{
        Title       = "7. Containment Actions"
        Description = "Disable accounts, isolate devices, block IPs"
        Queries     = @(
            @{
                Title = "Accounts to Disable"
                Query = @"
IdentityInfo
| where TimeGenerated > ago(7d)
| where RiskLevel in ("high", "critical")
| summarize arg_max(TimeGenerated, *) by AccountUPN
| where AccountEnabled == true
| project AccountUPN, RiskLevel, RiskEventType, LastSeen = TimeGenerated
| sort by RiskLevel desc
"@
            },
            @{
                Title = "Devices to Isolate"
                Query = @"
SecurityAlert
| where TimeGenerated > ago(7d)
| where Severity in ("High", "Critical")
| where ProductName == "Microsoft Defender for Endpoint"
| summarize AlertCount = count(), MaxSeverity = max(Severity) by DeviceName, DeviceIP
| where AlertCount >= 2
| sort by AlertCount desc
"@
            },
            @{
                Title = "IP Addresses to Block"
                Query = @"
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceAction in ("connection-success", "connection-attempt")
| where isnotempty(DestinationIP)
| summarize
    ConnectionCount = count(),
    DestinationPorts = make_set(DestinationPort),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DestinationIP
| where ConnectionCount > 20
| sort by ConnectionCount desc
"@
            }
        )
    },

    # Section 8: Post-Incident Review
    @{
        Title       = "8. Post-Incident Review"
        Description = "Lessons learned and policy improvements"
        Queries     = @(
            @{
                Title = "Incident Resolution Summary"
                Query = @"
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| summarize
    IncidentsClosed = count(),
    AvgTimeToResolve = avg(datetime_diff("minute", ModifiedTime, CreatedTime)),
    BySeverity = countif(Severity == "High" or Severity == "Critical")
  by Classification
| sort by IncidentsClosed desc
"@
            },
            @{
                Title = "Detection Gap Analysis"
                Query = @"
SecurityIncident
| where TimeGenerated > ago(30d)
| where Classification in ("True Positive", "Undetermined")
| extend AlertsCount = array_length(Alerts)
| summarize
    TotalIncidents = count(),
    AvgAlertsPerIncident = avg(AlertsCount),
    TopTechniques = make_set(Alerts[0].AlertProperties.MitreTechniques)
  by Severity
| sort by TotalIncidents desc
"@
            },
            @{
                Title = "Policy Effectiveness Review"
                Query = @"
SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus == "failure"
| summarize
    BlockedCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueApps = dcount(AppDisplayName)
  by ConditionalAccessStatus
| union (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ConditionalAccessStatus == "success"
    | summarize
        SuccessCount = count(),
        UniqueUsers = dcount(UserPrincipalName),
        UniqueApps = dcount(AppDisplayName)
    | extend ConditionalAccessStatus = "success"
)
| sort by BlockedCount desc
"@
            }
        )
    }
)

# Build the Graph API workbook payload
$workbookSections = @()
$partNumber = 1

foreach ($section in $investigationSections) {
    $sectionItems = @()

    foreach ($query in $section.Queries) {
        $sectionItems += @{
            type  = 3
            content = @{
                json = $query.Query
            }
            name  = $query.Title
        }
    }

    $workbookSections += @{
        type  = 1
        content = @{
            json = "## $($section.Title)`n$($section.Description)"
        }
        name  = $section.Title
    }

    $workbookSections += $sectionItems
    $partNumber++
}

$workbookPayload = @{
    displayName  = "ZeroTrust-Incident-Investigation"
    description  = $workbookDescription
    notebooks    = @()
    source       = @{
        type = "Local"
    }
    version      = "Notebook/1.0"
    isOnBoarded  = $true
    content      = @{
        `$schema  = "https://github.com/Azure/Azure-Sentinel/blob/master/Workbooks/schema/SentinelWorkbooksSchema.json"
        version   = "Notebook/1.0"
        isLocked  = $false
        items     = $workbookSections
    }
} | ConvertTo-Json -Depth 20

Write-Host "[OK] Workbook content built: ZeroTrust-Incident-Investigation" -ForegroundColor Green
Write-Host "     Sections: $($investigationSections.Count) investigation steps" -ForegroundColor Gray
$totalQueries = ($investigationSections | ForEach-Object { $_.Queries.Count } | Measure-Object -Sum).Sum
Write-Host "     Total KQL queries: $totalQueries" -ForegroundColor Gray

# ==========================================
# Step 5: Check for Existing Workbook
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 5: Checking for Existing Workbook" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$subscriptionId = $context.Subscription.Id
$tenantId = $context.Tenant.Id
$resourceName = "ZeroTrust-Incident-Investigation"

$checkUrl = "https://graph.microsoft.com/v1.0/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.SecurityInsights/workspaces/$WorkspaceName/providers/Microsoft.Insights/workbooks/$resourceName"

try {
    $existingCheck = Invoke-RestMethod -Uri $checkUrl -Headers $headers -Method Get -ErrorAction SilentlyContinue
    if ($existingCheck) {
        Write-Host "[INFO] Workbook already exists - will update" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[OK] No existing workbook found - will create new" -ForegroundColor Green
}

# ==========================================
# Step 6: Deploy Workbook via Graph API
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 6: Deploying Investigation Workbook" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "[WhatIf] Would create workbook: ZeroTrust-Incident-Investigation" -ForegroundColor Yellow
    Write-Host "[WhatIf] Investigation sections:" -ForegroundColor Yellow
    foreach ($section in $investigationSections) {
        Write-Host "         - $($section.Title) ($($section.Queries.Count) queries)" -ForegroundColor Yellow
    }
    Write-Host "[WhatIf] Total queries: $totalQueries" -ForegroundColor Yellow
}
else {
    try {
        $createUrl = "https://graph.microsoft.com/v1.0/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.SecurityInsights/workspaces/$WorkspaceName/providers/Microsoft.Insights/workbooks/$resourceName"

        $body = @{
            location   = $workspace.Location
            kind       = "shared"
            properties = @{
                displayName  = "ZeroTrust-Incident-Investigation"
                description  = $workbookDescription
                serializedData = $workbookPayload | ConvertFrom-Json
                version      = "1.0"
                sourceId     = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
            }
        } | ConvertTo-Json -Depth 20

        $result = Invoke-RestMethod -Uri $createUrl -Headers $headers -Method Put -Body $body
        Write-Host "[OK] Workbook created: ZeroTrust-Incident-Investigation" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Graph API failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[INFO] Falling back to Az Sentinel cmdlets..." -ForegroundColor Yellow

        try {
            $workbookData = $workbookPayload | ConvertFrom-Json
            $serializedData = $workbookData.content | ConvertTo-Json -Depth 20 -Compress

            New-AzSentinelWorkbook `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -DisplayName "ZeroTrust-Incident-Investigation" `
                -Description $workbookDescription `
                -SerializedData $serializedData `
                -ErrorAction Stop

            Write-Host "[OK] Workbook created via Az cmdlet: ZeroTrust-Incident-Investigation" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Fallback also failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "INCIDENT INVESTIGATION WORKBOOK SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Workbook : ZeroTrust-Incident-Investigation" -ForegroundColor Green
    Write-Host "Location : Sentinel > Workbooks" -ForegroundColor White
    Write-Host "`nInvestigation Sections:" -ForegroundColor Cyan
    foreach ($section in $investigationSections) {
        Write-Host "  $($section.Title)" -ForegroundColor White
        Write-Host "    $($section.Description)" -ForegroundColor Gray
        foreach ($query in $section.Queries) {
            Write-Host "      - $($query.Title)" -ForegroundColor Gray
        }
    }
    Write-Host "`nUsage:" -ForegroundColor Yellow
    Write-Host "  1. Open Sentinel > Workbooks > ZeroTrust-Incident-Investigation" -ForegroundColor White
    Write-Host "  2. Follow the 8-step workflow for each incident" -ForegroundColor White
    Write-Host "  3. Replace placeholder values (INCIDENT-NUMBER-HERE, USER@DOMAIN.COM) with actual data" -ForegroundColor White
    Write-Host "  4. Each section provides 2-3 KQL queries for that investigation phase" -ForegroundColor White
    Write-Host "`nTip: Pin frequently used queries to your workspace favorites for quick access." -ForegroundColor Yellow
}
