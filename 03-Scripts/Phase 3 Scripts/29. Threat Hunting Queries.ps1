#Requires -Modules Az.Accounts, Az.OperationalInsights

<#
.SYNOPSIS
    Deploys pre-built threat hunting queries for SOC analysts.

.DESCRIPTION
    Provides KQL hunting queries for proactive threat investigation:
    - Suspicious login patterns
    - Lateral movement detection
    - Abnormal data access
    - Compromised endpoint investigation
    - Privilege escalation hunting
    - Persistence mechanism detection

    Queries are saved as Sentinel hunting queries and can be
    scheduled or run on-demand by SOC analysts.

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER WhatIf
    Shows what would happen without creating hunting queries.

.EXAMPLE
    .\29. Threat Hunting Queries.ps1
    .\29. Threat Hunting Queries.ps1 -WorkspaceName "MyWorkspace"
    .\29. Threat Hunting Queries.ps1 -WhatIf
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
# Hunting Query Definitions
# ==========================================
$huntingQueries = @(
    # Query 1: Suspicious Login Patterns
    @{
        Name        = "Hunting - Suspicious Login Patterns"
        Description = "Identifies users with unusual sign-in behavior: off-hours access, new locations, multiple failures"
        Category    = "Identity"
        Query       = @"
// Suspicious Login Patterns - Hunt for credential compromise
let baseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(7d))
| summarize Count = count() by UserPrincipalName, Location;
SigninLogs
| where TimeGenerated > ago(7d)
| join kind=leftanti baseline on UserPrincipalName, Location
| where ResultType == 0
| summarize SignInCount = count(), Locations = dcount(Location), Apps = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where SignInCount > 5 or Locations > 3
| project UserPrincipalName, IPAddress, SignInCount, Locations, Apps
| sort by SignInCount desc
"@
    },

    # Query 2: Lateral Movement Detection
    @{
        Name        = "Hunting - Lateral Movement"
        Description = "Detects potential lateral movement via pass-the-hash, pass-the-ticket, or remote execution"
        Category    = "Credential Access"
        Query       = @"
// Lateral Movement - Hunt for pass-the-hash, WinRM abuse
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625, 4648, 4672, 4776, 5140)
| where LogonType in (3, 10, 11)  // Network, RemoteInteractive, CachedInteractive
| summarize Count = count() by Account, ComputerName, LogonType, bin(TimeGenerated, 1h)
| where Count > 10
| project TimeGenerated, Account, ComputerName, LogonType, Count
| sort by Count desc
"@
    },

    # Query 3: Abnormal Data Access
    @{
        Name        = "Hunting - Abnormal Data Access"
        Description = "Identifies unusual file access patterns that may indicate data exfiltration"
        Category    = "Exfiltration"
        Query       = @"
// Abnormal Data Access - Hunt for data staging/exfiltration
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileDownloaded", "FileUploaded", "FileModified")
| summarize
    DownloadCount = countif(ActionType == "FileDownloaded"),
    UploadCount = countif(ActionType == "FileUploaded"),
    TotalSize = sum(FileSize),
    UniqueFiles = dcount(ActivityObjectId)
  by Account, bin(TimeGenerated, 1h)
| where DownloadCount > 50 or UploadCount > 10 or TotalSize > 524288000  // 500MB
| project TimeGenerated, Account, DownloadCount, UploadCount, TotalSizeMB = round(TotalSize/1048576, 2), UniqueFiles
| sort by TotalSize desc
"@
    },

    # Query 4: Compromised Endpoint Investigation
    @{
        Name        = "Hunting - Compromised Endpoint"
        Description = "Investigates a specific endpoint for signs of compromise"
        Category    = "Endpoint"
        Query       = @"
// Compromised Endpoint Investigation - Replace DeviceName with target
let targetDevice = "DEVICE-NAME-HERE";
let timeRange = ago(24h);
// Alerts on this device
let alerts = SecurityAlert
| where TimeGenerated > timeRange and DeviceName == targetDevice
| project AlertTime = TimeGenerated, AlertName, Severity, ProductName;
// Sign-ins from this device
let signins = SigninLogs
| where TimeGenerated > timeRange
| where DeviceDetail.displayName == targetDevice
| project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName;
// Process executions
let processes = SecurityEvent
| where TimeGenerated > timeRange and ComputerName == targetDevice
| where EventID == 4688
| project ProcessTime = TimeGenerated, Account, NewProcessName, CommandLine;
alerts | union signins | union processes | sort by TimeGenerated desc
"@
    },

    # Query 5: Privilege Escalation
    @{
        Name        = "Hunting - Privilege Escalation"
        Description = "Hunts for suspicious privilege escalation events"
        Category    = "Privilege Escalation"
        Query       = @"
// Privilege Escalation - Hunt for role assignments, PIM activations
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add eligible member to role", "Add scoped role member to role")
| extend TargetUser = tostring(Properties.targetResources[0].displayName)
| extend Actor = InitiatedBy.user.userPrincipalName
| extend Role = tostring(Properties.targetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, Actor, TargetUser, Role, OperationName
| sort by TimeGenerated desc
"@
    },

    # Query 6: Persistence Mechanisms
    @{
        Name        = "Hunting - Persistence Mechanisms"
        Description = "Detects potential persistence via scheduled tasks, services, or registry modifications"
        Category    = "Persistence"
        Query       = @"
// Persistence - Hunt for scheduled tasks, new services, registry changes
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (
    4698,   // Scheduled task created
    4697,   // Service installed
    4657,   // Registry value modified (Run keys)
    4720    // User account created
)
| extend Description = case(
    EventID == 4698, "Scheduled Task Created",
    EventID == 4697, "Service Installed",
    EventID == 4657, "Registry Modified (Run Key)",
    EventID == 4720, "User Account Created",
    "Unknown")
| project TimeGenerated, Account, ComputerName, EventID, Description, NewProcessName
| sort by TimeGenerated desc
"@
    }
)

# ==========================================
# Step 3: Create Hunting Queries
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Creating Hunting Queries" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$createdCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($query in $huntingQueries) {
    Write-Host "Processing: $($query.Name)" -ForegroundColor White

    try {
        $existing = Get-AzSentinelHuntingQuery `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $query.Name }

        if ($existing) {
            Write-Host "  [SKIP] Already exists" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        if ($WhatIf) {
            Write-Host "  [WhatIf] Would create hunting query: $($query.Name)" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        New-AzSentinelHuntingQuery `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -DisplayName $query.Name `
            -Description $query.Description `
            -Query $query.Query `
            -Category $query.Category

        Write-Host "  [OK] Created: $($query.Name)" -ForegroundColor Green
        Write-Host "       Category: $($query.Category)" -ForegroundColor Gray
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
Write-Host "THREAT HUNTING QUERIES SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Created : $createdCount hunting queries" -ForegroundColor Green
    Write-Host "Skipped : $skippedCount (already exist)" -ForegroundColor Yellow
    Write-Host "Errors  : $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Gray" })
    Write-Host "`nHunting queries deployed:" -ForegroundColor Cyan
    foreach ($q in $huntingQueries) {
        Write-Host "  - $($q.Name)" -ForegroundColor White
        Write-Host "    Category: $($q.Category)" -ForegroundColor Gray
        Write-Host "    $($q.Description)" -ForegroundColor Gray
    }
    Write-Host "`nAccess queries: Sentinel > Hunting > ZeroTrust-*" -ForegroundColor Yellow
    Write-Host "`nTip: Replace DEVICE-NAME-HERE in Compromised Endpoint query with actual device name." -ForegroundColor Yellow
}
