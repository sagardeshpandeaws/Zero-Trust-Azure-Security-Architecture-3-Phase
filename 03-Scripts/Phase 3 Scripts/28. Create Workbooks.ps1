#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights

<#
.SYNOPSIS
    Creates Sentinel workbooks for security operations dashboards.

.DESCRIPTION
    Deploys Sentinel workbooks that visualize:
    - Authentication trends (sign-ins, failures, risk levels)
    - Security alerts by severity and category
    - Endpoint threat statistics
    - Conditional Access policy activity
    - JML lifecycle events (joiners, movers, leavers)
    - SOC operations overview

    Workbooks provide real-time visibility for security analysts.

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER WhatIf
    Shows what would happen without creating workbooks.

.EXAMPLE
    .\28. Create Workbooks.ps1
    .\28. Create Workbooks.ps1 -WorkspaceName "MyWorkspace"
    .\28. Create Workbooks.ps1 -WhatIf
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
# Workbook Definitions
# ==========================================
$workbooks = @(
    # Workbook 1: Authentication Overview
    @{
        Name        = "ZeroTrust-Authentication-Overview"
        Description = "Authentication trends, sign-in patterns, and risk distribution"
        Queries     = @(
            @{
                Title = "Sign-In Volume (24h)"
                Query = "SigninLogs | where TimeGenerated > ago(24h) | summarize Count = count() by bin(TimeGenerated, 1h) | render timechart"
            },
            @{
                Title = "Failed Sign-Ins by User"
                Query = "SigninLogs | where TimeGenerated > ago(7d) and ResultType != 0 | summarize FailCount = count() by UserPrincipalName | top 10 by FailCount | render barchart"
            },
            @{
                Title = "Sign-Ins by Risk Level"
                Query = "SigninLogs | where TimeGenerated > ago(7d) | summarize Count = count() by RiskLevelDuringSignIn | render piechart"
            },
            @{
                Title = "Sign-Ins by Location"
                Query = "SigninLogs | where TimeGenerated > ago(7d) and ResultType == 0 | summarize Count = count() by Location | top 10 by Count | render barchart"
            }
        )
    },

    # Workbook 2: Security Alerts
    @{
        Name        = "ZeroTrust-Security-Alerts"
        Description = "Security alerts by severity, category, and trend"
        Queries     = @(
            @{
                Title = "Alerts by Severity (7d)"
                Query = "SecurityAlert | where TimeGenerated > ago(7d) | summarize Count = count() by Severity | render piechart"
            },
            @{
                Title = "Alert Trend (30d)"
                Query = "SecurityAlert | where TimeGenerated > ago(30d) | summarize Count = count() by bin(TimeGenerated, 1d) | render timechart"
            },
            @{
                Title = "Top Alert Types"
                Query = "SecurityAlert | where TimeGenerated > ago(30d) | summarize Count = count() by AlertName | top 10 by Count | render barchart"
            },
            @{
                Title = "Unresolved Alerts"
                Query = "SecurityAlert | where TimeGenerated > ago(7d) | where ExtendedProperties !contains 'Resolved' | project TimeGenerated, AlertName, Severity, ProductName"
            }
        )
    },

    # Workbook 3: Endpoint Threats
    @{
        Name        = "ZeroTrust-Endpoint-Threats"
        Description = "Endpoint security posture and threat detection"
        Queries     = @(
            @{
                Title = "Malware Detections (7d)"
                Query = "SecurityAlert | where TimeGenerated > ago(7d) and ProductName == 'Microsoft Defender for Endpoint' | summarize Count = count() by AlertName | top 10 by Count | render barchart"
            },
            @{
                Title = "Compromised Devices"
                Query = "SecurityAlert | where TimeGenerated > ago(30d) and ProductName == 'Microsoft Defender for Endpoint' | summarize dcount(DeviceName) by AlertName | top 10 by dcount_DeviceName | render barchart"
            },
            @{
                Title = "Device Compliance Status"
                Query = "IntuneDeviceComplianceOrg | summarize Count = count() by ComplianceState | render piechart"
            },
            @{
                Title = "Non-Compliant Devices"
                Query = "IntuneDeviceComplianceOrg | where ComplianceState == 'Noncompliant' | project DeviceName, UserPrincipalName, LastCheckInTime"
            }
        )
    },

    # Workbook 4: Conditional Access
    @{
        Name        = "ZeroTrust-Conditional-Access"
        Description = "Conditional Access policy evaluation and enforcement"
        Queries     = @(
            @{
                Title = "CA Policy Evaluations (24h)"
                Query = "SigninLogs | where TimeGenerated > ago(24h) | summarize Count = count() by ConditionalAccessStatus | render piechart"
            },
            @{
                Title = "CA Failures by Policy"
                Query = "SigninLogs | where TimeGenerated > ago(7d) and ConditionalAccessStatus == 'failure' | summarize Count = count() by AppDisplayName | top 10 by Count | render barchart"
            },
            @{
                Title = "MFA Challenge Results"
                Query = "SigninLogs | where TimeGenerated > ago(7d) | extend AuthMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod) | summarize Count = count() by AuthMethod | render piechart"
            }
        )
    },

    # Workbook 5: SOC Overview
    @{
        Name        = "ZeroTrust-SOC-Overview"
        Description = "Security Operations Center overview dashboard"
        Queries     = @(
            @{
                Title = "Incident Count (7d)"
                Query = "SecurityIncident | where TimeGenerated > ago(7d) | summarize Count = count() by Severity | render piechart"
            },
            @{
                Title = "Incident Trend (30d)"
                Query = "SecurityIncident | where TimeGenerated > ago(30d) | summarize Count = count() by bin(TimeGenerated, 1d) | render timechart"
            },
            @{
                Title = "Open Incidents"
                Query = "SecurityIncident | where Status != 'Closed' | project Number, Title, Severity, Status, CreatedTime, Owner"
            },
            @{
                Title = "Incidents by Category"
                Query = "SecurityIncident | where TimeGenerated > ago(30d) | summarize Count = count() by Classification | render barchart"
            }
        )
    },

    # Workbook 6: App Access Patterns
    @{
        Name        = "ZeroTrust-App-Access-Patterns"
        Description = "Application access patterns, OAuth consents, and API permission grants"
        Queries     = @(
            @{
                Title = "Top Apps by Sign-In Volume (7d)"
                Query = "SigninLogs | where TimeGenerated > ago(7d) | summarize Count = count() by AppDisplayName | top 20 by Count | render barchart"
            },
            @{
                Title = "Unusual OAuth App Consents"
                Query = "AuditLogs | where OperationName == 'Consent to application' | project TimeGenerated, InitiatedBy = InitiatedBy.user.userPrincipalName, AppName = TargetResources[0].displayName, Permissions = TargetResources[0].modifiedProperties"
            },
            @{
                Title = "API Permission Grants"
                Query = "AuditLogs | where OperationName == 'Add app role assignment to user' or OperationName == 'Add app role assignment grant to user' | project TimeGenerated, User = TargetResources[0].displayName, App = TargetResources[1].displayName"
            }
        )
    }
)

# ==========================================
# Step 3: Create Workbooks
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Creating Workbooks" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$createdCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($workbook in $workbooks) {
    Write-Host "Processing: $($workbook.Name)" -ForegroundColor White

    try {
        $existing = Get-AzSentinelWorkbook `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $workbook.Name }

        if ($existing) {
            Write-Host "  [SKIP] Already exists" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        if ($WhatIf) {
            Write-Host "  [WhatIf] Would create workbook: $($workbook.Name)" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        # Build workbook content
        $workbookContent = @{
            version  = "Notebook/1.0"
            items    = @()
            isLocked = $false
        }

        foreach ($q in $workbook.Queries) {
            $workbookContent.items += @{
                type  = 3
                content = @{
                    json = $q.Query
                }
                name  = $q.Title
            }
        }

        $workbookJson = $workbookContent | ConvertTo-Json -Depth 10

        New-AzSentinelWorkbook `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -DisplayName $workbook.Name `
            -Description $workbook.Description `
            -SerializedData $workbookJson

        Write-Host "  [OK] Created workbook: $($workbook.Name)" -ForegroundColor Green
        Write-Host "       $($workbook.Description)" -ForegroundColor Gray
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
Write-Host "WORKBOOKS DEPLOYMENT SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Created : $createdCount workbooks" -ForegroundColor Green
    Write-Host "Skipped : $skippedCount (already exist)" -ForegroundColor Yellow
    Write-Host "Errors  : $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Gray" })
    Write-Host "`nWorkbooks deployed:" -ForegroundColor Cyan
    foreach ($w in $workbooks) {
        Write-Host "  - $($w.Name)" -ForegroundColor White
        Write-Host "    $($w.Description)" -ForegroundColor Gray
    }
    Write-Host "`nAccess workbooks: Sentinel > Workbooks > ZeroTrust-*" -ForegroundColor Yellow
}
