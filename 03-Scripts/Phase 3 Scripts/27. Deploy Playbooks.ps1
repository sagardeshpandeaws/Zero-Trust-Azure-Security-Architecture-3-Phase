#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights, Az.LogicApp, Microsoft.Graph.Users.Actions

<#
.SYNOPSIS
    Deploys Sentinel playbooks (SOAR) for automated incident response.

.DESCRIPTION
    Creates Azure Logic App playbooks that automate security responses:
    - Disable compromised user accounts
    - Force password reset for risky users
    - Isolate infected endpoint devices
    - Notify security administrators via email

    Playbooks are triggered by Sentinel incidents or manually.
    Each playbook uses Managed Identity for authentication.

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER NotificationEmail
    Email address for security notifications. Defaults to "soc@yourtenant.com".

.PARAMETER WhatIf
    Shows what would happen without creating playbooks.

.EXAMPLE
    .\27. Deploy Playbooks.ps1
    .\27. Deploy Playbooks.ps1 -NotificationEmail "security@yourtenant.com"
    .\27. Deploy Playbooks.ps1 -WhatIf
#>

param(
    [string]$WorkspaceName = "Sentinel-ZeroTrust-Workspace",
    [string]$ResourceGroup = "rg-sentinel-zerotrust",
    [string]$NotificationEmail = "soc@yourtenant.com",
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
# Step 3: Create Managed Identity
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Creating Logic App Managed Identity" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$identityName = "Sentinel-SOAR-Identity"

try {
    $existingIdentity = Get-AzADServicePrincipal -DisplayName $identityName -ErrorAction SilentlyContinue

    if ($existingIdentity) {
        Write-Host "[SKIP] Managed identity '$identityName' already exists" -ForegroundColor Yellow
    }
    else {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would create managed identity: $identityName" -ForegroundColor Yellow
        }
        else {
            New-AzADServicePrincipal -DisplayName $identityName
            Write-Host "[OK] Created managed identity: $identityName" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "[WARNING] Identity creation: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ==========================================
# Playbook Definitions
# ==========================================
$playbooks = @(
    # Playbook 1: Disable Compromised Account
    @{
        Name        = "Sentinel-DisableCompromisedAccount"
        Description = "Disables a compromised user account when incident is triggered"
        LogicApp    = @{
            definition = @{
                '$schema' = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
                contentVersion = "1.0.0.0"
                parameters = @{
                    workspaceName = @{ type = "string"; defaultValue = $WorkspaceName }
                    resourceGroup = @{ type = "string"; defaultValue = $ResourceGroup }
                }
                triggers = @{
                    "When_a_response_to_an_Azure_Sentinel_alert_is_triggered" = @{
                        type = "ApiConnection"
                        kind = "AzureSentinel"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuresentinel']['connectionId']" } }
                            method = "post"
                            path = "/triggerables/execute"
                        }
                    }
                }
                actions = @{
                    "Get_User_UPN_from_alert" = @{
                        type = "Compose"
                        inputs = "@triggerBody()?['object']?['properties']?['relatedEntities']![?(@.type == 'account')][0]?['properties']?['userPrincipalName']"
                    }
                    "Disable_User_Account" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuread']['connectionId']" } }
                            method = "post"
                            path = "/v1.0/users/@{body('Get_User_UPN_from_alert')}/accountEnabled"
                            body = "false"
                        }
                    }
                    "Send_Notification_Email" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['office365']['connectionId']" } }
                            method = "post"
                            path = "/v2/Mail/SendEmail"
                            body = @{
                                To = $NotificationEmail
                                Subject = "[SENTINEL] Account Disabled: @{body('Get_User_UPN_from_alert')}"
                                Body = "A compromised account has been automatically disabled by Sentinel playbook.`n`nUser: @{body('Get_User_UPN_from_alert')}`nTime: @{utcNow()}`nAction: Account Disabled"
                                Importance = "High"
                            }
                        }
                    }
                }
            }
        }
    },

    # Playbook 2: Force Password Reset
    @{
        Name        = "Sentinel-ForcePasswordReset"
        Description = "Forces password reset for high-risk users"
        LogicApp    = @{
            definition = @{
                '$schema' = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
                contentVersion = "1.0.0.0"
                parameters = @{}
                triggers = @{
                    "When_a_response_to_an_Azure_Sentinel_alert_is_triggered" = @{
                        type = "ApiConnection"
                        kind = "AzureSentinel"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuresentinel']['connectionId']" } }
                            method = "post"
                            path = "/triggerables/execute"
                        }
                    }
                    "Manual" = @{
                        type = "Request"
                        kind = "Http"
                        inputs = @{
                            schema = @{
                                type = "object"
                                properties = @{
                                    userPrincipalName = @{ type = "string" }
                                }
                            }
                        }
                    }
                }
                actions = @{
                    "Invalidate_User_Sessions" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuread']['connectionId']" } }
                            method = "post"
                            path = "/v1.0/users/@{triggerBody()?['userPrincipalName']}/invalidateRefresh"
                        }
                    }
                    "Require_Password_Change" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuread']['connectionId']" } }
                            method = "patch"
                            path = "/v1.0/users/@{triggerBody()?['userPrincipalName']}"
                            body = @{
                                passwordProfile = @{
                                    forceChangePasswordNextSignIn = $true
                                }
                            }
                        }
                    }
                }
            }
        }
    },

    # Playbook 3: Isolate Endpoint
    @{
        Name        = "Sentinel-IsolateEndpoint"
        Description = "Isolates an infected endpoint using Defender for Endpoint"
        LogicApp    = @{
            definition = @{
                '$schema' = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
                contentVersion = "1.0.0.0"
                parameters = @{}
                triggers = @{
                    "When_a_response_to_an_Azure_Sentinel_alert_is_triggered" = @{
                        type = "ApiConnection"
                        kind = "AzureSentinel"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuresentinel']['connectionId']" } }
                            method = "post"
                            path = "/triggerables/execute"
                        }
                    }
                    "Manual" = @{
                        type = "Request"
                        kind = "Http"
                        inputs = @{
                            schema = @{
                                type = "object"
                                properties = @{
                                    deviceId = @{ type = "string" }
                                }
                            }
                        }
                    }
                }
                actions = @{
                    "Isolate_Device" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['microsoftdefenderatp']['connectionId']" } }
                            method = "post"
                            path = "/api/machines/@{triggerBody()?['deviceId']}/isolate"
                            body = @{
                                IsolationType = "Full"
                                Comment = "Automated isolation by Sentinel SOAR playbook"
                            }
                        }
                    }
                    "Notify_SOC" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['office365']['connectionId']" } }
                            method = "post"
                            path = "/v2/Mail/SendEmail"
                            body = @{
                                To = $NotificationEmail
                                Subject = "[SENTINEL] Endpoint Isolated: @{triggerBody()?['deviceId']}"
                                Body = "An endpoint has been automatically isolated by Sentinel playbook.`n`nDevice: @{triggerBody()?['deviceId']}`nTime: @{utcNow()}`nAction: Full Network Isolation"
                                Importance = "High"
                            }
                        }
                    }
                }
            }
        }
    },

    # Playbook 4: Notify Security Admin
    @{
        Name        = "Sentinel-NotifySecurityAdmin"
        Description = "Sends email notification to SOC team for incident triage"
        LogicApp    = @{
            definition = @{
                '$schema' = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
                contentVersion = "1.0.0.0"
                parameters = @{}
                triggers = @{
                    "When_a_response_to_an_Azure_Sentinel_alert_is_triggered" = @{
                        type = "ApiConnection"
                        kind = "AzureSentinel"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['azuresentinel']['connectionId']" } }
                            method = "post"
                            path = "/triggerables/execute"
                        }
                    }
                }
                actions = @{
                    "Send_Alert_Summary" = @{
                        type = "ApiConnection"
                        inputs = @{
                            host = @{ connection = @{ name = "@parameters('\$connections')['office365']['connectionId']" } }
                            method = "post"
                            path = "/v2/Mail/SendEmail"
                            body = @{
                                To = $NotificationEmail
                                Subject = "[SENTINEL] New Incident: @{triggerBody()?['object']?['properties']?['displayName']}"
                                Body = "New Sentinel incident requires review.`n`nIncident: @{triggerBody()?['object']?['properties']?['displayName']}`nSeverity: @{triggerBody()?['object']?['properties']?['severity']}`nTime: @{utcNow()}`n`nReview in Sentinel portal."
                                Importance = "High"
                            }
                        }
                    }
                }
            }
        }
    }
)

# ==========================================
# Step 4: Create Playbooks
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 4: Deploying Playbooks" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$createdCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($playbook in $playbooks) {
    Write-Host "Processing: $($playbook.Name)" -ForegroundColor White

    try {
        $existing = Get-AzLogicApp `
            -ResourceGroupName $ResourceGroup `
            -Name $playbook.Name `
            -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Host "  [SKIP] Already exists" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        if ($WhatIf) {
            Write-Host "  [WhatIf] Would create playbook: $($playbook.Name)" -ForegroundColor Yellow
            $skippedCount++
            continue
        }

        $location = $workspace.Location

        New-AzLogicApp `
            -ResourceGroupName $ResourceGroup `
            -Name $playbook.Name `
            -Location $location `
            -Definition $playbook.LogicApp.definition

        Write-Host "  [OK] Created playbook: $($playbook.Name)" -ForegroundColor Green
        Write-Host "       $($playbook.Description)" -ForegroundColor Gray
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
Write-Host "PLAYBOOKS (SOAR) DEPLOYMENT SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Created : $createdCount playbooks" -ForegroundColor Green
    Write-Host "Skipped : $skippedCount (already exist)" -ForegroundColor Yellow
    Write-Host "Errors  : $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Gray" })
    Write-Host "`nPlaybooks deployed:" -ForegroundColor Cyan
    foreach ($p in $playbooks) {
        Write-Host "  - $($p.Name)" -ForegroundColor White
        Write-Host "    $($p.Description)" -ForegroundColor Gray
    }
    Write-Host "`nNext Steps:" -ForegroundColor Yellow
    Write-Host "  1. Configure API connections in each Logic App" -ForegroundColor White
    Write-Host "  2. Assign Managed Identity appropriate roles" -ForegroundColor White
    Write-Host "  3. Test playbooks with sample incidents" -ForegroundColor White
    Write-Host "  4. Link playbooks to analytics rules in Sentinel" -ForegroundColor White
}
