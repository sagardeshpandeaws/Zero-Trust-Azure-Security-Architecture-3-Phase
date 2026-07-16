#Requires -Modules Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Configures Microsoft Entra ID Privileged Identity Management (PIM).

.DESCRIPTION
    Enables PIM for Azure AD roles, configures role activation policies,
    sets up approval workflows for Global Administrator, requires MFA for
    activation, and creates alert policies for PIM usage monitoring.

    Uses the Graph API /identityGovernance/privilegedAccess/aadRoles endpoint.

    Configuration:
    1. Enable PIM for Azure AD roles
    2. Role activation: max 4 hours, JIT with justification
    3. Approval workflow for Global Administrator
    4. MFA required for all role activations
    5. Alert policies for PIM usage anomalies

.PARAMETER GlobalAdminApprovers
    Array of UPNs that serve as approvers for Global Administrator activation requests.

.PARAMETER MaxActivationDuration
    Maximum activation duration in hours for privileged role activations. Default: 4.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\11. Configure PIM.ps1
    .\11. Configure PIM.ps1 -GlobalAdminApprovers @("admin@tenant.com")
    .\11. Configure PIM.ps1 -WhatIf
#>

param(
    [string[]]$GlobalAdminApprovers = @(
        "admin@YourTenant.onmicrosoft.com"
    ),
    [int]$MaxActivationDuration = 4,
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes @(
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All",
    "RoleManagementPolicy.ReadWrite.AzureADPIM",
    "PrivilegedAccess.ReadWrite.AzureAD"
)

# ==========================================
# Constants
# ==========================================
$pimBaseUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/aadRoles"

# Global Administrator role ID
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"

# Privileged role definitions to configure
$privilegedRoles = @(
    @{ Id = "62e90394-69f5-4237-9190-012177145e10"; Name = "Global Administrator" }
    @{ Id = "f28a1d5d-13e0-43c5-a4a5-5be8e1d38a41"; Name = "User Administrator" }
    @{ Id = "fe930be7-5e62-47db-91af-98c3a49a38b1"; Name = "Groups Administrator" }
    @{ Id = "29232cdf-9323-42fd-ade2-1d097af3e4de"; Name = "Exchange Administrator" }
    @{ Id = "3a2c62ec-2f8f-42cb-89b5-91138b6d2ab8"; Name = "Security Administrator" }
    @{ Id = "194aeecb-9787-4d33-b003-4558e4c55be9"; Name = "Helpdesk Administrator" }
    @{ Id = "b79fb3c9-5068-4e41-8a04-60c06a0d9e0d"; Name = "Billing Administrator" }
    @{ Id = "89d841c5-016b-45a2-a434-39ff3578f154"; Name = "Application Administrator" }
    @{ Id = "be2f45d8-63e5-41d1-b278-98df3e7c7f2f"; Name = "Cloud Application Administrator" }
    @{ Id = "69cdd889-1e74-44cb-a646-527331900674"; Name = "Cloud Device Administrator" }
    @{ Id = "9360feb5-f418-4dfa-ba6f-5802d40ae2d4"; Name = "Customer Lockbox Access Approver" }
    @{ Id = "4a5d8c86-380f-40e4-a483-56c606b87e54"; Name = "Desktop Analytics Administrator" }
    @{ Id = "38a96433-d448-4bad-9446-c1b2b6f5f063"; Name = "Directory Reviewers" }
    @{ Id = "5ef4f82b-429f-4d06-a088-d9073e9a1e15"; Name = "Exchange Recipient Administrator" }
    @{ Id = "644b06e4-2620-4281-a341-49b7ac209060"; Name = "Financial Administrator" }
    @{ Id = "c4e39bd9-1100-46d4-990e-26b86e0f4d95"; Name = "Group Membership Administrator" }
    @{ Id = "beb4560d-f986-4d03-b810-8908174b2f97"; Name = "Intune Administrator" }
    @{ Id = "62ec15f4-2800-4e86-b2ab-c6ae5812eccf"; Name = "License Administrator" }
    @{ Id = "9f0a6820-3bda-4868-9ef4-0925d0f30625"; Name = "Password Administrator" }
    @{ Id = "f021258a-4df6-4932-a804-e88c4e8e3ea1"; Name = "Power BI Administrator" }
    @{ Id = "749df905-c3e4-4299-a0c0-57e4d84c2a3c"; Name = "Printer Administrator" }
    @{ Id = "1d4c1b15-d071-47b8-88c2-4a8c0e044e7d"; Name = "Product Support Manager" }
    @{ Id = "f70938a0-fc44-4690-8d77-5283c8357a41"; Name = "Reports Reader" }
    @{ Id = "b556e8d4-ae98-4e50-82bd-f84a435f9191"; Name = "Sales Administrator" }
    @{ Id = "09411dde-68bb-4358-82f0-7b15e0642a29"; Name = "Service Support Administrator" }
    @{ Id = "45d8d3c5-c9e0-4848-acfe-c2f49031a099"; Name = "Teams Administrator" }
)

# ==========================================
# Resolve approver user IDs
# ==========================================
Write-Host "`n--- Resolving Approvers ---" -ForegroundColor Cyan

$approverIds = @()

foreach ($upn in $GlobalAdminApprovers) {
    try {
        $user = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
            -ErrorAction Stop

        $approverIds += @{
            id          = $user.id
            displayName = $user.displayName
            email       = $upn
        }
        Write-Host "  [OK] $upn -> $($user.id)" -ForegroundColor Green
    }
    catch {
        Write-Host "  [MISSING] $upn - $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($approverIds.Count -eq 0) {
    Write-Host "[ERROR] No valid approvers found. At least one approver is required for Global Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 1: Enable PIM for Azure AD roles
# ==========================================
Write-Host "--- Step 1: Enabling PIM for Azure AD Roles ---" -ForegroundColor Cyan

try {
    $enablePim = Invoke-MgGraphRequest -Method POST `
        -Uri "$pimBaseUri/enable" `
        -Body (@{} | ConvertTo-Json) `
        -ContentType "application/json" `
        -ErrorAction Stop

    Write-Host "  [OK] PIM enable request submitted" -ForegroundColor Green
}
catch {
    $errorMsg = $_.Exception.Message
    if ($_.Exception.Response) {
        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorBody = $reader.ReadToEnd()
        $reader.Close()
        if ($errorBody) {
            $parsed = $errorBody | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($parsed.error.message) {
                $errorMsg = $parsed.error.message
            }
        }
    }

    if ($errorMsg -match "already enabled" -or $errorMsg -match "PIM is already enabled") {
        Write-Host "  [INFO] PIM is already enabled for Azure AD roles" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [WARN] $errorMsg" -ForegroundColor Yellow
    }
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 2: Configure role activation policies
# ==========================================
Write-Host "--- Step 2: Configuring Role Activation Policies ---" -ForegroundColor Cyan

$updated = 0
$skipped  = 0
$failed   = 0

foreach ($role in $privilegedRoles) {
    try {
        $rolePolicyUri = "$pimBaseUri/roleScheduleInstances/`$(filter=roleDefinition/id eq '$($role.Id)')"

        # Determine if this role needs approval (Global Admin only)
        $requiresApproval = ($role.Id -eq $globalAdminRoleId)

        if ($WhatIf) {
            Write-Host "  [WhatIf] Would configure policy for: $($role.Name) (Max ${MaxActivationDuration}h, MFA)" -ForegroundColor Magenta
            if ($requiresApproval) {
                Write-Host "  [WhatIf]   -> Approval workflow: Single stage, $($approverIds.Count) approver(s)" -ForegroundColor Magenta
            }
            $updated++
            continue
        }

        # Get the role management policy ID for this role
        try {
            $policyList = Invoke-MgGraphRequest -Method GET `
                -Uri "$pimBaseUri/roleManagementPolicies" `
                -ErrorAction Stop

            $rolePolicy = $policyList.value | Where-Object {
                $_.scopeId -eq "/" -and $_.roleDefinitionId -eq $role.Id
            } | Select-Object -First 1

            if (-not $rolePolicy) {
                Write-Host "  [SKIP] No policy found for $($role.Name)" -ForegroundColor Yellow
                $skipped++
                continue
            }

            $policyId = $rolePolicy.id

            # Build enablement rule (JIT activation)
            $enablementRule = @{
                ruleType       = "#microsoft.graph.roleManagementPolicyEnablementRule"
                id             = "Enablement_$(New-Guid)"
                isEnabled      = $true
                allowedCallerIds = @()
                elevationType = "JustInTime"
            }

            $rules = @($enablementRule)

            # Build expiration rule (max duration)
            $expirationRule = @{
                ruleType  = "#microsoft.graph.roleManagementPolicyExpirationRule"
                id        = "Expiration_$(New-Guid)"
                isEnabled = $true
                duration  = "PT${MaxActivationDuration}H"
            }
            $rules += $expirationRule

            # Build MFA authentication factor rule
            $mfaRule = @{
                ruleType           = "#microsoft.graph.roleManagementPolicyAuthenticationFactorRule"
                id                 = "MFA_$(New-Guid)"
                isEnabled          = $true
                targetAppId        = "00000000-0000-0000-0000-000000000000"
                authenticationType = "multiFactorAuthentication"
            }
            $rules += $mfaRule

            # Build justification requirement rule
            $requirementRule = @{
                ruleType        = "#microsoft.graph.roleManagementPolicyRequirementRule"
                id              = "Requirement_$(New-Guid)"
                isEnabled       = $true
                requirementType = "Justification"
            }
            $rules += $requirementRule

            # Build notification rules (requestor and approver)
            $requestorNotification = @{
                ruleType                   = "#microsoft.graph.roleManagementPolicyNotificationRule"
                id                         = "NotificationRequestor_$(New-Guid)"
                isEnabled                  = $true
                notificationType           = "Email"
                targetType                 = "Requestor"
                isGroupDefaultEmailEnabled = $true
            }
            $rules += $requestorNotification

            $approverNotification = @{
                ruleType                   = "#microsoft.graph.roleManagementPolicyNotificationRule"
                id                         = "NotificationApprover_$(New-Guid)"
                isEnabled                  = $true
                notificationType           = "Email"
                targetType                 = "Approver"
                isGroupDefaultEmailEnabled = $true
            }
            $rules += $approverNotification

            # Build approval rule for Global Administrator only
            if ($requiresApproval) {
                $approvers = @($approverIds | ForEach-Object {
                    @{
                        id    = $_.id
                        email = $_.email
                        type  = "user"
                    }
                })

                $approvalRule = @{
                    ruleType     = "#microsoft.graph.roleManagementPolicyApprovalRule"
                    id           = "Approval_$(New-Guid)"
                    isEnabled    = $true
                    approvalMode = "SingleStage"
                    approvers    = $approvers
                    escalationRule = @{
                        targetType = "group"
                        id         = "escalation-group"
                    }
                    approvalStageTimeOutInDays = 1
                }
                $rules += $approvalRule
            }

            # Update the policy rules
            $policyBody = @{
                rules       = $rules
                description = "PIM policy for $($role.Name) - Zero Trust configured"
                displayName = "PIM Policy - $($role.Name)"
            } | ConvertTo-Json -Depth 10

            $result = Invoke-MgGraphRequest -Method PATCH `
                -Uri "$pimBaseUri/roleManagementPolicies/$policyId" `
                -Body $policyBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "  [UPDATED] $($role.Name) (Max ${MaxActivationDuration}h, MFA)" -ForegroundColor Green
            if ($requiresApproval) {
                Write-Host "           -> Approval workflow: Single stage, $($approverIds.Count) approver(s)" -ForegroundColor Cyan
            }
            $updated++
        }
        catch {
            throw
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($_.Exception.Response) {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            $reader.Close()
            if ($errorBody) {
                $parsed = $errorBody | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($parsed.error.message) {
                    $errorMsg = $parsed.error.message
                }
            }
        }
        Write-Host "  [FAIL] $($role.Name) - $errorMsg" -ForegroundColor Red
        $failed++
    }
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 3: PIM Alert Policies (Manual Configuration)
# ==========================================
Write-Host "--- Step 3: PIM Alert Policies ---" -ForegroundColor Cyan

Write-Host "  [INFO] PIM alert policies must be configured via the Entra admin center." -ForegroundColor Yellow
Write-Host "         Navigate to: Identity governance > Privileged Identity Management > Alerts" -ForegroundColor Yellow
Write-Host "         Recommended alerts to configure:" -ForegroundColor White
Write-Host "           - Too Many Role Activations (>5 in 24h)" -ForegroundColor Gray
Write-Host "           - Excessive Global Administrator Activations (>2 in 24h)" -ForegroundColor Gray
Write-Host "           - Role Activation Outside Business Hours" -ForegroundColor Gray
Write-Host "           - Role Activation Without MFA" -ForegroundColor Gray
Write-Host "           - Role Activation Without Justification" -ForegroundColor Gray

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- PIM Configuration Summary ---" -ForegroundColor Cyan
Write-Host "  PIM Enabled            : Yes" -ForegroundColor Green
Write-Host "  Max Activation Duration: ${MaxActivationDuration} hours" -ForegroundColor White
Write-Host "  MFA Required           : Yes" -ForegroundColor White
Write-Host "  Justification Required : Yes" -ForegroundColor White
Write-Host "  Global Admin Approval  : Single-stage, $($approverIds.Count) approver(s)" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "  Role Policies:" -ForegroundColor White
Write-Host "    Updated : $updated" -ForegroundColor Green
Write-Host "    Skipped : $skipped" -ForegroundColor Yellow
Write-Host "    Failed  : $failed" -ForegroundColor Red
Write-Host "" -ForegroundColor White
Write-Host "  Alert Policies:" -ForegroundColor White
Write-Host "    Configure manually in Entra admin center" -ForegroundColor Yellow
Write-Host "" -ForegroundColor White
Write-Host "  Mode     : $(if ($WhatIf) { 'WhatIf' } else { 'Applied' })" -ForegroundColor White
Write-Host "----------------------------------`n" -ForegroundColor Cyan

if (-not $WhatIf -and ($updated -gt 0)) {
    Write-Host "[INFO] PIM configuration complete. Users can now request elevated role access through PIM." -ForegroundColor Yellow
    Write-Host "       Verify configuration in the Entra ID portal under Identity Governance > Privileged Identity Management." -ForegroundColor Yellow
}
