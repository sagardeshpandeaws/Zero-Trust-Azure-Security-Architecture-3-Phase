#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates Intune device compliance policies for Zero Trust deployment.

.DESCRIPTION
    Deploys compliance policies that enforce:
    - BitLocker encryption
    - Secure Boot
    - Antivirus protection
    - Minimum OS version
    - Password requirements
    - Jailbreak detection (mobile)

    Only compliant devices are granted access via Conditional Access (Script 4).

.PARAMETER WhatIf
    Shows what would happen without creating policies.

.EXAMPLE
    .\6. Intune Compliance Policy.ps1
    .\6. Intune Compliance Policy.ps1 -WhatIf
#>

param(
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# ==========================================
# Resolve target group
# ==========================================
Write-Host "`n--- Resolving Target Group ---" -ForegroundColor Cyan
$targetGroup = Get-MgGroup -Filter "displayName eq 'DG-Intune-Users'" -ErrorAction SilentlyContinue

if (-not $targetGroup) {
    Write-Host "[ERROR] DG-Intune-Users not found. Run Script 1 first." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] DG-Intune-Users -> $($targetGroup.Id)" -ForegroundColor Green
Write-Host "--------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Check existing policies
# ==========================================
Write-Host "--- Checking Existing Policies ---" -ForegroundColor Cyan
$existingPolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" `
    -ErrorAction SilentlyContinue

$existingNames = @()
if ($existingPolicies.value) {
    $existingNames = $existingPolicies.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingNames.Count) existing compliance policies" -ForegroundColor Gray
Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define compliance policies
# ==========================================

$compliancePolicies = @(
    # --- WINDOWS COMPLIANCE ---
    @{
        Name   = "COMP-WIN-01 - Windows Security Baseline"
        Config = @{
            displayName = "COMP-WIN-01 - Windows Security Baseline"
            description = "Requires BitLocker, Secure Boot, Antivirus, and minimum OS version for all Windows devices"
            "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
            scheduledActionsForRule = @(
                @{
                    ruleName = "PasswordRequired"
                    scheduledActionConfigurations = @(
                        @{
                            actionType         = "block"
                            gracePeriodHours   = 0
                            notificationTemplateId = ""
                        }
                    )
                }
            )
            passwordRequired               = $true
            passwordMinimumLength           = 8
            passwordRequiredType            = "alphanumeric"
            requireHealthyDeviceReport     = $true
            osMinimumVersion                = "10.0.19041"
            osMaximumVersion                = $null
            mobileOsMinimumVersion          = $null
            mobileOsMaximumVersion          = $null
            earlyAntiMalwareEnforcement     = $true
            bitLockerEnabled                = $true
            secureBootEnabled               = $true
            codeIntegrityEnabled            = $true
            storageRequireEncryption        = $true
            activeFirewallRequired          = $true
            defenderEnabled                 = $true
            defenderVersion                 = $null
            statusDisabled                  = $false
            configurationProfileNotificationPayloads = @()
        }
        Assignments = @($targetGroup.Id)
    },

    # --- WINDOWS PASSWORD POLICY ---
    @{
        Name   = "COMP-WIN-02 - Windows Password Policy"
        Config = @{
            displayName = "COMP-WIN-02 - Windows Password Policy"
            description = "Enforces strong password requirements for Windows devices"
            "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
            passwordRequired               = $true
            passwordMinimumLength           = 12
            passwordRequiredType            = "alphanumeric"
            passwordMinutesOfInactivityBeforeLock = 15
            passwordExpirationDays          = 90
            passwordPreviousPasswordBlockCount = 5
            earlyAntiMalwareEnforcement     = $false
            bitLockerEnabled                = $false
            secureBootEnabled               = $false
            codeIntegrityEnabled            = $false
            storageRequireEncryption        = $false
            activeFirewallRequired          = $false
            defenderEnabled                 = $false
            statusDisabled                  = $false
            configurationProfileNotificationPayloads = @()
        }
        Assignments = @($targetGroup.Id)
    },

    # --- MOBILE COMPLIANCE (Android) ---
    @{
        Name   = "COMP-MOB-01 - Android Compliance"
        Config = @{
            displayName = "COMP-MOB-01 - Android Compliance"
            description = "Minimum OS, jailbreak detection, and encryption for Android devices"
            "@odata.type" = "#microsoft.graph.androidCompliancePolicy"
            passwordRequired               = $true
            passwordMinimumLength           = 6
            passwordRequiredType            = "numeric"
            securityPreventInstallAppsFromUnknownSources = $true
            securityDisableUsbDebugging    = $false
            storageRequireEncryption        = $true
            osMinimumVersion                = "10.0"
            osMaximumVersion                = $null
            minAndroidSecurityPatchLevel    = "2024-01-01"
            safetyNetDeviceVerification     = $true
            safetyNetAttestationType        = "deviceIntegrity"
            googlePlayProtectEnabled        = $true
            securityRequireUpToDateSecurityProviders = $true
            securityRequireCompanyPortalAppInstaller  = $false
            statusDisabled                  = $false
            scheduledActionsForRule = @(
                @{
                    ruleName = "PasswordRequired"
                    scheduledActionConfigurations = @(
                        @{
                            actionType         = "block"
                            gracePeriodHours   = 24
                            notificationTemplateId = ""
                        }
                    )
                }
            )
            configurationProfileNotificationPayloads = @()
        }
        Assignments = @($targetGroup.Id)
    },

    # --- MOBILE COMPLIANCE (iOS) ---
    @{
        Name   = "COMP-MOB-02 - iOS Compliance"
        Config = @{
            displayName = "COMP-MOB-02 - iOS Compliance"
            description = "Minimum OS, jailbreak detection, and encryption for iOS/iPadOS devices"
            "@odata.type" = "#microsoft.graph.iosCompliancePolicy"
            passcodeRequired               = $true
            passcodeMinimumLength           = 6
            passcodeRequiredType            = "numeric"
            passcodeMinutesOfInactivityBeforeLock = 15
            passcodeExpirationDays          = 90
            passcodePreviousPasscodeBlockCount = 5
            securityBlockJailbreakedDevices  = $true
            osMinimumVersion                = "16.0"
            osMaximumVersion                = $null
            healthAttestationSupported      = $true
            activationLockBlockWhenSupervised = $true
            managedEmailProfileRequired     = $false
            statusDisabled                  = $false
            scheduledActionsForRule = @(
                @{
                    ruleName = "PasswordRequired"
                    scheduledActionConfigurations = @(
                        @{
                            actionType         = "block"
                            gracePeriodHours   = 24
                            notificationTemplateId = ""
                        }
                    )
                }
            )
            configurationProfileNotificationPayloads = @()
        }
        Assignments = @($targetGroup.Id)
    }
)

# ==========================================
# Create policies
# ==========================================
$created = 0
$skipped = 0
$failed  = 0

foreach ($policy in $compliancePolicies) {

    $policyName = $policy.Name
    $policyConfig = $policy.Config

    try {
        # Skip if already exists
        if ($existingNames -contains $policyName) {
            Write-Host "[SKIP] Already exists: $policyName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create compliance policy: $policyName" -ForegroundColor Magenta
            continue
        }

        # Create the compliance policy
        $body = $policyConfig | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[CREATED] $policyName (ID: $($result.id))" -ForegroundColor Green

        # Assign to group
        try {
            $assignmentBody = @{
                assignments = @(
                    @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId       = $policy.Assignments[0]
                        }
                    }
                )
            } | ConvertTo-Json -Depth 10

            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$($result.id)/assign" `
                -Body $assignmentBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "  [ASSIGNED] -> DG-Intune-Users" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  [WARN] Policy created but assignment failed - $($_.Exception.Message)" -ForegroundColor Yellow
        }

        $created++
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
        Write-Host "[FAIL] $policyName - $errorMsg" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Intune Compliance Policy Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $created" -ForegroundColor Green
Write-Host "  Skipped : $skipped" -ForegroundColor Yellow
Write-Host "  Failed  : $failed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode    : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "----------------------------------------`n" -ForegroundColor Cyan

if ($created -gt 0 -and -not $WhatIf) {
    Write-Host "[INFO] Policies created. Devices will be evaluated on next check-in." -ForegroundColor Green
    Write-Host "       Monitor compliance status in Intune Admin Center > Devices > Compliance." -ForegroundColor Gray
}
