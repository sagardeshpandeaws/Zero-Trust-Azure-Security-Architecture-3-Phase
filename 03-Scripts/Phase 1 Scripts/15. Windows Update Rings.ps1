#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates Windows Update rings for staged OS update deployment.

.DESCRIPTION
    Deploys Windows Update for Business configurations with three update rings:

    1. Pilot Ring (IT Group)
       - IT team devices receive updates first for validation
       - Feature update deferral: 3 days
       - Quality update deferral: 1 day
       - Short restart grace period for faster rollback testing

    2. Production Ring (All Users)
       - All remaining users receive updates after IT validation
       - Feature update deferral: 7 days
       - Quality update deferral: 5 days
       - Restart grace period: 3 days
       - Deadline: 7 days with forced restart

    3. Emergency Ring (Critical Updates)
       - Critical zero-day patches with 0 deferral
       - Immediate automatic install and restart
       - Deadline: 1 day with forced compliance

    Rings are assigned to dynamic groups from Script 1:
    - Pilot    -> DG-IT
    - Production -> DG-Intune-Users
    - Emergency  -> SG-Admins-Protected

    Prerequisites:
    - Microsoft Intune license
    - DeviceManagementConfiguration.ReadWrite.All permission
    - Dynamic groups created (Script 1)

.PARAMETER WhatIf
    Shows what would happen without creating update rings.

.EXAMPLE
    .\15. Windows Update Rings.ps1
    .\15. Windows Update Rings.ps1 -WhatIf
#>

param(
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All", "Group.Read.All"

# ==========================================
# Resolve target groups
# ==========================================
Write-Host "`n--- Resolving Target Groups ---" -ForegroundColor Cyan

$groupMap = @(
    @{ Name = "DG-IT";                Role = "Pilot Ring";       Var = "pilotGroup" }
    @{ Name = "DG-Intune-Users";      Role = "Production Ring";  Var = "prodGroup" }
    @{ Name = "SG-Admins-Protected";  Role = "Emergency Ring";   Var = "emergencyGroup" }
)

$resolvedGroups = @{}

foreach ($entry in $groupMap) {
    $group = Get-MgGroup -Filter "displayName eq '$($entry.Name)'" -ErrorAction SilentlyContinue
    if ($group) {
        $resolvedGroups[$entry.Var] = $group.Id
        Write-Host "  [OK] $($entry.Name) -> $($group.Id) ($($entry.Role))" -ForegroundColor Green
    }
    else {
        Write-Host "  [ERROR] $($entry.Name) not found. Run Script 1 first." -ForegroundColor Red
        exit 1
    }
}
Write-Host "--------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Check existing update configurations
# ==========================================
Write-Host "--- Checking Existing Configurations ---" -ForegroundColor Cyan
$existingConfigs = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsUpdateForBusinessConfigurations" `
    -ErrorAction SilentlyContinue

$existingNames = @()
if ($existingConfigs.value) {
    $existingNames = $existingConfigs.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingNames.Count) existing Windows Update configurations" -ForegroundColor Gray
Write-Host "----------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define update ring configurations
# ==========================================

$updateRings = @(
    # --- RING 1: Pilot (IT Group) ---
    # Minimal deferral, early validation, short grace period
    @{
        Name   = "UPD-PILOT-01 - Windows Update Pilot Ring (IT)"
        Config = @{
            "@odata.type"   = "#microsoft.graph.windowsUpdateForBusinessConfiguration"
            displayName     = "UPD-PILOT-01 - Windows Update Pilot Ring (IT)"
            description     = "Pilot ring for IT team - minimal deferral (3 day feature, 1 day quality) with short restart grace period for early validation"
            roleScopeTagIds = @()

            # Feature updates - short deferral for early testing
            featureUpdatesDeferralPeriodInDays        = 3
            featureUpdatesScheduleImpactType          = "notConfigured"

            # Quality updates - minimal deferral
            qualityUpdatesDeferralPeriodInDays        = 1

            # Microsoft Update
            microsoftUpdateServiceEnabled             = $true

            # Delivery optimization
            deliveryOptimizationMode                  = "httpOnly"

            # Prerelease - stable channel only
            prereleaseType                            = "none"

            # Automatic updates
            automaticInstallUpdatesEnabled            = $true
            automaticUpdateMode                       = "autoInstallAndRebootAtScheduledTime"

            # Active hours - IT working hours
            activeHoursStart                          = "06:00:00.0000000"
            activeHoursEnd                            = "18:00:00.0000000"

            # Scheduled install - daily at noon
            scheduledInstallDay                       = "everyday"
            scheduledInstallTime                      = "12:00:00.0000000"

            # Restart - short grace period, quick deadline
            automaticRestartTimeSlot                  = "12:00"
            automaticRestartWarningDisplayInMinutes   = 15
            restartGracePeriodInDays                  = 1
            restartDeadlineInDays                     = 2

            # Notifications
            updateNotificationLevel                   = "enable"

            # Post-update behavior
            automaticRestartClockDisabled             = $false
        }
        Assignments = @($resolvedGroups.pilotGroup)
    },

    # --- RING 2: Production (All Users) ---
    # Balanced deferral for stability, longer grace period
    @{
        Name   = "UPD-PROD-01 - Windows Update Production Ring"
        Config = @{
            "@odata.type"   = "#microsoft.graph.windowsUpdateForBusinessConfiguration"
            displayName     = "UPD-PROD-01 - Windows Update Production Ring"
            description     = "Production ring for all users - 7 day feature deferral, 5 day quality deferral, 3 day grace period, 7 day forced deadline"
            roleScopeTagIds = @()

            # Feature updates - 1 week deferral
            featureUpdatesDeferralPeriodInDays        = 7
            featureUpdatesScheduleImpactType          = "notConfigured"

            # Quality updates - 5 day deferral
            qualityUpdatesDeferralPeriodInDays        = 5

            # Microsoft Update
            microsoftUpdateServiceEnabled             = $true

            # Delivery optimization
            deliveryOptimizationMode                  = "peeringEnabled"

            # Prerelease - stable channel only
            prereleaseType                            = "none"

            # Automatic updates
            automaticInstallUpdatesEnabled            = $true
            automaticUpdateMode                       = "autoInstallAndRebootAtScheduledTime"

            # Active hours - standard business hours
            activeHoursStart                          = "06:00:00.0000000"
            activeHoursEnd                            = "20:00:00.0000000"

            # Scheduled install - weekend morning (Saturday)
            scheduledInstallDay                       = "days"
            scheduledInstallTime                      = "03:00:00.0000000"

            # Restart - generous grace period, weekly deadline
            automaticRestartTimeSlot                  = "04:00"
            automaticRestartWarningDisplayInMinutes   = 60
            restartGracePeriodInDays                  = 3
            restartDeadlineInDays                     = 7

            # Notifications
            updateNotificationLevel                   = "enable"

            # Post-update behavior
            automaticRestartClockDisabled             = $false
        }
        Assignments = @($resolvedGroups.prodGroup)
    },

    # --- RING 3: Emergency (Critical Patches) ---
    # Zero deferral, immediate forced restart, aggressive compliance
    @{
        Name   = "UPD-EMRG-01 - Windows Update Emergency Ring"
        Config = @{
            "@odata.type"   = "#microsoft.graph.windowsUpdateForBusinessConfiguration"
            displayName     = "UPD-EMRG-01 - Windows Update Emergency Ring"
            description     = "Emergency ring for critical zero-day patches - 0 deferral, immediate install, 1 day forced deadline"
            roleScopeTagIds = @()

            # Feature updates - immediate (0 deferral)
            featureUpdatesDeferralPeriodInDays        = 0
            featureUpdatesScheduleImpactType          = "notConfigured"

            # Quality updates - immediate (0 deferral)
            qualityUpdatesDeferralPeriodInDays        = 0

            # Microsoft Update
            microsoftUpdateServiceEnabled             = $true

            # Delivery optimization
            deliveryOptimizationMode                  = "httpOnly"

            # Prerelease - stable channel only
            prereleaseType                            = "none"

            # Automatic updates - aggressive
            automaticInstallUpdatesEnabled            = $true
            automaticUpdateMode                       = "autoInstallAndReboot"

            # Active hours - broad coverage
            activeHoursStart                          = "08:00:00.0000000"
            activeHoursEnd                            = "18:00:00.0000000"

            # Scheduled install - daily at 2 AM
            scheduledInstallDay                       = "everyday"
            scheduledInstallTime                      = "02:00:00.0000000"

            # Restart - short grace, aggressive deadline
            automaticRestartTimeSlot                  = "02:00"
            automaticRestartWarningDisplayInMinutes   = 15
            restartGracePeriodInDays                  = 0
            restartDeadlineInDays                     = 1

            # Notifications
            updateNotificationLevel                   = "enable"

            # Post-update behavior
            automaticRestartClockDisabled             = $true
        }
        Assignments = @($resolvedGroups.emergencyGroup)
    }
)

# ==========================================
# Create update rings
# ==========================================
Write-Host "--- Creating Windows Update Rings ---" -ForegroundColor Cyan

$created = 0
$skipped = 0
$failed  = 0

foreach ($ring in $updateRings) {

    $ringName = $ring.Name
    $ringConfig = $ring.Config

    try {
        # Skip if already exists
        if ($existingNames -contains $ringName) {
            Write-Host "[SKIP] Already exists: $ringName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create update ring: $ringName" -ForegroundColor Magenta
            $created++
            continue
        }

        # Create the update configuration
        $body = $ringConfig | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsUpdateForBusinessConfigurations" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[CREATED] $ringName (ID: $($result.id))" -ForegroundColor Green

        # Assign to target group
        try {
            $targetGroupId = $ring.Assignments[0]

            $assignmentBody = @{
                assignments = @(
                    @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId       = $targetGroupId
                        }
                    }
                )
            } | ConvertTo-Json -Depth 10

            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsUpdateForBusinessConfigurations/$($result.id)/assign" `
                -Body $assignmentBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            $groupName = ($groupMap | Where-Object { $_.Var -eq ($resolvedGroups.Keys | Where-Object { $resolvedGroups[$_] -eq $targetGroupId }) }).Name
            Write-Host "  [ASSIGNED] -> $groupName" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  [WARN] Ring created but assignment failed - $($_.Exception.Message)" -ForegroundColor Yellow
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
        Write-Host "[FAIL] $ringName - $errorMsg" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Windows Update Ring Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $created" -ForegroundColor Green
Write-Host "  Skipped : $skipped" -ForegroundColor Yellow
Write-Host "  Failed  : $failed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode    : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "------------------------------------`n" -ForegroundColor Cyan

if ($created -gt 0 -and -not $WhatIf) {
    Write-Host "  Ring Configuration:" -ForegroundColor White
    Write-Host "    Pilot (IT)       : 3 day feature / 1 day quality / 1 day grace / 2 day deadline" -ForegroundColor Gray
    Write-Host "    Production       : 7 day feature / 5 day quality / 3 day grace / 7 day deadline" -ForegroundColor Gray
    Write-Host "    Emergency        : 0 deferral / immediate install / 0 day grace / 1 day deadline" -ForegroundColor Gray
    Write-Host ""
    Write-Host "[INFO] Rings created. Devices will receive update policies on next check-in." -ForegroundColor Green
    Write-Host "       Monitor in Intune Admin Center > Devices > Windows > Windows updates." -ForegroundColor Gray
}
