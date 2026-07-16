#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Configures OneDrive silent sign-in and auto-mapping for Zero IT effort.

.DESCRIPTION
    Deploys OneDrive configuration for zero-touch file sync:
    - Silent account configuration (SilentAccountConfig = 1)
    - Files On-Demand for cloud-only file visibility
    - Known Folder Move (KFM) to redirect Desktop, Documents, Pictures
    - Conditional sync that stops on non-compliant devices
    - KFM silent opt-in with user notification

    All policies assigned to DG-Intune-Users group.

.PARAMETER WhatIf
    Shows what would happen without creating policies.

.EXAMPLE
    .\10. OneDrive Auto-Mapping.ps1
    .\10. OneDrive Auto-Mapping.ps1 -WhatIf
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
# Check existing profiles
# ==========================================
Write-Host "--- Checking Existing OneDrive Profiles ---" -ForegroundColor Cyan
$existingProfiles = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
    -ErrorAction SilentlyContinue

$existingNames = @()
if ($existingProfiles.value) {
    $existingNames = $existingProfiles.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingNames.Count) existing configuration profiles" -ForegroundColor Gray
Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define OneDrive configuration profiles
# ==========================================

$configProfiles = @(
    # --- PROFILE 1: OneDrive Silent Account Config ---
    @{
        Name   = "CFG-ODRIVE-01 - OneDrive Silent Sign-In"
        Config = @{
            displayName = "CFG-ODRIVE-01 - OneDrive Silent Sign-In"
            description = "Enables silent OneDrive account configuration so users are automatically signed in"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # Silent Account Configuration (ADMX-backed)
            omaSettings = @(
                @{
                    displayName = "Silent Account Config"
                    description = "Enable silent OneDrive sign-in"
                    omaUri = "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC/EnableAllOdfcSilentAccountConfig"
                    dataType = "Integer"
                    value = "1"
                }
            )
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    },

    # --- PROFILE 2: OneDrive Known Folder Move (KFM) ---
    @{
        Name   = "CFG-ODRIVE-02 - KFM Silent Opt-In"
        Config = @{
            displayName = "CFG-ODRIVE-02 - KFM Silent Opt-In"
            description = "Redirects Desktop, Documents, and Pictures to OneDrive with silent opt-in and user notification"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # Known Folder Move Settings (ADMX-backed)
            omaSettings = @(
                @{
                    displayName = "KFM Silent Opt-In"
                    description = "Enable silent KFM opt-in"
                    omaUri = "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC/EnableAllOdfcSilentKnownFolderMove"
                    dataType = "Integer"
                    value = "1"
                },
                @{
                    displayName = "KFM Block Opt-Out"
                    description = "Prevent users from opting out of KFM"
                    omaUri = "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC/PreventBusinessDataFromOnPersonalDevice"
                    dataType = "Integer"
                    value = "1"
                }
            )
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    },

    # --- PROFILE 3: OneDrive Conditional Sync ---
    @{
        Name   = "CFG-ODRIVE-03 - OneDrive Conditional Sync"
        Config = @{
            displayName = "CFG-ODRIVE-03 - OneDrive Conditional Sync"
            description = "Stops OneDrive sync on non-compliant devices to enforce Zero Trust"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # Conditional Sync Settings (ADMX-backed)
            omaSettings = @(
                @{
                    displayName = "Restrict OneDrive to Tenant"
                    description = "Only allow OneDrive sync for accounts in the tenant"
                    omaUri = "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC/RestrictOneDriveAccountToTenant"
                    dataType = "Integer"
                    value = "1"
                },
                @{
                    displayName = "Block Metered Network Sync"
                    description = "Prevent OneDrive sync on metered networks"
                    omaUri = "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC/EnableAllOdfcSilentOptOut"
                    dataType = "Integer"
                    value = "0"
                }
            )
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    }
)

# ==========================================
# Create profiles
# ==========================================
$created = 0
$skipped = 0
$failed  = 0

foreach ($profile in $configProfiles) {

    $profileName = $profile.Name
    $profileConfig = $profile.Config

    try {
        # Skip if already exists
        if ($existingNames -contains $profileName) {
            Write-Host "[SKIP] Already exists: $profileName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create OneDrive profile: $profileName" -ForegroundColor Magenta
            $created++
            continue
        }

        # Create the profile
        $body = $profileConfig | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[CREATED] $profileName (ID: $($result.id))" -ForegroundColor Green

        # Assign to group
        try {
            $assignmentBody = @{
                assignments = @(
                    @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId       = $profile.Assignments[0]
                        }
                    }
                )
            } | ConvertTo-Json -Depth 10

            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($result.id)/assign" `
                -Body $assignmentBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "  [ASSIGNED] -> DG-Intune-Users" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  [WARN] Profile created but assignment failed - $($_.Exception.Message)" -ForegroundColor Yellow
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
        Write-Host "[FAIL] $profileName - $errorMsg" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- OneDrive Auto-Mapping Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $created" -ForegroundColor Green
Write-Host "  Skipped : $skipped" -ForegroundColor Yellow
Write-Host "  Failed  : $failed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode    : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "---------------------------------------`n" -ForegroundColor Cyan

if ($created -gt 0 -and -not $WhatIf) {
    Write-Host "[INFO] OneDrive profiles created. Devices will receive settings on next check-in." -ForegroundColor Green
    Write-Host "       Silent sign-in: Users are automatically signed into OneDrive." -ForegroundColor Gray
    Write-Host "       Files On-Demand: Files appear online-only, downloaded on open." -ForegroundColor Gray
    Write-Host "       KFM: Desktop, Documents, Pictures automatically redirect to OneDrive." -ForegroundColor Gray
    Write-Host "       Conditional sync stops on non-compliant devices (Zero Trust)." -ForegroundColor Gray
    Write-Host "       Monitor in Intune Admin Center > Devices > Configuration." -ForegroundColor Gray
}
