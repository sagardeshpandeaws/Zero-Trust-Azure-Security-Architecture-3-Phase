#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates Windows Autopilot deployment profiles for Zero Touch device provisioning.

.DESCRIPTION
    Automates Autopilot setup:
    - Creates Autopilot deployment profile (User-driven, Azure AD Join)
    - Skips privacy settings and EULA
    - Creates device group for Autopilot assignment
    - Optionally imports device hashes from CSV

    Prerequisites:
    - Run Script 1 first (creates dynamic groups)
    - Devices must have hardware hash collected via Get-WindowsAutopilotInfo.ps1

.PARAMETER DeviceHashCsvPath
    Path to CSV containing device hardware hashes. Format: SerialNumber,GroupTag,ProductKey

.PARAMETER WhatIf
    Shows what would happen without creating profiles.

.EXAMPLE
    .\8. Autopilot Profile Assignment.ps1
    .\8. Autopilot Profile Assignment.ps1 -DeviceHashCsvPath "C:\hashes.csv"
    .\8. Autopilot Profile Assignment.ps1 -WhatIf
#>

param(
    [string]$DeviceHashCsvPath,
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All", "Group.ReadWrite.All"

# ==========================================
# Check existing profiles
# ==========================================
Write-Host "`n--- Checking Existing Autopilot Profiles ---" -ForegroundColor Cyan
$existingProfiles = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles" `
    -ErrorAction SilentlyContinue

$existingNames = @()
if ($existingProfiles.value) {
    $existingNames = $existingProfiles.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingNames.Count) existing Autopilot profiles" -ForegroundColor Gray
Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Create Autopilot Device Group (static)
# ==========================================
Write-Host "--- Resolving Autopilot Device Group ---" -ForegroundColor Cyan
$autopilotGroupName = "SG-Autopilot-Devices"
$autopilotGroup = Get-MgGroup -Filter "displayName eq '$autopilotGroupName'" -ErrorAction SilentlyContinue

if (-not $autopilotGroup) {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would create group: $autopilotGroupName" -ForegroundColor Magenta
    }
    else {
        try {
            $autopilotGroup = New-MgGroup `
                -DisplayName $autopilotGroupName `
                -Description "Static group for Autopilot-enrolled devices. Add devices manually or via hash import." `
                -MailEnabled:$false `
                -MailNickname $autopilotGroupName `
                -SecurityEnabled:$true `
                -GroupTypes @() `
                -ErrorAction Stop

            Write-Host "[CREATED] $autopilotGroupName (ID: $($autopilotGroup.Id))" -ForegroundColor Green
        }
        catch {
            Write-Host "[FAIL] Could not create $autopilotGroupName - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "[OK] $autopilotGroupName already exists (ID: $($autopilotGroup.Id))" -ForegroundColor Green
}
Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Create Autopilot Deployment Profile
# ==========================================
$profileName = "AP-USER-DRIVEN-01 - Zero Touch Deployment"

Write-Host "--- Creating Autopilot Profile ---" -ForegroundColor Cyan

$autopilotProfile = $null
try {
    if ($existingNames -contains $profileName) {
        Write-Host "[SKIP] Profile already exists: $profileName" -ForegroundColor Yellow
        $autopilotProfile = $existingProfiles.value | Where-Object { $_.displayName -eq $profileName } | Select-Object -First 1
    }
    else {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would create Autopilot profile: $profileName" -ForegroundColor Magenta
        }
        else {
            $profileConfig = @{
                displayName = $profileName
                description = "User-driven Azure AD Join profile for Zero Touch deployment. Skips EULA and privacy settings."
                "@odata.type" = "#microsoft.graph.windowsAutopilotDeploymentProfile"
                deploymentType = "userDriven"
                joinType = "azureADJoined"
                outOfBoxExperienceSetting = @{
                    hidePrivacySettings = $true
                    hideEULA = $true
                    hideKeyboardSelectionPage = $false
                    userType = "standard"
                    deviceUsageType = "shared"
                }
                enrollmentStatusScreenDetails = $null
                extractHardwareHash = $true
                hwHashImported = $false
                locale = "os-default"
                managementServiceAppId = ""
                roleScopeTagIds = @()
            }

            $body = $profileConfig | ConvertTo-Json -Depth 10

            $autopilotProfile = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "[CREATED] $profileName (ID: $($autopilotProfile.id))" -ForegroundColor Green
        }
    }

    # Assign profile to device group
    if ($autopilotProfile -and $autopilotGroup -and -not $WhatIf) {
        try {
            $assignmentBody = @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $autopilotGroup.Id
                }
            } | ConvertTo-Json -Depth 10

            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles/$($autopilotProfile.id)/assign" `
                -Body $assignmentBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "  [ASSIGNED] -> $autopilotGroupName" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  [WARN] Profile created but assignment failed - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
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
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Import Device Hashes (if CSV provided)
# ==========================================
if ($DeviceHashCsvPath) {
    Write-Host "--- Importing Device Hardware Hashes ---" -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $DeviceHashCsvPath)) {
        Write-Host "[ERROR] Hash CSV not found: $DeviceHashCsvPath" -ForegroundColor Red
    }
    else {
        $devices = Import-Csv -Path $DeviceHashCsvPath
        Write-Host "  Loaded $($devices.Count) device(s) from CSV" -ForegroundColor Gray

        $imported = 0
        $importFailed = 0

        foreach ($device in $devices) {
            try {
                if (-not $device.serialNumber -or -not $device.hardwareIdentifier) {
                    Write-Host "[SKIP] Missing serial or hash for device" -ForegroundColor Yellow
                    $importFailed++
                    continue
                }

                if ($WhatIf) {
                    Write-Host "[WhatIf] Would import: $($device.serialNumber)" -ForegroundColor Magenta
                    $imported++
                    continue
                }

                $importBody = @{
                    serialNumber     = $device.serialNumber
                    hardwareIdentifier = $device.hardwareIdentifier
                    groupTag         = if ($device.groupTag) { $device.groupTag } else { "" }
                    productKey       = if ($device.productKey) { $device.productKey } else { "" }
                } | ConvertTo-Json

                Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities" `
                    -Body $importBody `
                    -ContentType "application/json" `
                    -ErrorAction Stop

                Write-Host "  [IMPORTED] $($device.serialNumber)" -ForegroundColor Green
                $imported++

                # Add to Autopilot group
                if ($autopilotGroup -and -not $WhatIf) {
                    try {
                        $deviceEntry = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities?`$filter=serialNumber eq '$($device.serialNumber)'" `
                            -ErrorAction Stop

                        if ($deviceEntry.value -and $deviceEntry.value.Count -gt 0) {
                            $deviceId = $deviceEntry.value[0].id

                            # Add to group via member
                            Invoke-MgGraphRequest -Method POST `
                                -Uri "https://graph.microsoft.com/v1.0/groups/$($autopilotGroup.Id)/members/`$ref" `
                                -Body @{
                                    "@odata.id" = "https://graph.microsoft.com/v1.0/devices/$deviceId"
                                } | ConvertTo-Json | ConvertFrom-Json `
                                -ErrorAction Stop

                            Write-Host "    [GROUPED] Added to $autopilotGroupName" -ForegroundColor Cyan
                        }
                    }
                    catch {
                        Write-Host "    [WARN] Device imported but group add failed - $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Host "  [FAIL] $($device.serialNumber) - $($_.Exception.Message)" -ForegroundColor Red
                $importFailed++
            }
        }

        Write-Host "`n  Import Summary: $imported imported, $importFailed failed" -ForegroundColor White
    }
    Write-Host "-------------------------------------------`n" -ForegroundColor Cyan
}
else {
    Write-Host "--- Device Hash Import ---" -ForegroundColor Cyan
    Write-Host "  No CSV provided. To import devices, run:" -ForegroundColor Gray
    Write-Host '  .\8. Autopilot Profile Assignment.txt -DeviceHashCsvPath "C:\path\to\hashes.csv"' -ForegroundColor Gray
    Write-Host "-------------------------------------------`n" -ForegroundColor Cyan
}

# ==========================================
# Final Summary
# ==========================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Autopilot Setup Summary" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Profile    : $profileName" -ForegroundColor White
Write-Host "  Group      : $autopilotGroupName" -ForegroundColor White
Write-Host "  Join Type  : Azure AD Joined (User-Driven)" -ForegroundColor White
Write-Host "  EULA       : Skipped" -ForegroundColor White
Write-Host "  Privacy    : Skipped" -ForegroundColor White
if ($WhatIf) {
    Write-Host "  Mode       : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "============================================`n" -ForegroundColor Cyan

Write-Host "[NEXT STEPS]" -ForegroundColor Green
Write-Host "  1. Collect hardware hashes on new devices:" -ForegroundColor White
Write-Host '     Install-Script Get-WindowsAutopilotInfo' -ForegroundColor Gray
Write-Host '     Get-WindowsAutopilotInfo.ps1 -OutputFile AutoPilotHWID.csv' -ForegroundColor Gray
Write-Host "  2. Import hashes:" -ForegroundColor White
Write-Host '     .\8. Autopilot Profile Assignment.txt -DeviceHashCsvPath "AutoPilotHWID.csv"' -ForegroundColor Gray
Write-Host "  3. Device boots -> Autopilot enrolls -> Compliance/Config applied -> Access granted" -ForegroundColor White
Write-Host ""
