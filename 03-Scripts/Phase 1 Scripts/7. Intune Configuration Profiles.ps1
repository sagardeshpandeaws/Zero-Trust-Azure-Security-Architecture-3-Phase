#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates Intune device configuration profiles for Zero Trust deployment.

.DESCRIPTION
    Deploys configuration profiles using Settings Catalog:
    - Windows Security Baseline (Defender, Firewall, USB)
    - Device Lock Screen & Password Policy
    - Device Restriction (Control Panel, USB, Bluetooth)

    Profiles are assigned to DG-Intune-Users group.

.PARAMETER WhatIf
    Shows what would happen without creating profiles.

.EXAMPLE
    .\7. Intune Configuration Profiles.ps1
    .\7. Intune Configuration Profiles.ps1 -WhatIf
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
Write-Host "--- Checking Existing Profiles ---" -ForegroundColor Cyan
$existingProfiles = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
    -ErrorAction SilentlyContinue

$existingNames = @()
if ($existingProfiles.value) {
    $existingNames = $existingProfiles.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingNames.Count) existing configuration profiles" -ForegroundColor Gray
Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define configuration profiles
# ==========================================

$configProfiles = @(
    # --- PROFILE 1: Windows Defender & Firewall ---
    @{
        Name   = "CFG-WIN-01 - Windows Defender & Firewall"
        Config = @{
            displayName = "CFG-WIN-01 - Windows Defender & Firewall"
            description = "Enables Windows Defender real-time protection, firewall, and disables USB storage"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # Defender Settings
            defenderCloudExtendedTimeout = 50
            defenderCloudBlockAtFirstHit = $true
            defenderDisallowedCloudServiceLevel = "high"
            defenderMonitorFileActivity = "allFiles"
            defenderScanMaxCpuPercentage = 50
            defenderScanType = "quickScan"
            defenderScheduleQuickScanTime = "12:00:00.0000000"
            defenderScanArchiveFiles = $true
            defenderScanDownloads = $true
            defenderScanIncomingMail = $true
            defenderScanMappedNetworkDrivesDuringFullScan = $false
            defenderScanRemovableDrivesDuringFullScan = $true
            defenderSignatureUpdateIntervalInHours = 8
            defenderPotentiallyUnwantedAppAction = "block"
            defenderExploitProtection = $true

            # ASR Rules - Granular
            defenderAttackSurfaceReductionRules = @{
                "@odata.type" = "#microsoft.graph.defenderAttackSurfaceReductionRules"
                defenderBlockCredentialStealingFromLsass = "block"                          # 56a863a9-875e-4185-98a7-b882c64b5ce5
                defenderBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "block" # 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84
                defenderBlockOfficeApplicationsFromCreatingExecutableContent = "block"       # d4f940ab-401b-4efc-aadc-ad5f3c50688a
                defenderBlockExecutionOfPotentiallyObfuscatedScripts = "block"               # 9e6c4e1f-7d60-472f-ba1a-a39ef669e95e
                defenderBlockWin32ApiCallsFromOfficeMacros = "block"                         # 01443614-cd74-433a-b99e-2ecdc07bfc25
                defenderBlockProcessCreationsFromWmiCommandLine = "block"                    # c1db55ab-c21a-4637-bb3f-a12568109d35
                defenderBlockOfficeChildProcessCreation = "block"                            # 26190899-1602-49e8-8b27-eb1d0a1ce869
                defenderBlockUntrustedUnsignedProcessesFromUsb = "block"                     # 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
                defenderBlockExecutableContentFromEmailClientAndWebmail = "block"            # e6db77e5-3df2-4cf1-b95a-636979351e5b
                defenderBlockAdobeReaderFromCreatingChildProcesses = "block"                 # be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
            }

            # Controlled Folder Access
            defenderControlledFolderAccessEnabled = $true

            # Block disk encryption on untrusted devices
            defenderBlockDiskEncryptionOnUntrustedDevices = $true

            # Firewall Settings
            firewallBlockStatefulFTP = $true
            firewallIdleTimeoutForSecurityAssociation = 300
            firewallPreventICMPsResponseFromPrivateNetworkInterface = $false
            firewallShellHarnessPayload = 1
            firewallConnectionSecurityRule = $true
            firewallIPSecExemptProtocol = 3
            firewallIPSecMergedMode = $true
            firewallCertificateRevocationListCheckMethod = 1
            firewallIPSecExemptARP = $true
            firewallIPSecExemptNeighborDiscoveryICMP = $true
            firewallIPSecExemptRouterDiscoveryICMP = $true
            firewallIPSecSecuredPacketExemption = $true
            firewallMergeRules = $true
            firewallLocalConnectionRules = $true
            firewallLocalAdminExceptions = $true
            firewallStealthModeBlocked = $true
            firewallUnicastResponsesToMulticastBroadcastBlocked = $true
            firewallSanctionedUncanonicalizedNamesBlocked = $true
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    },

    # --- PROFILE 2: USB & Peripheral Restrictions ---
    @{
        Name   = "CFG-WIN-02 - USB & Peripheral Restrictions"
        Config = @{
            displayName = "CFG-WIN-02 - USB & Peripheral Restrictions"
            description = "Restricts USB storage, Bluetooth, and removable media"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # USB Restrictions
            storageAllowUSBDrive = $false
            storageAllowBootUSB = $false
            storageAllowInstallFromUSB = $false

            # Bluetooth
            bluetoothAllowedServices = @()
            bluetoothPreventDeviceMetadataSubmission = $true
            bluetoothAllowedToTurnOn = $false

            # Clipboard
            clipboardSharingEnabled = $false

            # Screen Capture
            screenCaptureBlocked = $true
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    },

    # --- PROFILE 3: Device Lock & Password ---
    @{
        Name   = "CFG-WIN-03 - Device Lock & Password"
        Config = @{
            displayName = "CFG-WIN-03 - Device Lock & Password"
            description = "Lock screen timeout, password complexity, and biometric settings"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # Lock Screen
            lockScreenRequireUserInput = $true
            lockScreenAllowTimeoutConfiguration = $true
            lockScreenTimeoutInSeconds = 300
            lockScreenDisabledConfigured = $false

            # Password
            passwordEnabled = $true
            passwordMinimumLength = 12
            passwordRequiredType = "alphanumeric"
            passwordBlockSimple = $true
            passwordExpirationDays = 90
            passwordPreviousPasswordBlockCount = 5
            passwordHistoryViolationCount = 5
            passwordRequireWhenResumeFromIdle = $true
            passwordMinimumAgeInDays = 1
            passwordReuseValidationCount = 24

            # Biometric
            biometricsEnabled = $true
            prebootBiometricsRestricted = $true
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    },

    # --- PROFILE 4: Device Restrictions (Admin Panel, Lockdown) ---
    @{
        Name   = "CFG-WIN-04 - Device Restrictions"
        Config = @{
            displayName = "CFG-WIN-04 - Device Restrictions"
            description = "Disables Control Panel, restricts app installs, and enforces power settings"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # App Restrictions
            appInstallFromUnknownSourcesAllowed = $false
            appInstallFromRemovableMediaAllowed = $false

            # Control Panel & Settings
            controlPanelAccessFromStoreApps = $true
            settingsAppAccess = "blockAll"
            controlPanelAccess = "prohibitAccess"

            # Power Management
            powerEnabled = $true
            powerTimeoutOnBatteryInMinutes = 15
            powerTimeoutPluggedInMinutes = 30

            # Desktop
            desktopAppInstallationAllowed = $false
            windowsStoreAppAutoUpdate = "autoUpdateAtScheduledTimeWithNetwork"

            # Start Menu
            startMenuLayoutXml = $null

            # Edge Browser
            edgeHomeButtonConfigurationEnabled = $true
            edgeHomeButtonHidden = $false
            edgeNewTabPageType = "newTabPage"
        }
        Platform  = "windows10"
        Assignments = @($targetGroup.Id)
    },

    # --- PROFILE 5: BitLocker Encryption ---
    @{
        Name   = "CFG-WIN-05 - BitLocker Encryption"
        Config = @{
            displayName = "CFG-WIN-05 - BitLocker Encryption"
            description = "Enables BitLocker encryption on OS and fixed drives with TPM"
            "@odata.type" = "#microsoft.graph.windows10DeviceConfiguration"
            roleScopeTagIds = @()

            # BitLocker
            bitLockerEnableEncryption = $true
            bitLockerEncryptionMethod = "aes256"
            bitLockerRecoveryPasswordProtector = $true
            bitLockerRecoveryKeyProtector = $true
            bitLockerRecoveryOptions = "3"
            bitLockerRemovableDrivePolicy = @{
                bitLockerEnabled = $true
                encryptionMethod = "aes256"
                requireEncryptionForWriteAccess = $true
                blockCrossOrganizationWriteAccess = $true
            }
            bitLockerFixedDrivePolicy = @{
                bitLockerEnabled = $true
                encryptionMethod = "aes256"
                requireEncryptionForWriteAccess = $true
                recoveryKeyProtector = $true
                recoveryPasswordProtector = $true
            }
            bitLockerOSDrivePolicy = @{
                bitLockerEnabled = $true
                encryptionMethod = "aes256"
                requireEncryptionForWriteAccess = $true
                recoveryKeyProtector = $true
                recoveryPasswordProtector = $true
                prebootRecoveryInfoAndTools = $true
                startupAuthentication = $true
                startupKey = $true
                startupPin = $false
            }
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
            Write-Host "[WhatIf] Would create configuration profile: $profileName" -ForegroundColor Magenta
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
Write-Host "`n--- Intune Configuration Profile Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $created" -ForegroundColor Green
Write-Host "  Skipped : $skipped" -ForegroundColor Yellow
Write-Host "  Failed  : $failed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode    : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

if ($created -gt 0 -and -not $WhatIf) {
    Write-Host "[INFO] Profiles created. Devices will receive settings on next check-in." -ForegroundColor Green
    Write-Host "       Monitor in Intune Admin Center > Devices > Configuration." -ForegroundColor Gray
}
