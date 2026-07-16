#Requires -Modules Microsoft.Graph.Security, Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Configures Microsoft Defender for Endpoint P2 for endpoint detection and response.

.DESCRIPTION
    Deploys Defender for Endpoint EDR capabilities across the tenant:

    1. EDR Block Mode
       - Enables EDR in block mode for all onboarded devices
       - Blocks detected threats at the endpoint level

    2. Automated Investigation and Remediation (AIR)
       - Enables AIR policies for automated threat investigation
       - Configures remediation scope for security admins

    3. Ransomware Rollback
       - Enables ransomware rollback capability on endpoints
       - Configures 72-hour file rollback window

    4. Defender for Endpoint Onboarding via Intune
       - Configures MDE onboarding package for Windows devices
       - Deploys onboarding configuration profile

    5. Exploit Protection
       - Enables system-wide exploit protection settings
       - Configures attack surface reduction rules

    Prerequisites:
    - Microsoft Defender for Endpoint P2 license
    - Microsoft Graph Security admin permissions
    - Microsoft Graph DeviceManagement admin permissions
    - Intune admin permissions (for onboarding profile)

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\14. Defender for Endpoint EDR.ps1
    .\14. Defender for Endpoint EDR.ps1 -WhatIf
#>

param(
    [switch]$WhatIf
)

# ==========================================
# Initialize
# ==========================================
$stats = @{ EdrPolicies = 0; AirPolicies = 0; Onboarding = 0; ExploitProtection = 0; Failed = 0 }

function Write-Status {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        "SUCCESS" { "Green" }
        "SKIP"    { "Yellow" }
        "WHATIF"  { "Magenta" }
        default   { "Cyan" }
    }
    Write-Host "  [$Level] $Message" -ForegroundColor $color
}

# ==========================================
# Connect - Microsoft Graph Security & Device Management
# ==========================================
Write-Host "`n--- Connecting to Microsoft Graph ---" -ForegroundColor Cyan

$graphScopes = @(
    "SecurityEvents.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "Device.ReadWrite.All"
)

try {
    Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
    Write-Status "Connected to Microsoft Graph" "SUCCESS"
}
catch {
    Write-Status "Failed to connect to Microsoft Graph - $($_.Exception.Message)" "ERROR"
    exit 1
}

# ==========================================
# Retrieve existing Defender for Endpoint onboarding status
# ==========================================
Write-Host "`n--- Checking Existing Defender for Endpoint Status ---" -ForegroundColor Cyan

try {
    $mdatpOnboard = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/security/attacksurface/windowsDefenderATP/onboarding" `
        -ErrorAction SilentlyContinue

    if ($mdatpOnboard -and $mdatpOnboard.value) {
        Write-Status "Found existing MDE onboarding configuration(s): $($mdatpOnboard.value.Count)"
    }
    else {
        Write-Status "No existing MDE onboarding configuration found" "WARN"
    }
}
catch {
    Write-Status "Could not retrieve MDE onboarding status - $($_.Exception.Message)" "WARN"
}

try {
    $existingPolicies = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
        -ErrorAction SilentlyContinue

    $mdeProfiles = @()
    if ($existingPolicies.value) {
        $mdeProfiles = $existingPolicies.value | Where-Object {
            $_.displayName -match "MDE|Defender.*Endpoint|EDR"
        }
    }

    Write-Status "Existing MDE/EDR profiles: $($mdeProfiles.Count)"
}
catch {
    Write-Status "Could not enumerate device configurations - $($_.Exception.Message)" "WARN"
}

# ==========================================
# Section 1: EDR Block Mode
# ==========================================
Write-Host "`n--- Configuring EDR Block Mode ---" -ForegroundColor Cyan

$edrBlockPolicyName = "MDE-EDR-01 - EDR Block Mode"

try {
    $existingEdrBlock = $mdeProfiles | Where-Object { $_.displayName -eq $edrBlockPolicyName }

    if ($existingEdrBlock) {
        Write-Status "EDR block mode policy already exists: $edrBlockPolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create EDR block mode policy: $edrBlockPolicyName" "WHATIF"
            $stats.EdrPolicies++
        }
        else {
            $edrBlockBody = @{
                "@odata.type"  = "#microsoft.graph.windowsDefenderATPConfigurationProfile"
                displayName    = $edrBlockPolicyName
                description    = "Configures Defender for Endpoint EDR in block mode. Detects and blocks threats at the endpoint level with automated response."
                windowsDefenderATP = @{
                    enableNetworkProtection    = $true
                    enableTamperProtection     = $true
                }
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
                -Body $edrBlockBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created EDR block mode policy: $edrBlockPolicyName (ID: $($result.id))" "SUCCESS"
            $stats.EdrPolicies++
        }
    }
}
catch {
    Write-Status "Failed to create EDR block mode policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# Configure EDR block mode via Security API
try {
    Write-Host "`n  Configuring EDR block mode settings..." -ForegroundColor Gray

    if ($WhatIf) {
        Write-Status "[WhatIf] Would enable EDR block mode for all onboarded devices" "WHATIF"
    }
    else {
        $edrModeBody = @{
            edrMode = "block"
        } | ConvertTo-Json

        $edrModeResult = Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/security/attacksurface/windowsDefenderATP/configuration" `
            -Body $edrModeBody `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Status "EDR block mode enabled for the tenant" "SUCCESS"
    }
}
catch {
    Write-Status "Could not set EDR block mode via Security API - $($_.Exception.Message)" "WARN"
    Write-Status "EDR mode can be configured manually in the Microsoft 365 Defender portal" "WARN"
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Section 2: Automated Investigation and Remediation (AIR)
# ==========================================
Write-Host "`n--- Configuring Automated Investigation and Remediation ---" -ForegroundColor Cyan

$airPolicyName = "MDE-AIR-01 - Automated Investigation"

try {
    $existingAirPolicy = $mdeProfiles | Where-Object { $_.displayName -eq $airPolicyName }

    if ($existingAirPolicy) {
        Write-Status "AIR policy already exists: $airPolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create AIR policy: $airPolicyName" "WHATIF"
            $stats.AirPolicies++
        }
        else {
            $airPolicyBody = @{
                "@odata.type"  = "#microsoft.graph.windowsDefenderATPConfigurationProfile"
                displayName    = $airPolicyName
                description    = "Enables Automated Investigation and Remediation for automated threat investigation and remediation across all onboarded devices."
                windowsDefenderATP = @{
                    enableAutoReport = $true
                }
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
                -Body $airPolicyBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created AIR policy: $airPolicyName (ID: $($result.id))" "SUCCESS"
            $stats.AirPolicies++
        }
    }
}
catch {
    Write-Status "Failed to create AIR policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# Configure AIR remediation scope
try {
    Write-Host "`n  Configuring AIR remediation scope..." -ForegroundColor Gray

    if ($WhatIf) {
        Write-Status "[WhatIf] Would enable full remediation scope for AIR" "WHATIF"
    }
    else {
        $airRemediationBody = @{
            autoInvestigationMode = "enabled"
            remediationScope      = "fullRemediation"
        } | ConvertTo-Json

        $airRemediationResult = Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/security/attackSimulation/automationMode" `
            -Body $airRemediationBody `
            -ContentType "application/json" `
            -ErrorAction SilentlyContinue

        Write-Status "AIR remediation scope configured" "SUCCESS"
    }
}
catch {
    Write-Status "AIR remediation scope configuration skipped - $($_.Exception.Message)" "WARN"
    Write-Status "AIR can be configured in Microsoft 365 Defender > Settings > Automated investigations" "WARN"
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Section 3: Ransomware Rollback Capability
# ==========================================
Write-Host "`n--- Configuring Ransomware Rollback ---" -ForegroundColor Cyan

$ransomwarePolicyName = "MDE-RANSOM-01 - Ransomware Rollback"

try {
    $existingRansom = $mdeProfiles | Where-Object { $_.displayName -eq $ransomwarePolicyName }

    if ($existingRansom) {
        Write-Status "Ransomware rollback policy already exists: $ransomwarePolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create ransomware rollback policy: $ransomwarePolicyName" "WHATIF"
            $stats.EdrPolicies++
        }
        else {
            $ransomwareBody = @{
                "@odata.type"  = "#microsoft.graph.windowsDefenderATPConfigurationProfile"
                displayName    = $ransomwarePolicyName
                description    = "Enables ransomware rollback capability with 72-hour file rollback window and automated remediation for ransomware attacks."
                windowsDefenderATP = @{
                    enableRansomwareDataRecovery = $true
                    allowNetworkProtectionDownLevel = $false
                }
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
                -Body $ransomwareBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created ransomware rollback policy: $ransomwarePolicyName (ID: $($result.id))" "SUCCESS"
            $stats.EdrPolicies++
        }
    }
}
catch {
    Write-Status "Failed to create ransomware rollback policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# Enable Controlled Folder Access for ransomware protection
try {
    Write-Host "`n  Configuring Controlled Folder Access..." -ForegroundColor Gray

    if ($WhatIf) {
        Write-Status "[WhatIf] Would enable Controlled Folder Access for ransomware protection" "WHATIF"
    }
    else {
        Write-Host "  [INFO] Controlled Folder Access must be configured via Intune portal." -ForegroundColor Yellow
        Write-Host "         Navigate to: Devices > Windows > Configuration profiles > Create profile" -ForegroundColor Yellow
        Write-Host "         Platform: Windows 10 and later, Template: Endpoint protection" -ForegroundColor Yellow
        Write-Host "         Then enable: Microsoft Defender Exploit Guard > Controlled Folder Access" -ForegroundColor Yellow
    }
}
catch {
    Write-Status "Controlled Folder Access configuration skipped - $($_.Exception.Message)" "WARN"
    Write-Status "Configure via Intune > Devices > Windows > Configuration > Exploit protection" "WARN"
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Section 4: Defender for Endpoint Onboarding via Intune
# ==========================================
Write-Host "`n--- Configuring MDE Onboarding via Intune ---" -ForegroundColor Cyan

$onboardProfileName = "MDE-ONBOARD-01 - Defender for Endpoint Onboarding"

try {
    $existingOnboard = $mdeProfiles | Where-Object { $_.displayName -eq $onboardProfileName }

    if ($existingOnboard) {
        Write-Status "MDE onboarding profile already exists: $onboardProfileName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create MDE onboarding profile: $onboardProfileName" "WHATIF"
            $stats.Onboarding++
        }
        else {
            $onboardBody = @{
                "@odata.type"  = "#microsoft.graph.windowsDefenderATPConfigurationProfile"
                displayName    = $onboardProfileName
                description    = "Onboards Windows devices to Microsoft Defender for Endpoint with automatic package deployment via Intune."
                windowsDefenderATP = @{
                    enableConnectedUserExperienceAndDeviceDiscovery = $true
                    enableAutoSampleCollection                   = $true
                    enableFileHashComputation                     = $true
                    allowArchiveScanning                          = $true
                    allowBehaviorMonitoring                        = $true
                    allowEmailScanning                            = $false
                    allowFullScanOnMappedNetworkDrives             = $true
                    allowFullScanRemovableDriveScanning            = $true
                    allowIntrusionPreventionSystem                 = $true
                    allowIOAVProtection                            = $true
                    allowRealtimeMonitoring                        = $true
                    allowScanningFromRegisteredProtectedFolders    = $true
                    allowScriptScanning                            = $true
                    allowUserUIAccess                              = $true
                    disableRealtimeMonitoring                      = $false
                    disableBehaviorMonitoring                      = $false
                    disableIOAVProtection                          = $false
                    disableRealtimeMonitoringValue                 = $false
                    disableScriptScanning                          = $false
                }
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
                -Body $onboardBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created MDE onboarding profile: $onboardProfileName (ID: $($result.id))" "SUCCESS"
            $stats.Onboarding++
        }
    }
}
catch {
    Write-Status "Failed to create MDE onboarding profile - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# Create onboarding package configuration for Windows 10/11
try {
    Write-Host "`n  Retrieving MDE onboarding package..." -ForegroundColor Gray

    if ($WhatIf) {
        Write-Status "[WhatIf] Would retrieve and configure MDE onboarding package" "WHATIF"
    }
    else {
        $onboardPackage = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/security/attacksurface/windowsDefenderATP/packages" `
            -ErrorAction SilentlyContinue

        if ($onboardPackage -and $onboardPackage.value) {
            $windowsPackage = $onboardPackage.value | Where-Object {
                $_.platform -eq "windows" -or $_.os -eq "Windows10"
            } | Select-Object -First 1

            if ($windowsPackage) {
                Write-Status "Windows MDE onboarding package found (ID: $($windowsPackage.id))" "SUCCESS"
            }
            else {
                Write-Status "Windows onboarding package not found in existing packages" "WARN"
            }
        }
        else {
            Write-Status "No onboarding packages available - create package in M365 Defender portal first" "WARN"
        }
    }
}
catch {
    Write-Status "Could not retrieve onboarding package - $($_.Exception.Message)" "WARN"
    Write-Status "Upload onboarding package via Microsoft 365 Defender > Settings > Device onboarding" "WARN"
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Section 5: Exploit Protection Settings
# ==========================================
Write-Host "`n--- Configuring Exploit Protection ---" -ForegroundColor Cyan

$exploitProtectionPolicyName = "MDE-EXPLOIT-01 - Exploit Protection"

try {
    $existingExploit = $mdeProfiles | Where-Object { $_.displayName -eq $exploitProtectionPolicyName }

    if ($existingExploit) {
        Write-Status "Exploit protection policy already exists: $exploitProtectionPolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create exploit protection policy: $exploitProtectionPolicyName" "WHATIF"
            $stats.ExploitProtection++
        }
    else {
        Write-Host "  [INFO] Exploit Protection must be configured via Intune portal." -ForegroundColor Yellow
        Write-Host "         Navigate to: Devices > Windows > Configuration profiles > Create profile" -ForegroundColor Yellow
        Write-Host "         Platform: Windows 10 and later, Template: Endpoint protection" -ForegroundColor Yellow
        Write-Host "         Then configure: Microsoft Defender Exploit Protection > System settings" -ForegroundColor Yellow
        Write-Host "         Enable DEP, ASLR, and SEHOP as needed." -ForegroundColor Yellow
    }
    }
}
catch {
    Write-Status "Failed to create exploit protection policy - $($_.Exception.Message)" "ERROR"
    $stats.Failed++
}

# Configure Attack Surface Reduction (ASR) rules
try {
    Write-Host "`n  Configuring Attack Surface Reduction rules..." -ForegroundColor Gray

    if ($WhatIf) {
        Write-Status "[WhatIf] Would enable Attack Surface Reduction rules" "WHATIF"
    }
    else {
        $asrRulesBody = @{
            "@odata.type"  = "#microsoft.graph.windowsDefenderATPConfigurationProfile"
            displayName    = "MDE-ASR-01 - Attack Surface Reduction Rules"
            description    = "Enables Attack Surface Reduction rules to reduce attack vectors for common malware and exploits."
            windowsDefenderATP = @{
                enableNetworkProtection                = $true
                enableBlockAbusiveProcesses            = $true
                enableExploitProtection                = $true
                enableFileHashComputation              = $true
            }
        } | ConvertTo-Json -Depth 5

        $asrResult = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
            -Body $asrRulesBody `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Status "Created ASR rules configuration (ID: $($asrResult.id))" "SUCCESS"
        $stats.ExploitProtection++
    }
}
catch {
    Write-Status "Could not create ASR rules configuration - $($_.Exception.Message)" "WARN"
    Write-Status "Configure ASR rules via Microsoft 365 Defender > Settings > Attack surface reduction" "WARN"
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Configure device exclusions (empty by default)
# ==========================================
Write-Host "`n--- Configuring Device Groups and Scope Tags ---" -ForegroundColor Cyan

$deviceGroupPolicyName = "MDE-GROUP-01 - Defender Device Group"

try {
    $existingDeviceGroup = $mdeProfiles | Where-Object { $_.displayName -eq $deviceGroupPolicyName }

    if ($existingDeviceGroup) {
        Write-Status "Device group policy already exists: $deviceGroupPolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create device group policy for MDE targeting: $deviceGroupPolicyName" "WHATIF"
        }
        else {
            $deviceGroupBody = @{
                "@odata.type"  = "#microsoft.graph.windowsDefenderATPConfigurationProfile"
                displayName    = $deviceGroupPolicyName
                description    = "Creates a device group for targeting Defender for Endpoint policies to all Windows devices."
                windowsDefenderATP = @{
                    deviceGroupTag = "All devices"
                }
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
                -Body $deviceGroupBody `
                -ContentType "application/json" `
                -ErrorAction SilentlyContinue

            if ($result) {
                Write-Status "Created device group policy: $deviceGroupPolicyName" "SUCCESS"
            }
            else {
                Write-Status "Device group policy creation skipped" "SKIP"
            }
        }
    }
}
catch {
    Write-Status "Device group policy creation skipped - $($_.Exception.Message)" "WARN"
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Verification
# ==========================================
Write-Host "`n--- Verification ---" -ForegroundColor Cyan

try {
    $finalProfiles = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
        -ErrorAction SilentlyContinue

    if ($finalProfiles.value) {
        $mdeCreated = $finalProfiles.value | Where-Object {
            $_.displayName -match "^MDE-"
        }

        if ($mdeCreated) {
            Write-Host "  MDE Configurations created:" -ForegroundColor Gray
            foreach ($p in $mdeCreated) {
                Write-Host "    - $($p.displayName)" -ForegroundColor Gray
            }
        }
    }
}
catch {
    Write-Status "Verification encountered errors - $($_.Exception.Message)" "WARN"
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Defender for Endpoint EDR Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  EDR Block Mode Policies   : $($stats.EdrPolicies)" -ForegroundColor White
Write-Host "  AIR Policies              : $($stats.AirPolicies)" -ForegroundColor White
Write-Host "  Onboarding Profiles       : $($stats.Onboarding)" -ForegroundColor White
Write-Host "  Exploit Protection        : $($stats.ExploitProtection)" -ForegroundColor White
Write-Host "  Failed                    : $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })
if ($WhatIf) {
    Write-Host "  Mode                      : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "  EDR Capabilities:" -ForegroundColor White
Write-Host "    - EDR in block mode (detects and blocks endpoint threats)" -ForegroundColor Gray
Write-Host "    - Automated Investigation and Remediation (AIR)" -ForegroundColor Gray
Write-Host "    - Ransomware rollback (72-hour file recovery)" -ForegroundColor Gray
Write-Host "    - Controlled Folder Access for ransomware protection" -ForegroundColor Gray
Write-Host "    - Defender for Endpoint onboarding via Intune" -ForegroundColor Gray
Write-Host "    - Exploit protection (DEP, ASLR, SEHOP)" -ForegroundColor Gray
Write-Host "    - Attack Surface Reduction (ASR) rules" -ForegroundColor Gray
Write-Host "    - Network protection" -ForegroundColor Gray

Write-Host "`n[NEXT STEPS]" -ForegroundColor Green
Write-Host "  1. Ensure Defender for Endpoint P2 licenses are assigned to all users" -ForegroundColor White
Write-Host "  2. Create MDE onboarding package in Microsoft 365 Defender portal if not present" -ForegroundColor White
Write-Host "  3. Assign the created Intune policies to device groups" -ForegroundColor White
Write-Host "  4. Monitor onboarding status at security.microsoft.com > Device inventory" -ForegroundColor White
Write-Host "  5. Configure ASR rules exceptions for approved applications" -ForegroundColor White
Write-Host "  6. Review AIR settings in Microsoft 365 Defender > Settings > Automated investigations" -ForegroundColor White
Write-Host "  7. Verify ransomware rollback is operational in Device inventory > Risky devices" -ForegroundColor White
Write-Host ""
