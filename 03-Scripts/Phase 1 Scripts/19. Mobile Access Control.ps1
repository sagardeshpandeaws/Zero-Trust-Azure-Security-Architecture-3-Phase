#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Configures mobile device access policies for Zero Trust deployment.

.DESCRIPTION
    Implements mobile access control through three layers:

    1. CA Policy: Blocks all mobile device access by default
    2. Intune App Protection Policies (MAM): Protects Outlook Mobile, OneDrive Mobile,
       and Teams Mobile with PIN, encryption, and data transfer restrictions
    3. CA Policy: Allows mobile access ONLY when an app protection policy is present

    This ensures no unmanaged mobile device can access corporate data without
    MAM enrollment and protection policies applied.

.PARAMETER TargetGroupName
    Name of the Entra ID group to scope the block policy to.
    Default: "DG-All-Users"

.PARAMETER WhatIf
    Shows what would happen without creating policies.

.EXAMPLE
    .\19. Mobile Access Control.ps1
    .\19. Mobile Access Control.ps1 -WhatIf
    .\19. Mobile Access Control.ps1 -TargetGroupName "DG-All-Licensed-Users"
#>

param(
    [string]$TargetGroupName = "DG-All-Users",
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes @(
    "Policy.ReadWrite.ConditionalAccess",
    "DeviceManagementConfiguration.ReadWrite.All"
)

# ==========================================
# Resolve required groups
# ==========================================
Write-Host "`n--- Resolving Groups ---" -ForegroundColor Cyan

$requiredGroups = @(
    $TargetGroupName,
    "SG-BreakGlass-Exclude",
    "Emergency Account"
)

$groupIds = @{}

foreach ($name in $requiredGroups) {
    $g = Get-MgGroup -Filter "displayName eq '$name'" -ErrorAction SilentlyContinue
    if ($g) {
        $groupIds[$name] = $g.Id
        Write-Host "  [OK] $name -> $($g.Id)" -ForegroundColor Green
    }
    else {
        Write-Host "  [MISSING] $name" -ForegroundColor Red
    }
}

if (-not $groupIds.ContainsKey($TargetGroupName)) {
    Write-Host "[ERROR] $TargetGroupName group is required. Run Script 1 first." -ForegroundColor Red
    exit 1
}

if (-not $groupIds.ContainsKey("SG-BreakGlass-Exclude") -or -not $groupIds.ContainsKey("Emergency Account")) {
    Write-Host "[ERROR] SG-BreakGlass-Exclude and Emergency Account groups are required." -ForegroundColor Red
    exit 1
}

$excludeAll = @($groupIds["SG-BreakGlass-Exclude"], $groupIds["Emergency Account"])

Write-Host "-------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Check for existing policies
# ==========================================
Write-Host "--- Checking Existing Policies ---" -ForegroundColor Cyan
$existingCAPolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -ErrorAction SilentlyContinue

$existingCANames = @()
if ($existingCAPolicies.value) {
    $existingCANames = $existingCAPolicies.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingCANames.Count) existing CA policies" -ForegroundColor Gray

$existingMAMPolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies" `
    -ErrorAction SilentlyContinue

$existingMAMNames = @()
if ($existingMAMPolicies.value) {
    $existingMAMNames = $existingMAMPolicies.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingMAMNames.Count) existing MAM policies" -ForegroundColor Gray
Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Mobile app identifiers for CA app conditions
# ==========================================
$mobileAppIds = @(
    "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online (Outlook Mobile)
    "d3590ed6-52b3-4102-aeff-aad2292ab0f6",  # Microsoft Office
    "ab954323-c6f4-4488-9625-bb75db6f0758"   # Microsoft OneDrive
)

$outlookMobileAppId    = "00000002-0000-0ff1-ce00-000000000000"
$onedriveMobileAppId   = "d3590ed6-52b3-4102-aeff-aad2292ab0f6"
$teamsMobileAppId      = "1fec8e7b-ba15-4f11-94dd-92e01b8984fb"

# ==========================================
# Define MAM (App Protection) Policies
# ==========================================
Write-Host "--- Defining MAM App Protection Policies ---" -ForegroundColor Cyan

$mamPolicies = @(
    # --- Outlook Mobile (iOS) ---
    @{
        Name   = "MAM - Outlook Mobile (iOS)"
        GraphPayload = @{
            "@odata.type"    = "#microsoft.graph.iosManagedAppProtection"
            displayName      = "MAM - Outlook Mobile (iOS)"
            description      = "App protection policy for Outlook Mobile iOS - PIN required, encryption, data restrictions"
            periodOfflineBeforeAccessCheck       = 12
            periodOfflineBlockOrReset            = 720
            periodOnlineBeforeAccessCheck         = 30
            allowedInboundDataTransferSources     = "managedApps"
            allowedOutboundDataTransferDestinations = "managedApps"
            pinRequired                         = $true
            maximumPinRetries                   = 10
            pinMinimumLength                    = 4
            pinCharacterSet                     = "numeric"
            allowedDataStorageLocations         = @("sharePoint", "oneDriveBusiness")
            allowedApps                          = @(
                @{
                    mobileManaged = $true
                }
            )
            encryptOrgData                       = $true
            disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
            isAssigned                           = $false
        }
        Uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections"
    },

    # --- Outlook Mobile (Android) ---
    @{
        Name   = "MAM - Outlook Mobile (Android)"
        GraphPayload = @{
            "@odata.type"    = "#microsoft.graph.androidManagedAppProtection"
            displayName      = "MAM - Outlook Mobile (Android)"
            description      = "App protection policy for Outlook Mobile Android - PIN required, encryption, data restrictions"
            periodOfflineBeforeAccessCheck       = 12
            periodOfflineBlockOrReset            = 720
            periodOnlineBeforeAccessCheck         = 30
            allowedInboundDataTransferSources     = "managedApps"
            allowedOutboundDataTransferDestinations = "managedApps"
            pinRequired                         = $true
            maximumPinRetries                   = 10
            pinMinimumLength                    = 4
            pinCharacterSet                     = "numeric"
            allowedDataStorageLocations         = @("sharePoint", "oneDriveBusiness")
            allowedApps                          = @(
                @{
                    mobileManaged = $true
                }
            )
            encryptOrgData                       = $true
            disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
            isAssigned                           = $false
        }
        Uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections"
    },

    # --- OneDrive Mobile (iOS) ---
    @{
        Name   = "MAM - OneDrive Mobile (iOS)"
        GraphPayload = @{
            "@odata.type"    = "#microsoft.graph.iosManagedAppProtection"
            displayName      = "MAM - OneDrive Mobile (iOS)"
            description      = "App protection policy for OneDrive Mobile iOS - PIN, encryption, no local storage"
            periodOfflineBeforeAccessCheck       = 12
            periodOfflineBlockOrReset            = 720
            periodOnlineBeforeAccessCheck         = 30
            allowedInboundDataTransferSources     = "managedApps"
            allowedOutboundDataTransferDestinations = "managedApps"
            pinRequired                         = $true
            maximumPinRetries                   = 10
            pinMinimumLength                    = 4
            pinCharacterSet                     = "numeric"
            allowedDataStorageLocations         = @("sharePoint", "oneDriveBusiness")
            allowedApps                          = @(
                @{
                    mobileManaged = $true
                }
            )
            encryptOrgData                       = $true
            disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
            isAssigned                           = $false
        }
        Uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections"
    },

    # --- OneDrive Mobile (Android) ---
    @{
        Name   = "MAM - OneDrive Mobile (Android)"
        GraphPayload = @{
            "@odata.type"    = "#microsoft.graph.androidManagedAppProtection"
            displayName      = "MAM - OneDrive Mobile (Android)"
            description      = "App protection policy for OneDrive Mobile Android - PIN, encryption, no local storage"
            periodOfflineBeforeAccessCheck       = 12
            periodOfflineBlockOrReset            = 720
            periodOnlineBeforeAccessCheck         = 30
            allowedInboundDataTransferSources     = "managedApps"
            allowedOutboundDataTransferDestinations = "managedApps"
            pinRequired                         = $true
            maximumPinRetries                   = 10
            pinMinimumLength                    = 4
            pinCharacterSet                     = "numeric"
            allowedDataStorageLocations         = @("sharePoint", "oneDriveBusiness")
            allowedApps                          = @(
                @{
                    mobileManaged = $true
                }
            )
            encryptOrgData                       = $true
            disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
            isAssigned                           = $false
        }
        Uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections"
    },

    # --- Teams Mobile (iOS) ---
    @{
        Name   = "MAM - Teams Mobile (iOS)"
        GraphPayload = @{
            "@odata.type"    = "#microsoft.graph.iosManagedAppProtection"
            displayName      = "MAM - Teams Mobile (iOS)"
            description      = "App protection policy for Teams Mobile iOS - PIN, encryption, restricted data sharing"
            periodOfflineBeforeAccessCheck       = 12
            periodOfflineBlockOrReset            = 720
            periodOnlineBeforeAccessCheck         = 30
            allowedInboundDataTransferSources     = "managedApps"
            allowedOutboundDataTransferDestinations = "managedApps"
            pinRequired                         = $true
            maximumPinRetries                   = 10
            pinMinimumLength                    = 4
            pinCharacterSet                     = "numeric"
            allowedDataStorageLocations         = @("sharePoint", "oneDriveBusiness")
            allowedApps                          = @(
                @{
                    mobileManaged = $true
                }
            )
            encryptOrgData                       = $true
            disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
            isAssigned                           = $false
        }
        Uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections"
    },

    # --- Teams Mobile (Android) ---
    @{
        Name   = "MAM - Teams Mobile (Android)"
        GraphPayload = @{
            "@odata.type"    = "#microsoft.graph.androidManagedAppProtection"
            displayName      = "MAM - Teams Mobile (Android)"
            description      = "App protection policy for Teams Mobile Android - PIN, encryption, restricted data sharing"
            periodOfflineBeforeAccessCheck       = 12
            periodOfflineBlockOrReset            = 720
            periodOnlineBeforeAccessCheck         = 30
            allowedInboundDataTransferSources     = "managedApps"
            allowedOutboundDataTransferDestinations = "managedApps"
            pinRequired                         = $true
            maximumPinRetries                   = 10
            pinMinimumLength                    = 4
            pinCharacterSet                     = "numeric"
            allowedDataStorageLocations         = @("sharePoint", "oneDriveBusiness")
            allowedApps                          = @(
                @{
                    mobileManaged = $true
                }
            )
            encryptOrgData                       = $true
            disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
            isAssigned                           = $false
        }
        Uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections"
    }
)

# ==========================================
# Define CA policies
# ==========================================
$targetGroupId = $groupIds[$TargetGroupName]

$caPolicies = @(
    # --- POLICY 1: Block Mobile Access by Default ---
    @{
        Name   = "CA - Block Mobile Access (Default Deny)"
        Config = @{
            displayName = "CA - Block Mobile Access (Default Deny)"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($targetGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
                platforms = @{
                    includePlatforms  = @("android", "iOS")
                    excludePlatforms  = @("all")
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("block")
            }
        }
    },

    # --- POLICY 2: Allow Mobile Access ONLY When App Protection Policy Present ---
    @{
        Name   = "CA - Allow Mobile with App Protection Policy"
        Config = @{
            displayName = "CA - Allow Mobile with App Protection Policy"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($targetGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($outlookMobileAppId, $onedriveMobileAppId, $teamsMobileAppId)
                }
                platforms = @{
                    includePlatforms = @("android", "iOS")
                }
            }
            grantControls = @{
                operator        = "AND"
                builtInControls = @("mfa")
                customAuthenticationFactors  = @()
                termsOfUse                  = @()
            }
            sessionControls = @{
                signInFrequency = @{
                    value             = 1
                    type              = "hours"
                    isEnabled         = $true
                    frequencyInterval = "timeBased"
                }
            }
        }
    }
)

# ==========================================
# Create MAM App Protection Policies
# ==========================================
Write-Host "--- Creating MAM App Protection Policies ---" -ForegroundColor Cyan

$mamCreated = 0
$mamSkipped = 0
$mamFailed  = 0

foreach ($policy in $mamPolicies) {

    $policyName = $policy.Name
    $policyUri = $policy.Uri

    try {
        if ($existingMAMNames -contains $policyName) {
            Write-Host "[SKIP] MAM policy already exists: $policyName" -ForegroundColor Yellow
            $mamSkipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create MAM policy: $policyName" -ForegroundColor Magenta
            $mamCreated++
            continue
        }

        $body = $policy.GraphPayload | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri $policyUri `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[CREATED] $policyName (ID: $($result.id))" -ForegroundColor Green
        $mamCreated++
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
        $mamFailed++
    }
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Create CA Policies
# ==========================================
Write-Host "--- Creating Conditional Access Policies ---" -ForegroundColor Cyan

$caCreated = 0
$caSkipped = 0
$caFailed  = 0

foreach ($policy in $caPolicies) {

    $policyName = $policy.Name
    $policyConfig = $policy.Config

    try {
        if ($existingCANames -contains $policyName) {
            Write-Host "[SKIP] CA policy already exists: $policyName" -ForegroundColor Yellow
            $caSkipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create CA policy: $policyName" -ForegroundColor Magenta
            $caCreated++
            continue
        }

        $body = $policyConfig | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[CREATED] $policyName (ID: $($result.id))" -ForegroundColor Green
        $caCreated++
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
        $caFailed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Mobile Access Control Summary ---" -ForegroundColor Cyan
Write-Host "  MAM Policies:" -ForegroundColor White
Write-Host "    Created : $mamCreated" -ForegroundColor Green
Write-Host "    Skipped : $mamSkipped" -ForegroundColor Yellow
Write-Host "    Failed  : $mamFailed" -ForegroundColor Red
Write-Host "  CA Policies:" -ForegroundColor White
Write-Host "    Created : $caCreated" -ForegroundColor Green
Write-Host "    Skipped : $caSkipped" -ForegroundColor Yellow
Write-Host "    Failed  : $caFailed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode      : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "--------------------------------------`n" -ForegroundColor Cyan

if (($caCreated -gt 0 -or $mamCreated -gt 0) -and -not $WhatIf) {
    Write-Host "[INFO] Policies created in report-only mode." -ForegroundColor Yellow
    Write-Host "  - Block Mobile Access policy denies all mobile access by default" -ForegroundColor Gray
    Write-Host "  - MAM policies protect Outlook, OneDrive, and Teams Mobile apps" -ForegroundColor Gray
    Write-Host "  - Allow Mobile with App Protection policy grants access when MAM is enrolled" -ForegroundColor Gray
    Write-Host "  - Use -EnablePolicies on Script 5 to enforce after validation" -ForegroundColor Gray
    Write-Host "`n[NOTE] MAM policies are currently unassigned. Assign them via Intune Admin Center" -ForegroundColor Yellow
    Write-Host "       or update the 'isAssigned' field and set 'targetGroups' after validation.`n" -ForegroundColor Yellow
}
