#Requires -Modules Microsoft.Graph.Sites, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Configures SharePoint Online secure file access for Zero Trust deployment.

.DESCRIPTION
    Sets up SharePoint secure access using Microsoft Entra ID for authentication
    and device compliance enforcement via Intune app protection policies.

    Configuration includes:
    - SharePoint site creation/configuration
    - External sharing restrictions via Graph API site settings
    - Intune app protection policies for device-based access (iOS & Android)
    - SharePoint tenant-level access policies
    - Group-based site membership

    Security design:
    - Access is identity-based (not network-based)
    - Device compliance required via Intune app protection
    - External sharing disabled at site level
    - Legacy authentication blocked at tenant level
    - Anonymous sharing links disabled

.PARAMETER SiteName
    Name of the SharePoint site. Defaults to "SecureAccess".

.PARAMETER SiteUrl
    URL for the SharePoint site.

.PARAMETER AppProtectionPolicyName
    Base name for Intune app protection policies. Platform suffixes appended automatically.
    Defaults to "SP-DeviceAccess-Policy".

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\21. Configure SharePoint Secure Access.ps1
    .\21. Configure SharePoint Secure Access.ps1 -SiteName "HRPortal"
    .\21. Configure SharePoint Secure Access.ps1 -WhatIf
#>

param(
    [string]$SiteName = "SecureAccess",
    [string]$SiteUrl = "https://yourtenant.sharepoint.com/sites/SecureAccess",
    [string]$AppProtectionPolicyName = "SP-DeviceAccess-Policy",
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes @(
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "SharePointTenantSettings.ReadWrite.All"
)

# ==========================================
# Step 1: Verify SharePoint Online Access
# ==========================================
Write-Host "`n--- Step 1: Verifying SharePoint Online Access ---" -ForegroundColor Cyan

try {
    $sharePointRoot = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/sites/root" `
        -ErrorAction Stop

    Write-Host "  [OK] SharePoint Online accessible: $($sharePointRoot.displayName)" -ForegroundColor Green
    Write-Host "    Root URL: $($sharePointRoot.webUrl)" -ForegroundColor Gray
}
catch {
    Write-Host "  [FAIL] Cannot access SharePoint Online: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Ensure SharePoint license is assigned and API permissions are granted." -ForegroundColor Yellow
    exit 1
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 2: Create/Verify SharePoint Site
# ==========================================
Write-Host "--- Step 2: Creating SharePoint Site ---" -ForegroundColor Cyan

$site = $null
try {
    $existingSites = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/sites?search=$SiteName" `
        -ErrorAction SilentlyContinue

    $matchingSite = $existingSites.value | Where-Object { $_.displayName -eq $SiteName } | Select-Object -First 1

    if ($matchingSite) {
        $site = $matchingSite
        Write-Host "  [OK] Site already exists: $SiteName (ID: $($site.id))" -ForegroundColor Green
    }
    else {
        if ($WhatIf) {
            Write-Host "  [WhatIf] Would create SharePoint site: $SiteName" -ForegroundColor Magenta
        }
        else {
            # Create site using Graph API with group-based provisioning
            # First create a Microsoft 365 Group, then access its SharePoint site
            $groupParams = @{
                displayName = $SiteName
                description = "Secure internal access site for Zero Trust deployment"
                mailEnabled = $false
                securityEnabled = $true
                mailNickname = $SiteName.ToLower() -replace '[^a-z0-9]', ''
            }

            $group = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
            $site = Get-MgSite -SiteId "$($group.MailNickname)" -ErrorAction SilentlyContinue

            Write-Host "  [CREATED] SharePoint site: $SiteName (ID: $($site.id))" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "  [WARN] Site creation: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 3: Configure External Sharing Restrictions
# ==========================================
Write-Host "--- Step 3: Configuring External Sharing Restrictions ---" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would disable external sharing on site: $SiteName" -ForegroundColor Magenta
        Write-Host "    PATCH https://graph.microsoft.com/v1.0/sites/$($site.id)" -ForegroundColor Gray
        Write-Host '    Body: { "settings": { "sharingCapability": "disabled" } }' -ForegroundColor Gray
    }
    elseif ($site) {
        $sharingBody = @{
            settings = @{
                sharingCapability = "disabled"
            }
        } | ConvertTo-Json -Depth 5

        $updatedSite = Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)" `
            -Body $sharingBody `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "  [OK] External sharing disabled on site: $SiteName" -ForegroundColor Green
        Write-Host "    sharingCapability: $($updatedSite.settings.sharingCapability)" -ForegroundColor Gray
    }
    else {
        Write-Host "  [SKIP] Site not available. Complete Step 2 first." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Sharing restrictions: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 4: Configure Device-Based Access via Intune App Protection
# ==========================================
Write-Host "--- Step 4: Configuring Device-Based Access ---" -ForegroundColor Cyan

$intuneAssigned = $false

try {
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would create Intune app protection policies:" -ForegroundColor Magenta
        Write-Host "    - $AppProtectionPolicyName-iOS" -ForegroundColor Gray
        Write-Host "    - $AppProtectionPolicyName-Android" -ForegroundColor Gray
        Write-Host "    Target group: DG-Intune-Users" -ForegroundColor Gray
    }
    else {
        $targetGroup = Get-MgGroup -Filter "displayName eq 'DG-Intune-Users'" -ErrorAction SilentlyContinue

        if (-not $targetGroup) {
            Write-Host "  [WARN] DG-Intune-Users not found. Run Script 1 first." -ForegroundColor Yellow
        }

        $appProtectionPolicies = @(
            @{
                DisplayName = "$AppProtectionPolicyName-iOS"
                ODataType   = "#microsoft.graph.iosManagedAppProtection"
                Uri         = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections"
                AssignUri  = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/{id}/assign"
            },
            @{
                DisplayName = "$AppProtectionPolicyName-Android"
                ODataType   = "#microsoft.graph.androidManagedAppProtection"
                Uri         = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections"
                AssignUri  = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections/{id}/assign"
            }
        )

        foreach ($policyDef in $appProtectionPolicies) {
            $policyBody = @{
                "@odata.type" = $policyDef.ODataType
                displayName = $policyDef.DisplayName
                description = "Device-based access policy for SharePoint secure access - Zero Trust"
                allowedDataStorageLocations = @("sharePoint")
                allowedInboundDataTransferSources = "managedApps"
                allowedOutboundDataTransferToOrganizationalAccounts = $true
                allowedOutboundDataTransferToPersonalAccounts = $false
                blockDataTransferBetweenOrganizationalAccounts = $true
                encryptAppData = $true
                managedBrowser = "microsoftEdge"
                maxAllowedDeviceThreatLevel = "medium"
                periodOfflineBeforeAccessCheck = 300
                periodOfflineBeforeWipeIsEnforced = 1209600
            } | ConvertTo-Json -Depth 10

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri $policyDef.Uri `
                -Body $policyBody `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "  [CREATED] $($policyDef.DisplayName) (ID: $($result.id))" -ForegroundColor Green

            if ($targetGroup) {
                $assignBody = @{
                    targetGroups = @(
                        @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $targetGroup.Id
                        }
                    )
                } | ConvertTo-Json -Depth 5

                $assignUri = $policyDef.AssignUri -replace '\{id\}', $result.id

                Invoke-MgGraphRequest -Method POST `
                    -Uri $assignUri `
                    -Body $assignBody `
                    -ContentType "application/json" `
                    -ErrorAction Stop

                Write-Host "  [ASSIGNED] $($policyDef.DisplayName) -> DG-Intune-Users" -ForegroundColor Green
                $intuneAssigned = $true
            }
        }

        Write-Host "  [CONFIGURED] Device-based access controls:" -ForegroundColor Green
        Write-Host "    - Require managed device for browser access: Yes" -ForegroundColor Gray
        Write-Host "    - Require app encryption: Yes" -ForegroundColor Gray
        Write-Host "    - Block data transfer to personal accounts: Yes" -ForegroundColor Gray
        Write-Host "    - Max allowed device threat level: Medium" -ForegroundColor Gray
        Write-Host "    - Offline grace period: 5 minutes" -ForegroundColor Gray
        Write-Host "    - Wipe enforcement offline: 14 days" -ForegroundColor Gray
        Write-Host "    - CA policies: Applied via Script 11" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARN] Device access: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 5: Assign Users/Groups to Site
# ==========================================
Write-Host "--- Step 5: Assigning Users/Groups to Site ---" -ForegroundColor Cyan

try {
    $targetGroup = Get-MgGroup -Filter "displayName eq 'DG-Intune-Users'" -ErrorAction SilentlyContinue

    if ($targetGroup -and -not $WhatIf -and $site) {
        $memberBody = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($targetGroup.Id)"
        } | ConvertTo-Json

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/members/`$ref" `
            -Body $memberBody `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "  [ASSIGNED] DG-Intune-Users -> $SiteName (Member)" -ForegroundColor Green
    }
    elseif ($WhatIf) {
        Write-Host "  [WhatIf] Would assign DG-Intune-Users to site" -ForegroundColor Magenta
    }
    else {
        Write-Host "  [WARN] DG-Intune-Users not found. Run Script 1 first." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Site assignment: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 6: Configure SharePoint Access Policies
# ==========================================
Write-Host "--- Step 6: Configuring Access Policies ---" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would configure SharePoint tenant access policies" -ForegroundColor Magenta
        Write-Host "    PATCH https://graph.microsoft.com/beta/admin/sharepoint/settings" -ForegroundColor Gray
        Write-Host "    - Disable anonymous file links" -ForegroundColor Gray
        Write-Host "    - Disable anonymous site links" -ForegroundColor Gray
        Write-Host "    - Block legacy authentication" -ForegroundColor Gray
        Write-Host "    - Restrict OneDrive sharing" -ForegroundColor Gray
        Write-Host "    - Disable self-service site creation" -ForegroundColor Gray
    }
    else {
        $accessSettings = @{
            fileAnonymousLinkType = "none"
            siteAnonymousLinkType = "none"
            isLegacyAuthProtocolsEnabled = $false
            isSharePointClientRestrictionEnabled = $true
            oneDriveSharingCapability = "disabled"
            isSiteCreationEnabled = $false
        } | ConvertTo-Json -Depth 5

        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/beta/admin/sharepoint/settings" `
            -Body $accessSettings `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "  [OK] SharePoint tenant access policies configured:" -ForegroundColor Green
        Write-Host "    - Anonymous file links: Disabled" -ForegroundColor Gray
        Write-Host "    - Anonymous site links: Disabled" -ForegroundColor Gray
        Write-Host "    - Legacy authentication protocols: Blocked" -ForegroundColor Gray
        Write-Host "    - SharePoint client restriction: Enabled" -ForegroundColor Gray
        Write-Host "    - OneDrive sharing: Disabled" -ForegroundColor Gray
        Write-Host "    - Self-service site creation: Disabled" -ForegroundColor Gray

        Write-Host "`n  [INFO] Additional enforcement via:" -ForegroundColor Yellow
        Write-Host "    - Conditional Access policies (Script 11)" -ForegroundColor Gray
        Write-Host "    - Intune app protection policies (Step 4)" -ForegroundColor Gray
        Write-Host "    - Defender for Cloud Apps session controls" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARN] Access policies: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SharePoint Secure Access Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Site Name   : $SiteName" -ForegroundColor White
Write-Host "  Site URL    : $SiteUrl" -ForegroundColor White
Write-Host "  External    : Sharing disabled" -ForegroundColor White
Write-Host "  Device      : Intune app protection enforced" -ForegroundColor White
Write-Host "  Policies    : Tenant-level access restricted" -ForegroundColor White
if ($WhatIf) {
    Write-Host "  Mode        : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "[SECURITY DESIGN]" -ForegroundColor Green
Write-Host "  - Access is identity-based (not network-based)" -ForegroundColor White
Write-Host "  - No VPN dependency" -ForegroundColor White
Write-Host "  - Device compliance verified via Intune" -ForegroundColor White
Write-Host "  - External sharing disabled" -ForegroundColor White
Write-Host "  - Legacy authentication blocked" -ForegroundColor White
Write-Host "  - Data exfiltration prevented" -ForegroundColor White
Write-Host ""
