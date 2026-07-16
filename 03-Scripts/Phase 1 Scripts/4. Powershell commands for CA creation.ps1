#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates Conditional Access policies for Zero Trust deployment.

.DESCRIPTION
    Creates 11 CA policies in report-only mode, then optionally enables them.
    All policies exclude break-glass and emergency accounts for safety.

    Policies:
    1. Require MFA for all users
    2. Block Legacy Authentication
    3. Require Compliant Device
    4. Sign-in Risk (Medium/High) -> MFA
    5. User Risk (High) -> Password Change
    6. Admin Protection (MFA + Compliant Device)
    7. Block Untrusted Locations
    8. Session Control (1-hour sign-in frequency)
    9. SharePoint Zero Trust Access (Compliant + Domain Joined)
    10. Admin FIDO2 Protection (FIDO2 for admin roles)
    11. Block Untrusted Countries (Allow only IN, US, UK)

.PARAMETER EnablePolicies
    If specified, enables all created policies after creation (removes report-only mode).

.PARAMETER WhatIf
    Shows what would happen without creating policies.

.EXAMPLE
    .\4. Powershell commands for CA creation.ps1
    .\4. Powershell commands for CA creation.ps1 -EnablePolicies
    .\4. Powershell commands for CA creation.ps1 -WhatIf
#>

param(
    [switch]$EnablePolicies,
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes @(
    "Policy.ReadWrite.ConditionalAccess",
    "IdentityRiskyUser.ReadWrite.All",
    "Directory.Read.All",
    "Group.Read.All"
)

# ==========================================
# Resolve required groups
# ==========================================
Write-Host "`n--- Resolving Groups ---" -ForegroundColor Cyan

$requiredGroups = @(
    "SG-BreakGlass-Exclude",
    "SG-Admins-Protected",
    "Emergency Account",
    "DG-CA-Compliant-Users"
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

# Validate critical groups exist
if (-not $groupIds.ContainsKey("SG-BreakGlass-Exclude") -or -not $groupIds.ContainsKey("Emergency Account")) {
    Write-Host "[ERROR] SG-BreakGlass-Exclude and Emergency Account groups are required. Create them first." -ForegroundColor Red
    exit 1
}

if (-not $groupIds.ContainsKey("DG-CA-Compliant-Users")) {
    Write-Host "[ERROR] DG-CA-Compliant-Users group is required. Run Script 1 first." -ForegroundColor Red
    exit 1
}

# ==========================================
# Build exclusion arrays
# ==========================================
$excludeAll    = @($groupIds["SG-BreakGlass-Exclude"], $groupIds["Emergency Account"])
$excludeAdmins = @($groupIds["SG-BreakGlass-Exclude"], $groupIds["Emergency Account"], $groupIds["SG-Admins-Protected"])

$caGroupId = $groupIds["DG-CA-Compliant-Users"]

Write-Host "-------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Resolve named locations for country-based policies
# ==========================================
Write-Host "`n--- Resolving Named Locations ---" -ForegroundColor Cyan

$targetCountryCodes = @("IN", "US", "UK")
$allowedCountryLocationIds = @()

try {
    $namedLocationResponse = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" `
        -ErrorAction Stop

    foreach ($loc in $namedLocationResponse.value) {
        if ($loc.'@odata.type' -eq '#microsoft.graph.countryNamedLocation') {
            foreach ($code in $targetCountryCodes) {
                if ($loc.countriesAndRegions -contains $code) {
                    $allowedCountryLocationIds += $loc.id
                    Write-Host "  [OK] $($loc.displayName) ($code) -> $($loc.id)" -ForegroundColor Green
                }
            }
        }
    }
}
catch {
    Write-Host "  [WARN] Could not retrieve named locations - $($_.Exception.Message)" -ForegroundColor Yellow
}

if ($allowedCountryLocationIds.Count -eq 0) {
    Write-Host "  [WARN] No named locations found for IN, US, UK. Policy 11 may not work as expected." -ForegroundColor Yellow
    Write-Host "         Create country-based named locations in: Azure AD > Security > Conditional Access > Named locations" -ForegroundColor Yellow
}
Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Check for existing policies
# ==========================================
Write-Host "--- Checking Existing Policies ---" -ForegroundColor Cyan
$existingPolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -ErrorAction SilentlyContinue

$existingNames = @()
if ($existingPolicies.value) {
    $existingNames = $existingPolicies.value | ForEach-Object { $_.displayName }
}
Write-Host "  Found $($existingNames.Count) existing policies" -ForegroundColor Gray
Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define all CA policies
# ==========================================

$policies = @(
    # --- POLICY 1: Require MFA ---
    @{
        Name   = "CA - Require MFA"
        Config = @{
            displayName = "CA - Require MFA"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAdmins
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("mfa")
            }
        }
    },

    # --- POLICY 2: Block Legacy Auth ---
    @{
        Name   = "CA - Block Legacy Auth"
        Config = @{
            displayName = "CA - Block Legacy Auth"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
                clientAppTypes = @("exchangeActiveSync", "other")
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("block")
            }
        }
    },

    # --- POLICY 3: Require Compliant Device ---
    @{
        Name   = "CA - Require Compliant Device"
        Config = @{
            displayName = "CA - Require Compliant Device"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator       = "AND"
                builtInControls = @("mfa", "compliantDevice")
            }
        }
    },

    # --- POLICY 4: Sign-in Risk ---
    @{
        Name   = "CA - Sign-in Risk"
        Config = @{
            displayName = "CA - Sign-in Risk"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                signInRiskLevels = @("medium", "high")
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("mfa")
            }
        }
    },

    # --- POLICY 5: User Risk ---
    @{
        Name   = "CA - User Risk"
        Config = @{
            displayName = "CA - User Risk"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                userRiskLevels = @("high")
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("passwordChange")
            }
        }
    },

    # --- POLICY 6: Admin Protection ---
    # Uses multiple admin roles instead of just Global Admin
    @{
        Name   = "CA - Admin Protection"
        Config = @{
            displayName = "CA - Admin Protection"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeRoles = @(
                        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                        "f28a1d5d-13e0-43c5-a4a5-5be8e1d38a41",  # User Administrator
                        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # Groups Administrator
                        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
                        "3a2c62ec-2f8f-42cb-89b5-91138b6d2ab8",  # Security Administrator
                        "194aeecb-9787-4d33-b003-4558e4c55be9"   # Helpdesk Administrator
                    )
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator       = "AND"
                builtInControls = @("mfa", "compliantDevice")
            }
        }
    },

    # --- POLICY 7: Block Untrusted Locations ---
    @{
        Name   = "CA - Block Untrusted Locations"
        Config = @{
            displayName = "CA - Block Untrusted Locations"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                locations = @{
                    includeLocations = @("All")
                    excludeLocations = @("Trusted")
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("block")
            }
        }
    },

    # --- POLICY 8: Session Control (1-hour sign-in frequency) ---
    @{
        Name   = "CA - Session Control"
        Config = @{
            displayName = "CA - Session Control"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
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
    },

    # --- POLICY 9: SharePoint Zero Trust Access ---
    # Requires compliant device AND domain-joined for SharePoint Online access
    @{
        Name   = "CA - SharePoint Zero Trust Access"
        Config = @{
            displayName = "CA - SharePoint Zero Trust Access"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeUsers  = @("All")
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("00000003-0000-0ff1-ce00-000000000000")  # SharePoint Online
                }
            }
            grantControls = @{
                operator        = "AND"
                builtInControls = @("compliantDevice", "domainJoined")
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
    },

    # --- POLICY 10: Admin FIDO2 Protection ---
    # Requires phishing-resistant MFA (FIDO2) for privileged admin roles on trusted locations
    @{
        Name   = "CA - Admin FIDO2 Protection"
        Config = @{
            displayName = "CA - Admin FIDO2 Protection"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeRoles = @(
                        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
                        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
                        "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
                        "b0f54661-2d74-4c50-afa3-1ec803f12efe"   # Billing Administrator
                    )
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
                locations = @{
                    includeLocations = @("Trusted")
                }
            }
            grantControls = @{
                operator             = "OR"
                authenticationStrength = @{
                    id = "00000000-0000-0000-0000-000000000004"  # Phishing-resistant MFA (FIDO2, WHfB, CBA)
                }
            }
        }
    },

    # --- POLICY 11: Block Untrusted Countries ---
    # Blocks access from all locations except named locations for IN, US, UK
    @{
        Name   = "CA - Block Untrusted Countries"
        Config = @{
            displayName = "CA - Block Untrusted Countries"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeUsers  = @("All")
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @("All")
                }
                locations = @{
                    includeLocations = @("All")
                    excludeLocations = $allowedCountryLocationIds
                }
            }
            grantControls = @{
                operator        = "OR"
                builtInControls = @("block")
            }
        }
    }
)

# ==========================================
# Create policies
# ==========================================
$created = 0
$skipped = 0
$failed  = 0
$enabled = 0

foreach ($policy in $policies) {

    $policyName = $policy.Name
    $policyConfig = $policy.Config

    try {
        # Skip if policy already exists
        if ($existingNames -contains $policyName) {
            Write-Host "[SKIP] Policy already exists: $policyName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create policy: $policyName" -ForegroundColor Magenta
            $created++
            continue
        }

        $body = $policyConfig | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[CREATED] $policyName (ID: $($result.id))" -ForegroundColor Green
        $created++

        # Auto-enable if requested
        if ($EnablePolicies) {
            try {
                $enableBody = @{ state = "enabled" } | ConvertTo-Json
                Invoke-MgGraphRequest -Method PATCH `
                    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($result.id)" `
                    -Body $enableBody `
                    -ContentType "application/json" `
                    -ErrorAction Stop

                Write-Host "  [ENABLED] $policyName" -ForegroundColor Cyan
                $enabled++
            }
            catch {
                Write-Host "  [WARN] Failed to enable $policyName - $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        # Try to extract Graph API error message
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
        Write-Host "[FAIL] $policyName - $errorMsg" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Conditional Access Summary ---" -ForegroundColor Cyan
Write-Host "  Created  : $created" -ForegroundColor Green
Write-Host "  Skipped  : $skipped" -ForegroundColor Yellow
Write-Host "  Failed   : $failed" -ForegroundColor Red
if ($EnablePolicies) {
    Write-Host "  Enabled  : $enabled" -ForegroundColor Cyan
}
Write-Host "  Mode     : $(if ($WhatIf) { 'WhatIf' } elseif ($EnablePolicies) { 'Created + Enabled' } else { 'Created (Report-Only)' })" -ForegroundColor White
Write-Host "----------------------------------`n" -ForegroundColor Cyan

if (-not $EnablePolicies -and $created -gt 0) {
    Write-Host "[INFO] Policies created in report-only mode. Use -EnablePolicies to enable them." -ForegroundColor Yellow
    Write-Host "       Or run: .\05-EnableCAPolicies.ps1`n" -ForegroundColor Yellow
}
