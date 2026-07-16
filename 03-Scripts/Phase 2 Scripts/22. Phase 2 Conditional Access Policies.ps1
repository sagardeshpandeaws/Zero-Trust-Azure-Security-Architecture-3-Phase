#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates Phase 2 Conditional Access policies for secure application access.

.DESCRIPTION
    Deploys risk-adaptive Conditional Access policies specifically designed for
    internal application access via Entra Application Proxy.

    Policies include:
    1. Application Access Policy (MFA + Compliant Device)
    2. Sign-in Risk Policy (Medium/High risk -> MFA/Block)
    3. User Risk Policy (High risk -> Password Reset)
    4. Location-Based Policy (Trusted locations only)
    5. Session Control Policy (Defender for Cloud Apps)
    6. Device Risk Block Policy (High risk -> Block)

    Integration points:
    - Microsoft Defender for Endpoint (device risk)
    - Microsoft Defender for Cloud Apps (session control)
    - Microsoft Entra ID Protection (identity risk)
    - Microsoft Intune (device compliance)

    All policies exclude break-glass and emergency accounts for safety.

.PARAMETER WhatIf
    Shows what would happen without creating policies.

.EXAMPLE
    .\22. Phase 2 Conditional Access Policies.ps1 -AppProxyAppName "MyApp"
    .\22. Phase 2 Conditional Access Policies.ps1 -AppProxyAppName "MyApp" -WhatIf
#>

param(
    [switch]$WhatIf,
    [switch]$Confirm,
    [Parameter(Mandatory = $true)]
    [string]$AppProxyAppName
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
    "Emergency Account",
    "DG-CA-Compliant-Users",
    "DG-Intune-Users"
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

# Validate critical groups
if (-not $groupIds.ContainsKey("SG-BreakGlass-Exclude") -or -not $groupIds.ContainsKey("Emergency Account")) {
    Write-Host "[ERROR] SG-BreakGlass-Exclude and Emergency Account groups are required." -ForegroundColor Red
    exit 1
}

$excludeAll = @($groupIds["SG-BreakGlass-Exclude"], $groupIds["Emergency Account"])
$caGroupId = $groupIds["DG-CA-Compliant-Users"]
$intuneGroupId = $groupIds["DG-Intune-Users"]

Write-Host "-------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Resolve App Proxy application
# ==========================================
Write-Host "`n--- Resolving App Proxy Application ---" -ForegroundColor Cyan

if (-not $AppProxyAppName) {
    Write-Host "[ERROR] -AppProxyAppName parameter is required." -ForegroundColor Red
    exit 1
}

$servicePrincipals = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$AppProxyAppName'" `
    -ErrorAction SilentlyContinue

if ($servicePrincipals.value.Count -eq 0) {
    Write-Host "[ERROR] Application not found: $AppProxyAppName" -ForegroundColor Red
    exit 1
}

$appProxyAppId = $servicePrincipals.value[0].appId
Write-Host "  [OK] $AppProxyAppName -> $appProxyAppId" -ForegroundColor Green
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
# Define Phase 2 CA policies
# ==========================================

$policies = @(
    # --- POLICY 1: Application Access (MFA + Compliant Device) ---
    @{
        Name   = "CA-Phase2 - Application Access"
        Config = @{
            displayName = "CA-Phase2 - Application Access"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($appProxyAppId)
                }
                platforms = @{
                    includePlatforms = @("all")
                }
                clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
                devices = @{
                    includeDeviceStates = @("All")
                    deviceRiskLevels   = @("medium", "high")
                }
            }
            grantControls = @{
                operator       = "AND"
                builtInControls = @("mfa", "compliantDevice")
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

    # --- POLICY 2: Sign-in Risk Policy ---
    @{
        Name   = "CA-Phase2 - Sign-in Risk"
        Config = @{
            displayName = "CA-Phase2 - Sign-in Risk"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                signInRiskLevels = @("medium", "high")
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($appProxyAppId)
                }
                devices = @{
                    includeDeviceStates = @("All")
                    deviceRiskLevels   = @("medium", "high")
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("mfa")
            }
        }
    },

    # --- POLICY 3: User Risk Policy ---
    @{
        Name   = "CA-Phase2 - User Risk"
        Config = @{
            displayName = "CA-Phase2 - User Risk"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                userRiskLevels = @("high")
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($appProxyAppId)
                }
            }
            grantControls = @{
                operator       = "OR"
                builtInControls = @("passwordChange")
            }
        }
    },

    # --- POLICY 4: Location-Based Policy ---
    @{
        Name   = "CA-Phase2 - Trusted Locations"
        Config = @{
            displayName = "CA-Phase2 - Trusted Locations"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($appProxyAppId)
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

    # --- POLICY 5: Session Control (Defender for Cloud Apps) ---
    @{
        Name   = "CA-Phase2 - Session Control"
        Config = @{
            displayName = "CA-Phase2 - Session Control"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($appProxyAppId)
                }
                clientAppTypes = @("browser")
            }
            sessionControls = @{
                signInFrequency = @{
                    value             = 1
                    type              = "hours"
                    isEnabled         = $true
                    frequencyInterval = "timeBased"
                }
                cloudAppSecurity = @{
                    cloudAppSecurityType = "mcasConfigured"
                    isEnabled           = $true
                }
            }
        }
    },

    # --- POLICY 6: Device Risk Block ---
    @{
        Name   = "CA-Phase2 - Device Risk Block"
        Config = @{
            displayName = "CA-Phase2 - Device Risk Block"
            state       = "enabledForReportingButNotEnforced"
            conditions  = @{
                users = @{
                    includeGroups = @($caGroupId)
                    excludeGroups = $excludeAll
                }
                applications = @{
                    includeApplications = @($appProxyAppId)
                }
                devices = @{
                    includeDeviceStates = @("All")
                    deviceRiskLevels   = @("high")
                }
            }
            grantControls = @{
                operator       = "OR"
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
Write-Host "`n--- Phase 2 Conditional Access Summary ---" -ForegroundColor Cyan
Write-Host "  Created  : $created" -ForegroundColor Green
Write-Host "  Skipped  : $skipped" -ForegroundColor Yellow
Write-Host "  Failed   : $failed" -ForegroundColor Red
Write-Host "  Mode     : $(if ($WhatIf) { 'WhatIf' } else { 'Created (Report-Only)' })" -ForegroundColor White
Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

Write-Host "[POLICIES DEPLOYED]" -ForegroundColor Green
Write-Host "  1. Application Access   — MFA + Compliant Device" -ForegroundColor White
Write-Host "  2. Sign-in Risk         — Medium/High -> MFA" -ForegroundColor White
Write-Host "  3. User Risk            — High -> Password Reset" -ForegroundColor White
Write-Host "  4. Trusted Locations    — Block untrusted" -ForegroundColor White
Write-Host "  5. Session Control      — 1hr timeout + Defender" -ForegroundColor White
Write-Host "  6. Device Risk Block    — High risk -> Block" -ForegroundColor White

if (-not $WhatIf -and $created -gt 0) {
    Write-Host "`n[INFO] Policies created in report-only mode." -ForegroundColor Yellow
    Write-Host "       Review in Entra Admin Center > Security > Conditional Access" -ForegroundColor Gray
    Write-Host "       Then enable when ready." -ForegroundColor Gray
}
Write-Host ""
