#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Configures named trusted locations and geo-based access controls.

.DESCRIPTION
    Implements location-based Conditional Access controls using Microsoft Graph API:
    - Creates named trusted locations for office IP ranges (India, US, UK offices)
    - Creates named location for TOR/anonymous proxy networks
    - Creates country-based restriction named location (allowed: IN, US, UK)
    - Creates CA policy to restrict access to trusted countries only
    - Creates CA policy to block TOR/anonymous proxy IP connections

    Uses Graph API /identity/conditionalAccess/namedLocations endpoint.

    Named Locations:
    1. Office IP ranges - trusted corporate subnets for India, US, UK offices
    2. TOR/Anonymous Networks - known exit node IP ranges to block
    3. Trusted Countries - IN, US, UK as allowed geo locations

    CA Policies:
    1. Restrict access to trusted countries only (block all other countries)
    2. Block TOR/anonymous proxy IP addresses

.PARAMETER IndiaOfficeIPs
    Array of CIDR ranges for India office locations.

.PARAMETER USOfficeIPs
    Array of CIDR ranges for US office locations.

.PARAMETER UKOfficeIPs
    Array of CIDR ranges for UK office locations.

.PARAMETER TORExitNodeIPs
    Array of known TOR exit node IP ranges to block.

.PARAMETER WhatIf
    Shows what would be created without making changes.

.EXAMPLE
    .\17. Named Locations and Geo Controls.ps1
    .\17. Named Locations and Geo Controls.ps1 -WhatIf
    .\17. Named Locations and Geo Controls.ps1 -IndiaOfficeIPs @("10.10.0.0/16","10.11.0.0/16")
#>

param(
    [string[]]$IndiaOfficeIPs = @(
        "10.10.0.0/16"
        "192.168.1.0/24"
    ),
    [string[]]$USOfficeIPs = @(
        "10.20.0.0/16"
        "172.16.0.0/16"
    ),
    [string[]]$UKOfficeIPs = @(
        "10.30.0.0/16"
        "172.20.0.0/16"
    ),
    [string[]]$TORExitNodeIPs = @(
        "198.51.100.0/24"
        "203.0.113.0/24"
    ),
    [switch]$WhatIf
)

# ==========================================
# Initialize
# ==========================================
$stats = @{ NamedLocations = 0; CAPolicies = 0; Failed = 0 }
$graphBaseUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess"

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
# Connect
# ==========================================
Write-Host "`n--- Connecting to Microsoft Graph ---" -ForegroundColor Cyan

$graphScopes = @(
    "Policy.ReadWrite.ConditionalAccess",
    "Directory.Read.All"
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
# Resolve break-glass groups for CA exclusions
# ==========================================
Write-Host "`n--- Resolving Groups for CA Exclusions ---" -ForegroundColor Cyan

$requiredGroups = @(
    "SG-BreakGlass-Exclude",
    "Emergency Account"
)

$groupIds = @{}

foreach ($name in $requiredGroups) {
    $g = Get-MgGroup -Filter "displayName eq '$name'" -ErrorAction SilentlyContinue
    if ($g) {
        $groupIds[$name] = $g.Id
        Write-Status "$name -> $($g.Id)"
    }
    else {
        Write-Status "$name - not found" "WARN"
    }
}

$excludeGroups = @()
if ($groupIds.ContainsKey("SG-BreakGlass-Exclude")) { $excludeGroups += $groupIds["SG-BreakGlass-Exclude"] }
if ($groupIds.ContainsKey("Emergency Account")) { $excludeGroups += $groupIds["Emergency Account"] }

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Retrieve existing named locations
# ==========================================
Write-Host "--- Checking Existing Named Locations ---" -ForegroundColor Cyan

$existingLocations = @()
$existingLocationNames = @()

try {
    $locResponse = Invoke-MgGraphRequest -Method GET `
        -Uri "$graphBaseUri/namedLocations" `
        -ErrorAction Stop

    if ($locResponse.value) {
        $existingLocations = $locResponse.value
        $existingLocationNames = $existingLocations | ForEach-Object { $_.displayName }
    }
    Write-Status "Found $($existingLocations.Count) existing named location(s)"
}
catch {
    Write-Status "Could not retrieve existing named locations - $($_.Exception.Message)" "WARN"
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 1: Create Office IP Named Locations
# ==========================================
Write-Host "--- Step 1: Creating Office IP Named Locations ---" -ForegroundColor Cyan

$officeLocations = @(
    @{
        Name        = "LOC-Office-India"
        DisplayName = "LOC-Office-India"
        Description = "Trusted office IP ranges for India corporate locations"
        IPs         = $IndiaOfficeIPs
        IsTrusted   = $true
    },
    @{
        Name        = "LOC-Office-US"
        DisplayName = "LOC-Office-US"
        Description = "Trusted office IP ranges for US corporate locations"
        IPs         = $USOfficeIPs
        IsTrusted   = $true
    },
    @{
        Name        = "LOC-Office-UK"
        DisplayName = "LOC-Office-UK"
        Description = "Trusted office IP ranges for UK corporate locations"
        IPs         = $UKOfficeIPs
        IsTrusted   = $true
    }
)

foreach ($loc in $officeLocations) {

    try {
        # Skip if already exists
        if ($existingLocationNames -contains $loc.DisplayName) {
            Write-Status "Named location already exists: $($loc.DisplayName)" "SKIP"
            continue
        }

        if ($WhatIf) {
            Write-Status "[WhatIf] Would create named location: $($loc.DisplayName) ($($loc.IPs.Count) IP ranges)" "WHATIF"
            $stats.NamedLocations++
            continue
        }

        $body = @{
            "@odata.type"  = "#microsoft.graph.ipNamedLocation"
            displayName    = $loc.DisplayName
            description    = $loc.Description
            isTrusted      = $loc.IsTrusted
            ipRanges       = $loc.IPs | ForEach-Object {
                @{
                    "@odata.type" = "#microsoft.graph.ipRange"
                    cidrAddress   = $_
                }
            }
        } | ConvertTo-Json -Depth 5

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "$graphBaseUri/namedLocations" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Status "Created named location: $($loc.DisplayName) (ID: $($result.id))" "SUCCESS"
        $stats.NamedLocations++
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
        Write-Status "Failed to create named location: $($loc.DisplayName) - $errorMsg" "ERROR"
        $stats.Failed++
    }
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 2: Create TOR/Anonymous Network Named Location
# ==========================================
Write-Host "--- Step 2: Creating TOR/Anonymous Network Named Location ---" -ForegroundColor Cyan

$torLocName = "LOC-Anonymous-TOR"

try {
    if ($existingLocationNames -contains $torLocName) {
        Write-Status "Named location already exists: $torLocName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create named location: $torLocName ($($TORExitNodeIPs.Count) IP ranges)" "WHATIF"
            $stats.NamedLocations++
        }
        else {
            $body = @{
                "@odata.type"  = "#microsoft.graph.ipNamedLocation"
                displayName    = $torLocName
                description    = "Known TOR exit node and anonymous proxy IP ranges - block all access"
                isTrusted      = $false
                ipRanges       = $TORExitNodeIPs | ForEach-Object {
                    @{
                        "@odata.type" = "#microsoft.graph.ipRange"
                        cidrAddress   = $_
                    }
                }
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "$graphBaseUri/namedLocations" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created named location: $torLocName (ID: $($result.id))" "SUCCESS"
            $stats.NamedLocations++
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
    Write-Status "Failed to create named location: $torLocName - $errorMsg" "ERROR"
    $stats.Failed++
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 3: Create Country-Based Named Location
# ==========================================
Write-Host "--- Step 3: Creating Country-Based Named Location ---" -ForegroundColor Cyan

$countryLocName = "LOC-Trusted-Countries"

try {
    if ($existingLocationNames -contains $countryLocName) {
        Write-Status "Named location already exists: $countryLocName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create named location: $countryLocName (Countries: IN, US, UK)" "WHATIF"
            $stats.NamedLocations++
        }
        else {
            $body = @{
                "@odata.type"  = "#microsoft.graph.countryNamedLocation"
                displayName    = $countryLocName
                description    = "Allowed trusted countries: India, United States, United Kingdom"
                includeUnknownCountriesAndRegions = $false
                countriesAndRegions = @(
                    "IN"
                    "US"
                    "UK"
                )
            } | ConvertTo-Json -Depth 5

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "$graphBaseUri/namedLocations" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created named location: $countryLocName (ID: $($result.id))" "SUCCESS"
            $stats.NamedLocations++
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
    Write-Status "Failed to create named location: $countryLocName - $errorMsg" "ERROR"
    $stats.Failed++
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 4: Check existing CA policies
# ==========================================
Write-Host "--- Checking Existing Conditional Access Policies ---" -ForegroundColor Cyan

$existingPolicies = @()
$existingPolicyNames = @()

try {
    $policyResponse = Invoke-MgGraphRequest -Method GET `
        -Uri "$graphBaseUri/policies" `
        -ErrorAction Stop

    if ($policyResponse.value) {
        $existingPolicies = $policyResponse.value
        $existingPolicyNames = $existingPolicies | ForEach-Object { $_.displayName }
    }
    Write-Status "Found $($existingPolicies.Count) existing CA policy(ies)"
}
catch {
    Write-Status "Could not retrieve existing CA policies - $($_.Exception.Message)" "WARN"
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 5: Create CA Policy - Restrict to Trusted Countries
# ==========================================
Write-Host "--- Step 5: Creating CA Policy - Restrict to Trusted Countries ---" -ForegroundColor Cyan

$countryPolicyName = "CA - Restrict to Trusted Countries"

try {
    if ($existingPolicyNames -contains $countryPolicyName) {
        Write-Status "CA policy already exists: $countryPolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create CA policy: $countryPolicyName" "WHATIF"
            $stats.CAPolicies++
        }
        else {
            $body = @{
                displayName = $countryPolicyName
                state       = "enabledForReportingButNotEnforced"
                conditions  = @{
                    users = @{
                        includeUsers  = @("All")
                        excludeGroups = $excludeGroups
                    }
                    applications = @{
                        includeApplications = @("All")
                    }
                    locations = @{
                        includeLocations = @("All")
                        excludeLocations = @($countryLocName)
                    }
                }
                grantControls = @{
                    operator        = "OR"
                    builtInControls = @("block")
                }
            } | ConvertTo-Json -Depth 10

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "$graphBaseUri/policies" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created CA policy: $countryPolicyName (ID: $($result.id))" "SUCCESS"
            $stats.CAPolicies++
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
    Write-Status "Failed to create CA policy: $countryPolicyName - $errorMsg" "ERROR"
    $stats.Failed++
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 6: Create CA Policy - Block TOR/Anonymous Proxy
# ==========================================
Write-Host "--- Step 6: Creating CA Policy - Block TOR/Anonymous Proxy ---" -ForegroundColor Cyan

$torPolicyName = "CA - Block TOR Anonymous Proxy"

try {
    if ($existingPolicyNames -contains $torPolicyName) {
        Write-Status "CA policy already exists: $torPolicyName" "SKIP"
    }
    else {
        if ($WhatIf) {
            Write-Status "[WhatIf] Would create CA policy: $torPolicyName" "WHATIF"
            $stats.CAPolicies++
        }
        else {
            $body = @{
                displayName = $torPolicyName
                state       = "enabledForReportingButNotEnforced"
                conditions  = @{
                    users = @{
                        includeUsers  = @("All")
                        excludeGroups = $excludeGroups
                    }
                    applications = @{
                        includeApplications = @("All")
                    }
                    locations = @{
                        includeLocations = @($torLocName)
                        excludeLocations = @()
                    }
                }
                grantControls = @{
                    operator        = "OR"
                    builtInControls = @("block")
                }
            } | ConvertTo-Json -Depth 10

            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "$graphBaseUri/policies" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Status "Created CA policy: $torPolicyName (ID: $($result.id))" "SUCCESS"
            $stats.CAPolicies++
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
    Write-Status "Failed to create CA policy: $torPolicyName - $errorMsg" "ERROR"
    $stats.Failed++
}

Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Verification
# ==========================================
Write-Host "--- Verification ---" -ForegroundColor Cyan

try {
    # Verify named locations
    $finalLocations = Invoke-MgGraphRequest -Method GET `
        -Uri "$graphBaseUri/namedLocations" `
        -ErrorAction SilentlyContinue

    if ($finalLocations.value) {
        $scriptLocations = $finalLocations.value | Where-Object {
            $_.displayName -match "^LOC-(Office-|Anonymous-|Trusted-)"
        }

        if ($scriptLocations) {
            Write-Host "  Named Locations:" -ForegroundColor Gray
            foreach ($loc in $scriptLocations) {
                $type = if ($loc.'@odata.type' -match "country") { "Country" } else { "IP" }
                $trusted = if ($loc.isTrusted) { "Trusted" } else { "Not Trusted" }
                Write-Host "    - $($loc.displayName) [$type, $trusted]" -ForegroundColor Gray
            }
        }
    }

    # Verify CA policies
    $finalPolicies = Invoke-MgGraphRequest -Method GET `
        -Uri "$graphBaseUri/policies" `
        -ErrorAction SilentlyContinue

    if ($finalPolicies.value) {
        $scriptPolicies = $finalPolicies.value | Where-Object {
            $_.displayName -match "^CA - (Restrict to Trusted Countries|Block TOR)"
        }

        if ($scriptPolicies) {
            Write-Host "  CA Policies:" -ForegroundColor Gray
            foreach ($p in $scriptPolicies) {
                Write-Host "    - $($p.displayName) [State: $($p.state)]" -ForegroundColor Gray
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
Write-Host "  Named Locations & Geo Controls Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Named Locations    : $($stats.NamedLocations)" -ForegroundColor White
Write-Host "  CA Policies        : $($stats.CAPolicies)" -ForegroundColor White
Write-Host "  Failed             : $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "  Mode               : $(if ($WhatIf) { 'WhatIf (no changes made)' } else { 'Report-Only (policies not enforced)' })" -ForegroundColor $(if ($WhatIf) { "Magenta" } else { "White" })
Write-Host "========================================`n" -ForegroundColor Cyan

if ($stats.Failed -eq 0 -and -not $WhatIf) {
    Write-Host "[DONE] Named locations and geo-based CA policies configured." -ForegroundColor Green
    Write-Host "       All CA policies are in report-only mode. Review sign-in logs before enforcing." -ForegroundColor Gray
    Write-Host "       Office IPs are marked as trusted locations for compliant device bypass scenarios." -ForegroundColor Gray
    Write-Host "       TOR blocking policy will log blocked attempts in sign-in logs for review." -ForegroundColor Gray
}
