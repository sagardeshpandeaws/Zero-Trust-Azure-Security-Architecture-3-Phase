#Requires -Modules Microsoft.Graph.Groups

<#
.SYNOPSIS
    Assigns Microsoft 365 licenses to groups for automatic user licensing.

.DESCRIPTION
    Maps security groups to Microsoft 365 SKU licenses using group-based licensing.
    Users inherit licenses automatically when added to groups (via dynamic groups or JML script).

    Supports:
    - Auto-discovery of available SKUs from your tenant
    - Custom license mapping via parameter
    - License availability check (warns when seats are low)
    - WhatIf mode for safe preview

.PARAMETER LicenseMap
    Hashtable mapping group display names to SKU part numbers.
    Example: @{"LG-Managers" = "MSE365_E3"; "LG-Interns" = "MSE365_BUSINESS_PREMIUM"}

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\3. License assignment.ps1
    .\3. License assignment.ps1 -WhatIf
    .\3. License assignment.ps1 -LicenseMap @{"LG-Managers" = "MSE365_E3"}
#>

param(
    [hashtable]$LicenseMap = @{
        "DG-Finance"   = "MSE365_E3"
        "DG-IT"        = "MSE365_E5"
        "DG-HR"        = "MSE365_E3"
        "DG-Sales"     = "MSE365_BUSINESS_PREMIUM"
        "DG-Engineering" = "MSE365_E3"
        "DG-Operations"  = "MSE365_BUSINESS_PREMIUM"
        "DG-Default"   = "MSE365_BUSINESS_PREMIUM"
    },
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes "Group.ReadWrite.All", "Directory.ReadWrite.All"

# ==========================================
# Discover available SKUs
# ==========================================
Write-Host "`n--- Available Licenses in Tenant ---" -ForegroundColor Cyan
$allSkus = Get-MgSubscribedSku
$skuMap  = @{}

foreach ($sku in $allSkus) {
    $available = $sku prepaidUnits.Enabled - $sku ConsumedUnits
    $status    = if ($available -le 0) { "[FULL]" } elseif ($available -le 5) { "[LOW]" } else { "[OK]" }
    $color     = if ($available -le 0) { "Red" } elseif ($available -le 5) { "Yellow" } else { "Green" }

    Write-Host ("  {0,-40} Available: {1,5} {2}" -f $sku.SkuPartNumber, $available, $status) -ForegroundColor $color
    $skuMap[$sku.SkuPartNumber] = @{
        SkuId       = $sku.SkuId
        Available   = $available
        Consumed    = $sku.ConsumedUnits
    }
}
Write-Host "--------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Validate license map against available SKUs
# ==========================================
$validMap   = @{}
$invalidMap = @()

foreach ($group in $LicenseMap.Keys) {
    $skuPartNumber = $LicenseMap[$group]

    if ($skuMap.ContainsKey($skuPartNumber)) {
        $validMap[$group] = $skuMap[$skuPartNumber].SkuId
    }
    else {
        $invalidMap += "$group -> $skuPartNumber (SKU not found in tenant)"
    }
}

if ($invalidMap.Count -gt 0) {
    Write-Host "[WARN] The following mappings have invalid SKUs:" -ForegroundColor Yellow
    $invalidMap | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
}

if ($validMap.Count -eq 0) {
    Write-Host "[ERROR] No valid license mappings to process" -ForegroundColor Red
    Write-Host "Available SKUs: $($skuMap.Keys -join ', ')" -ForegroundColor Gray
    exit 1
}

# ==========================================
# Assign licenses to groups
# ==========================================
$created = 0
$failed  = 0

foreach ($group in $validMap.Keys) {

    try {
        Write-Host "[PROCESSING] Group: $group" -ForegroundColor Cyan

        $groupObj = Get-MgGroup -Filter "displayName eq '$group'" -ErrorAction Stop

        if (-not $groupObj) {
            Write-Host "[SKIP] Group not found: $group" -ForegroundColor Yellow
            $failed++
            continue
        }

        # Check license seat availability
        $skuInfo = $skuMap[$LicenseMap[$group]]
        if ($skuInfo -and $skuInfo.Available -le 0) {
            Write-Host "[WARN] No available seats for $($LicenseMap[$group]) - assignment may fail" -ForegroundColor Yellow
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would assign $($LicenseMap[$group]) to $group" -ForegroundColor Magenta
        }
        else {
            Set-MgGroupLicense `
                -GroupId $groupObj.Id `
                -AddLicenses @{ SkuId = $validMap[$group] } `
                -RemoveLicenses @() `
                -ErrorAction Stop

            Write-Host "[SUCCESS] License $($LicenseMap[$group]) assigned to $group" -ForegroundColor Green
        }
        $created++
    }
    catch {
        Write-Host "[FAIL] $group - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- License Assignment Summary ---" -ForegroundColor Cyan
Write-Host "  Assigned : $created" -ForegroundColor Green
Write-Host "  Failed   : $failed" -ForegroundColor Red
Write-Host "  Invalid  : $($invalidMap.Count)" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "  Mode     : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "-----------------------------------`n" -ForegroundColor Cyan
