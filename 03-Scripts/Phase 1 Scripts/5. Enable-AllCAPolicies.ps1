#Requires -Modules Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Enables all CA policies currently in report-only mode.

.DESCRIPTION
    Finds all Conditional Access policies in "enabledForReportingButNotEnforced" state
    and transitions them to "enabled" state.

    Supports WhatIf for safe preview.

.PARAMETER WhatIf
    Shows which policies would be enabled without making changes.

.PARAMETER PolicyFilter
    Optional wildcard filter to enable only matching policies.
    Example: "CA - Require*" to enable only MFA policy.

.EXAMPLE
    .\5. Enable-AllCAPolicies.ps1
    .\5. Enable-AllCAPolicies.ps1 -WhatIf
    .\5. Enable-AllCAPolicies.ps1 -PolicyFilter "CA - Require*"
#>

param(
    [switch]$WhatIf,
    [switch]$Confirm,
    [string]$PolicyFilter
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All"

# ==========================================
# Fetch all CA policies
# ==========================================
Write-Host "`n--- Conditional Access Policies ---" -ForegroundColor Cyan

$allPolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -ErrorAction Stop

$policies = $allPolicies.value

if (-not $policies -or $policies.Count -eq 0) {
    Write-Host "No Conditional Access policies found in tenant." -ForegroundColor Yellow
    exit 0
}

# ==========================================
# Filter policies
# ==========================================
$reportOnlyPolicies = $policies | Where-Object {
    $_.state -eq "enabledForReportingButNotEnforced"
}

if ($PolicyFilter) {
    $reportOnlyPolicies = $reportOnlyPolicies | Where-Object {
        $_.displayName -like $PolicyFilter
    }
}

if ($reportOnlyPolicies.Count -eq 0) {
    Write-Host "No policies in report-only mode found" $(if ($PolicyFilter) { "matching filter: $PolicyFilter" }) -ForegroundColor Yellow
    Write-Host "`nAll policies:" -ForegroundColor Gray
    foreach ($p in $policies) {
        $stateColor = switch ($p.state) {
            "enabled"                              { "Green" }
            "enabledForReportingButNotEnforced"    { "Yellow" }
            "disabled"                             { "Red" }
            default                                { "Gray" }
        }
        Write-Host ("  [{0}] {1}" -f $p.state, $p.displayName) -ForegroundColor $stateColor
    }
    exit 0
}

# ==========================================
# Display policies to enable
# ==========================================
Write-Host "`nPolicies to enable:" -ForegroundColor White
Write-Host ("{0,-45} {1}" -f "Name", "Current State") -ForegroundColor Gray
Write-Host ("-" * 65) -ForegroundColor Gray

foreach ($p in $reportOnlyPolicies) {
    Write-Host ("  {0,-43} enabledForReportingOnly" -f $p.displayName) -ForegroundColor Yellow
}

Write-Host ("-" * 65) -ForegroundColor Gray
Write-Host "  Total: $($reportOnlyPolicies.Count) policy(ies)" -ForegroundColor White
Write-Host ""

# ==========================================
# Confirm
# ==========================================
if (-not $WhatIf -and -not $Confirm) {
    Write-Host "  [INFO] Use -WhatIf to preview changes, or -Confirm to skip prompt" -ForegroundColor Yellow
    $response = Read-Host "Enable these policies? (Y/N)"
    if ($response -notin @("Y", "y", "Yes")) {
        Write-Host "Aborted." -ForegroundColor Red
        exit 0
    }
}

# ==========================================
# Enable policies
# ==========================================
$enabled = 0
$failed  = 0

foreach ($p in $reportOnlyPolicies) {

    try {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would enable: $($p.displayName)" -ForegroundColor Magenta
            $enabled++
            continue
        }

        $body = @{ state = "enabled" } | ConvertTo-Json

        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($p.id)" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "[ENABLED] $($p.displayName)" -ForegroundColor Green
        $enabled++
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
        Write-Host "[FAIL] $($p.displayName) - $errorMsg" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Enable Summary ---" -ForegroundColor Cyan
Write-Host "  Enabled : $enabled" -ForegroundColor Green
Write-Host "  Failed  : $failed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode    : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "-----------------------`n" -ForegroundColor Cyan

if ($enabled -gt 0 -and -not $WhatIf) {
    Write-Host "[DONE] All CA policies are now enforcing. Monitor sign-in logs for impact." -ForegroundColor Green
}
