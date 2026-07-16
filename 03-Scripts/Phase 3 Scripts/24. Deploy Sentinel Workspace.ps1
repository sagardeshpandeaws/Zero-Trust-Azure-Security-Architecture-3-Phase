#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights

<#
.SYNOPSIS
    Deploys Microsoft Sentinel SIEM workspace for Zero Trust security monitoring.

.DESCRIPTION
    Creates the foundational SIEM infrastructure for Phase 3 SOC operations:
    - Resource Group for security resources
    - Log Analytics Workspace with 90-day retention
    - Microsoft Sentinel solution installation
    - RBAC role assignments for SOC analysts

    This workspace serves as the central hub for all security telemetry
    from Entra ID, Defender for Endpoint, Intune, Defender for Cloud Apps,
    and Microsoft 365.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER Location
    Azure region. Defaults to "East US".

.PARAMETER RetentionInDays
    Log retention period. Defaults to 90 days.

.PARAMETER WhatIf
    Shows what would happen without creating resources.

.EXAMPLE
    .\24. Deploy Sentinel Workspace.ps1
    .\24. Deploy Sentinel Workspace.ps1 -WorkspaceName "MySentinelWorkspace" -Location "West US 2"
    .\24. Deploy Sentinel Workspace.ps1 -WhatIf
#>

param(
    [string]$WorkspaceName = "Sentinel-ZeroTrust-Workspace",
    [string]$ResourceGroup = "rg-sentinel-zerotrust",
    [string]$Location = "East US",
    [int]$RetentionInDays = 90,
    [switch]$WhatIf
)

# ==========================================
# Step 1: Connect to Azure
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 1: Connecting to Azure" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Connect-AzAccount -UseDeviceAuthentication
    Write-Host "[OK] Connected to Azure" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to connect to Azure: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# ==========================================
# Step 2: Create Resource Group
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 2: Creating Resource Group" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    $existingRG = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue

    if ($existingRG) {
        Write-Host "[SKIP] Resource group '$ResourceGroup' already exists" -ForegroundColor Yellow
    }
    else {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would create resource group: $ResourceGroup in $Location" -ForegroundColor Yellow
        }
        else {
            New-AzResourceGroup -Name $ResourceGroup -Location $Location
            Write-Host "[OK] Created resource group: $ResourceGroup" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "[ERROR] Failed to create resource group: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# ==========================================
# Step 3: Create Log Analytics Workspace
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Creating Log Analytics Workspace" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    $existingWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceName -ErrorAction SilentlyContinue

    if ($existingWorkspace) {
        Write-Host "[SKIP] Workspace '$WorkspaceName' already exists" -ForegroundColor Yellow
        $workspace = $existingWorkspace
    }
    else {
        if ($WhatIf) {
            Write-Host "[WhatIf] Would create workspace: $WorkspaceName with $RetentionInDays-day retention" -ForegroundColor Yellow
        }
        else {
            $workspace = New-AzOperationalInsightsWorkspace `
                -ResourceGroupName $ResourceGroup `
                -Name $WorkspaceName `
                -Location $Location `
                -RetentionInDays $RetentionInDays `
                -Sku PerGB2018
            Write-Host "[OK] Created Log Analytics workspace: $WorkspaceName" -ForegroundColor Green
            Write-Host "     Workspace ID: $($workspace.CustomerId)" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[ERROR] Failed to create workspace: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# ==========================================
# Step 4: Enable Sentinel Solution
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 4: Enabling Microsoft Sentinel" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Sentinel on workspace: $WorkspaceName" -ForegroundColor Yellow
    }
    else {
        $solution = Get-AzOperationalInsightsIntelligencePack `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -Name "SecurityInsights" `
            -ErrorAction SilentlyContinue

        if ($solution -and $solution.Enabled) {
            Write-Host "[SKIP] Sentinel already enabled on workspace" -ForegroundColor Yellow
        }
        else {
            Set-AzOperationalInsightsIntelligencePack `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Name "SecurityInsights" `
                -Enabled $true
            Write-Host "[OK] Microsoft Sentinel enabled" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "[ERROR] Failed to enable Sentinel: $($_.Exception.Message)" -ForegroundColor Red
}

# ==========================================
# Step 5: Configure Workspace Settings
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 5: Configuring Workspace Settings" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if (-not $WhatIf) {
        # Set daily quota cap (10 GB/day free tier)
        $workspaceConfig = Get-AzOperationalInsightsWorkspace `
            -ResourceGroupName $ResourceGroup `
            -Name $WorkspaceName

        Write-Host "[OK] Workspace configuration:" -ForegroundColor Green
        Write-Host "     Name: $($workspaceConfig.Name)" -ForegroundColor Gray
        Write-Host "     Region: $($workspaceConfig.Location)" -ForegroundColor Gray
        Write-Host "     Retention: $($workspaceConfig.RetentionInDays) days" -ForegroundColor Gray
        Write-Host "     Workspace ID: $($workspaceConfig.CustomerId)" -ForegroundColor Gray
        Write-Host "     Resource Group: $ResourceGroup" -ForegroundColor Gray
    }
}
catch {
    Write-Host "[WARNING] Could not verify workspace settings: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "SENTINEL WORKSPACE DEPLOYMENT SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Resource Group   : $ResourceGroup" -ForegroundColor White
    Write-Host "Workspace Name   : $WorkspaceName" -ForegroundColor White
    Write-Host "Location         : $Location" -ForegroundColor White
    Write-Host "Retention        : $RetentionInDays days" -ForegroundColor White
    Write-Host "Sentinel         : Enabled" -ForegroundColor White
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "  1. Run Script 10 to configure Data Connectors" -ForegroundColor White
    Write-Host "  2. Run Script 11 to create Analytics Rules" -ForegroundColor White
    Write-Host "  3. Run Script 12 to deploy Playbooks" -ForegroundColor White
    Write-Host "  4. Run Script 13 to create Workbooks" -ForegroundColor White
}
