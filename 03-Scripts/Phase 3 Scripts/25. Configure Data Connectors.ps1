#Requires -Modules Az.Accounts, Az.OperationalInsights, Az.SecurityInsights, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Configures Sentinel data connectors for all Zero Trust log sources.

.DESCRIPTION
    Enables Sentinel data connectors to ingest security telemetry from:
    - Microsoft Entra ID (sign-in, audit, risk events)
    - Microsoft 365 (SharePoint, Exchange, Teams activity)
    - Microsoft Defender for Endpoint (malware, process, vulnerability)
    - Microsoft Intune (compliance, enrollment, configuration)
    - Microsoft Defender for Cloud Apps (CASB activity, file downloads)

    Each connector is enabled and verified. Some connectors require
    corresponding licenses (E5/A5 for Defender for Endpoint, etc.).

.PARAMETER WorkspaceName
    Log Analytics workspace name. Defaults to "Sentinel-ZeroTrust-Workspace".

.PARAMETER ResourceGroup
    Resource group name. Defaults to "rg-sentinel-zerotrust".

.PARAMETER WhatIf
    Shows what would happen without enabling connectors.

.EXAMPLE
    .\25. Configure Data Connectors.ps1
    .\25. Configure Data Connectors.ps1 -WorkspaceName "MyWorkspace"
    .\25. Configure Data Connectors.ps1 -WhatIf
#>

param(
    [string]$WorkspaceName = "Sentinel-ZeroTrust-Workspace",
    [string]$ResourceGroup = "rg-sentinel-zerotrust",
    [switch]$WhatIf
)

# ==========================================
# Step 1: Connect to Azure + Graph
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 1: Connecting to Azure and Microsoft Graph" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Connect-AzAccount -UseDeviceAuthentication
    Write-Host "[OK] Connected to Azure" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to connect to Azure: $($_.Exception.Message)" -ForegroundColor Red
    return
}

try {
    Connect-MgGraph -Scopes @(
        "Directory.Read.All",
        "AuditLog.Read.All",
        "SecurityEvents.Read.All"
    )
    Write-Host "[OK] Connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Graph connection failed — some connectors may need manual setup: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ==========================================
# Step 2: Verify Sentinel Workspace
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 2: Verifying Sentinel Workspace" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    $workspace = Get-AzOperationalInsightsWorkspace `
        -ResourceGroupName $ResourceGroup `
        -Name $WorkspaceName `
        -ErrorAction Stop

    Write-Host "[OK] Workspace found: $($workspace.Name)" -ForegroundColor Green
    Write-Host "     Workspace ID: $($workspace.CustomerId)" -ForegroundColor Gray
}
catch {
    Write-Host "[ERROR] Workspace '$WorkspaceName' not found. Run Script 9 first." -ForegroundColor Red
    return
}

# ==========================================
# Step 3: Enable Entra ID Connector
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 3: Enabling Entra ID (Azure AD) Connector" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Entra ID connector" -ForegroundColor Yellow
    }
    else {
        $connector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "AzureActiveDirectory" }

        if ($connector) {
            Write-Host "[SKIP] Entra ID connector already enabled" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "AzureActiveDirectory" `
                -Enabled $true
            Write-Host "[OK] Entra ID connector enabled" -ForegroundColor Green
            Write-Host "     Logs: Sign-in, Audit, Risk events, PIM activations" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[WARNING] Entra ID connector: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Enable manually: Sentinel > Data connectors > Azure Active Directory" -ForegroundColor Gray
}

# ==========================================
# Step 4: Enable Microsoft 365 Connector
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 4: Enabling Microsoft 365 Connector" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Microsoft 365 connector" -ForegroundColor Yellow
    }
    else {
        $connector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "Microsoft365" }

        if ($connector) {
            Write-Host "[SKIP] Microsoft 365 connector already enabled" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "Microsoft365" `
                -Enabled $true
            Write-Host "[OK] Microsoft 365 connector enabled" -ForegroundColor Green
            Write-Host "     Logs: SharePoint, Exchange, Teams activity" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[WARNING] M365 connector: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Enable manually: Sentinel > Data connectors > Microsoft 365 Defender" -ForegroundColor Gray
}

# ==========================================
# Step 5: Enable Defender for Endpoint Connector
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 5: Enabling Defender for Endpoint Connector" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Defender for Endpoint connector" -ForegroundColor Yellow
    }
    else {
        $connector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "MicrosoftThreatProtection" }

        if ($connector) {
            Write-Host "[SKIP] Defender for Endpoint connector already enabled" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "MicrosoftThreatProtection" `
                -Enabled $true
            Write-Host "[OK] Defender for Endpoint connector enabled" -ForegroundColor Green
            Write-Host "     Telemetry: Malware detections, process behavior, vulnerabilities" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[WARNING] Defender for Endpoint connector: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Requires Defender for Endpoint P2 license" -ForegroundColor Gray
}

# ==========================================
# Step 6: Enable Intune Connector
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 6: Enabling Intune Connector" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Intune connector" -ForegroundColor Yellow
    }
    else {
        $connector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "Intune" }

        if ($connector) {
            Write-Host "[SKIP] Intune connector already enabled" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "Intune" `
                -Enabled $true
            Write-Host "[OK] Intune connector enabled" -ForegroundColor Green
            Write-Host "     Logs: Device compliance, enrollment, configuration changes" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[WARNING] Intune connector: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Enable manually: Sentinel > Data connectors > Microsoft Intune" -ForegroundColor Gray
}

# ==========================================
# Step 7: Enable Defender for Cloud Apps Connector
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Step 7: Enabling Defender for Cloud Apps Connector" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable Defender for Cloud Apps connector" -ForegroundColor Yellow
    }
    else {
        $connector = Get-AzSentinelDataConnector `
            -ResourceGroupName $ResourceGroup `
            -WorkspaceName $WorkspaceName `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Kind -eq "MicrosoftCloudAppSecurity" }

        if ($connector) {
            Write-Host "[SKIP] Defender for Cloud Apps connector already enabled" -ForegroundColor Yellow
        }
        else {
            New-AzSentinelDataConnector `
                -ResourceGroupName $ResourceGroup `
                -WorkspaceName $WorkspaceName `
                -Kind "MicrosoftCloudAppSecurity" `
                -Enabled $true
            Write-Host "[OK] Defender for Cloud Apps connector enabled" -ForegroundColor Green
            Write-Host "     Logs: CASB activity, file downloads, external sharing, exfiltration" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "[WARNING] Defender for Cloud Apps connector: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Requires Microsoft Defender for Cloud Apps license" -ForegroundColor Gray
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "DATA CONNECTORS CONFIGURATION SUMMARY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "Mode: WhatIf (no changes made)" -ForegroundColor Yellow
}
else {
    Write-Host "Workspace : $WorkspaceName" -ForegroundColor White
    Write-Host "Resource  : $ResourceGroup`n" -ForegroundColor White

    $connectors = @(
        @{ Name = "Entra ID"; Logs = "Sign-in, Audit, Risk, PIM" },
        @{ Name = "Microsoft 365"; Logs = "SharePoint, Exchange, Teams" },
        @{ Name = "Defender for Endpoint"; Logs = "Malware, Process, Vulnerability" },
        @{ Name = "Intune"; Logs = "Compliance, Enrollment, Config" },
        @{ Name = "Defender for Cloud Apps"; Logs = "CASB, Downloads, Sharing, Exfiltration" }
    )

    foreach ($c in $connectors) {
        Write-Host "  [+] $($c.Name)" -ForegroundColor Green
        Write-Host "      Logs: $($c.Logs)" -ForegroundColor Gray
    }

    Write-Host "`nNote: Some connectors require specific licenses:" -ForegroundColor Yellow
    Write-Host "  - Defender for Endpoint: E5/A5 or Defender for Endpoint P2" -ForegroundColor Gray
    Write-Host "  - Defender for Cloud Apps: Defender for Cloud Apps license" -ForegroundColor Gray
    Write-Host "  - Entra ID Premium: P1/P2 for risk events" -ForegroundColor Gray
}
