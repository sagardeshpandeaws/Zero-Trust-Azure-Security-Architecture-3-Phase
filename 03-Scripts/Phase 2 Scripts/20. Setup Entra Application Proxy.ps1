#Requires -Modules Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Configures Microsoft Entra Application Proxy for secure internal app publishing.

.DESCRIPTION
    Sets up Entra Application Proxy to publish internal web applications to the internet
    without VPN dependency. The connector maintains an outbound-only connection to Entra ID,
    ensuring no inbound firewall ports are exposed.

    Components configured:
    - Application Proxy service activation
    - Connector group creation
    - Internal application registration
    - External URL assignment
    - Pre-authentication settings

    Security benefits:
    - No DMZ required
    - No inbound ports exposed
    - Identity-based access (not network-based)
    - Continuous security evaluation

.PARAMETER InternalAppUrl
    Internal URL of the application (e.g., https://internal-app.yourtenant.local).

.PARAMETER ExternalAppUrl
    External URL for the application (e.g., https://hr-app.yourtenant.com).

.PARAMETER ConnectorGroupName
    Name of the connector group. Defaults to "AppProxy-Connectors".

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\20. Setup Entra Application Proxy.ps1
    .\20. Setup Entra Application Proxy.ps1 -InternalAppUrl "https://internal-app.yourtenant.local" -ExternalAppUrl "https://hr-app.yourtenant.com"
    .\20. Setup Entra Application Proxy.ps1 -WhatIf
#>

param(
    [string]$InternalAppUrl = "https://internal-app.yourtenant.local",
    [string]$ExternalAppUrl = "https://hr-app.yourtenant.com",
    [string]$ConnectorGroupName = "AppProxy-Connectors",
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes @(
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess"
)

# ==========================================
# Step 1: Check Application Proxy Status
# ==========================================
Write-Host "`n--- Step 1: Checking Application Proxy Status ---" -ForegroundColor Cyan

try {
    $proxyStatus = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/onPremisesPublishingProfiles/policies" `
        -ErrorAction Stop

    if ($proxyStatus.id -eq "imds") {
        Write-Host "  [OK] Application Proxy service is available" -ForegroundColor Green
    }
}
catch {
    Write-Host "  [INFO] Application Proxy status check completed" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 2: Create Connector Group
# ==========================================
Write-Host "--- Step 2: Creating Connector Group ---" -ForegroundColor Cyan

$connectorGroup = $null
try {
    $existingGroup = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/onPremisesPublishingProfiles/policies/connectorGroups?`$filter=displayName eq '$ConnectorGroupName'" `
        -ErrorAction SilentlyContinue

    if ($existingGroup.value -and $existingGroup.value.Count -gt 0) {
        $connectorGroup = $existingGroup.value[0]
        Write-Host "  [OK] Connector group already exists: $ConnectorGroupName (ID: $($connectorGroup.id))" -ForegroundColor Green
    }
    else {
        if ($WhatIf) {
            Write-Host "  [WhatIf] Would create connector group: $ConnectorGroupName" -ForegroundColor Magenta
        }
        else {
            $body = @{
                displayName = $ConnectorGroupName
            } | ConvertTo-Json

            $connectorGroup = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/onPremisesPublishingProfiles/policies/connectorGroups" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "  [CREATED] $ConnectorGroupName (ID: $($connectorGroup.id))" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "  [WARN] Connector group creation: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 3: Register Internal Application
# ==========================================
Write-Host "--- Step 3: Registering Internal Application ---" -ForegroundColor Cyan

$appDisplayName = "Internal Web Application"
$application = $null

try {
    $existingApp = Get-MgApplication -Filter "displayName eq '$appDisplayName'" -ErrorAction SilentlyContinue

    if ($existingApp) {
        $application = $existingApp
        Write-Host "  [OK] Application already exists: $appDisplayName (ID: $($application.Id))" -ForegroundColor Green
    }
    else {
        if ($WhatIf) {
            Write-Host "  [WhatIf] Would register application: $appDisplayName" -ForegroundColor Magenta
        }
        else {
            $appParams = @{
                DisplayName = $appDisplayName
                Description = "Internal web application published via Entra Application Proxy"
                IdentifierUris = @("https://$($ExternalAppUrl -replace 'https://', '')")
                Web = @{
                    RedirectUris = @("https://$($ExternalAppUrl -replace 'https://', '')/auth/callback")
                    ImplicitGrantSettings = @{
                        EnableIdTokenIssuance = $true
                        EnableAccessTokenIssuance = $false
                    }
                }
                RequiredResourceAccess = @(
                    @{
                        ResourceAppId = "00000003-0000-0000-c000-000000000000"
                        ResourceAccess = @(
                            @{
                                Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                                Type = "Scope"
                            }
                        )
                    }
                )
            }

            $application = New-MgApplication @appParams -ErrorAction Stop
            Write-Host "  [CREATED] $appDisplayName (ID: $($application.Id))" -ForegroundColor Green

            # Create service principal
            $spParams = @{
                AppId = $application.AppId
            }
            $sp = New-MgServicePrincipal @spParams -ErrorAction Stop
            Write-Host "  [CREATED] Service Principal (ID: $($sp.Id))" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "  [FAIL] Application registration: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 4: Configure Application Proxy
# ==========================================
Write-Host "--- Step 4: Configuring Application Proxy ---" -ForegroundColor Cyan

if ($application -and -not $WhatIf) {
    try {
        $proxyConfig = @{
            "@odata.type" = "#microsoft.graph.onPremisesApplication"
            displayName = $appDisplayName
            externalUrl = $ExternalAppUrl
            internalUrl = $InternalAppUrl
            translationRules = @()
            singleSignOnSettings = @{
                "@odata.type" = "#microsoft.graph.onPremisesSingleSignOnSettings"
                singleSignOnMode = "header"
                preferredSingleSignOnMode = "header"
                kerberosSignOnSettings = $null
            }
            applicationType = "web"
            timeout = "30"
            preAuthentication = "azureAD"
        }

        $body = $proxyConfig | ConvertTo-Json -Depth 10

        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/onPremisesPublishingProfiles/policies/applications" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "  [CONFIGURED] Application Proxy for $appDisplayName" -ForegroundColor Green
        Write-Host "    External URL: $ExternalAppUrl" -ForegroundColor Gray
        Write-Host "    Internal URL: $InternalAppUrl" -ForegroundColor Gray
        Write-Host "    SSO Mode: Header-based" -ForegroundColor Gray
        Write-Host "    Pre-Auth: Azure AD (Entra ID pre-authentication enforced)" -ForegroundColor Gray
        Write-Host "  [NOTE] You must download and install the Application Proxy connector on the target Azure VM." -ForegroundColor Yellow
        Write-Host "         Download from: https://portal.azure.com > Microsoft Entra ID > Application Proxy > Download connector" -ForegroundColor Yellow
    }
    catch {
        Write-Host "  [FAIL] Proxy configuration: $($_.Exception.Message)" -ForegroundColor Red
    }
}
elseif ($WhatIf) {
    Write-Host "  [WhatIf] Would configure Application Proxy" -ForegroundColor Magenta
    Write-Host "    External URL: $ExternalAppUrl" -ForegroundColor Gray
    Write-Host "    Internal URL: $InternalAppUrl" -ForegroundColor Gray
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Step 5: Assign to Connector Group
# ==========================================
Write-Host "--- Step 5: Assigning to Connector Group ---" -ForegroundColor Cyan

if ($connectorGroup -and $application -and -not $WhatIf) {
    try {
        $assignBody = @{
            "@odata.type" = "#microsoft.graph.onPremisesApplication"
            connectorGroupId = $connectorGroup.id
        } | ConvertTo-Json

        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/onPremisesPublishingProfiles/policies/applications/$($application.Id)" `
            -Body $assignBody `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "  [ASSIGNED] $appDisplayName -> $ConnectorGroupName" -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARN] Assignment: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
elseif ($WhatIf) {
    Write-Host "  [WhatIf] Would assign to connector group: $ConnectorGroupName" -ForegroundColor Magenta
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Application Proxy Setup Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Application : $appDisplayName" -ForegroundColor White
Write-Host "  Internal    : $InternalAppUrl" -ForegroundColor White
Write-Host "  External    : $ExternalAppUrl" -ForegroundColor White
Write-Host "  Connector   : $ConnectorGroupName" -ForegroundColor White
Write-Host "  SSO Mode    : Header-based" -ForegroundColor White
if ($WhatIf) {
    Write-Host "  Mode        : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "[NEXT STEPS]" -ForegroundColor Green
Write-Host "  1. Install Application Proxy connector on internal server:" -ForegroundColor White
Write-Host '     Download from: Entra Admin Center > Applications > Application Proxy' -ForegroundColor Gray
Write-Host "  2. Assign users/groups to the application" -ForegroundColor White
Write-Host "  3. Configure Conditional Access policies (Script 11)" -ForegroundColor White
Write-Host "  4. Test access from external network" -ForegroundColor White
Write-Host ""
