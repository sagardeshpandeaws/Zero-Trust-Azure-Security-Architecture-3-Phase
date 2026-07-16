#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Configures Microsoft Defender for Office 365 for email and collaboration protection.

.DESCRIPTION
    Deploys Defender for Office 365 security policies across the tenant:

    1. Anti-Phishing Policies
       - Executive impersonation protection (CEO, CFO, CTO)
       - Domain impersonation protection (tenant domains)
       - Standalone mailbox protection policy

    2. Safe Links Policies
       - URL detonation and time-of-click protection
       - Click tracking and rewriting
       - Organization-wide coverage

    3. Safe Attachments Policies
       - Block unknown malware in attachments
       - Monitor and redirect suspicious files
       - SharePoint/OneDrive/Teams ATP protection

    4. External Sender Tagging
       - Transport rule to prepend [EXTERNAL] tag
       - Helps users identify external email

    Prerequisites:
    - Microsoft Defender for Office 365 Plan 1 or 2 license
    - Exchange Online admin permissions
    - Azure AD admin permissions (for group lookups)

.PARAMETER WhatIf
    Shows what would happen without creating policies.

.EXAMPLE
    .\13. Defender for Office 365.ps1
    .\13. Defender for Office 365.ps1 -WhatIf
#>

param(
    [switch]$WhatIf
)

# ==========================================
# Connect
# ==========================================
Write-Host "`n--- Connecting to Exchange Online ---" -ForegroundColor Cyan
try {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "  [OK] Exchange Online connected" -ForegroundColor Green
}
catch {
    Write-Host "  [FAIL] Could not connect to Exchange Online - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n--- Connecting to Microsoft Graph ---" -ForegroundColor Cyan
Connect-MgGraph -Scopes "Group.Read.All", "User.Read.All"
Write-Host "  [OK] Microsoft Graph connected" -ForegroundColor Green
Write-Host "-------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Resolve executive users for impersonation protection
# ==========================================
Write-Host "--- Resolving Executive Users ---" -ForegroundColor Cyan

$executiveUPNs = @(
    "ceo@yourtenant.com",
    "cfo@yourtenant.com",
    "cto@yourtenant.com"
)

$executiveSendsAs = @()

foreach ($upn in $executiveUPNs) {
    $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if ($user) {
        $executiveSendsAs += $upn
        Write-Host "  [OK] $upn (ID: $($user.Id))" -ForegroundColor Green
    }
    else {
        Write-Host "  [MISSING] $upn" -ForegroundColor Yellow
    }
}

Write-Host "  Resolved $($executiveSendsAs.Count)/$($executiveUPNs.Count) executives" -ForegroundColor Gray
Write-Host "-----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Resolve tenant domains
# ==========================================
Write-Host "--- Resolving Accepted Domains ---" -ForegroundColor Cyan

$acceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue
$domainNames = @()

if ($acceptedDomains) {
    foreach ($domain in $acceptedDomains) {
        $domainNames += $domain.DomainName
        Write-Host "  [OK] $($domain.DomainName) (Default: $($domain.Default))" -ForegroundColor Green
    }
}
else {
    Write-Host "  [WARN] Could not retrieve accepted domains" -ForegroundColor Yellow
}

Write-Host "-------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Check existing Defender policies
# ==========================================
Write-Host "--- Checking Existing Policies ---" -ForegroundColor Cyan

$existingAntiPhish = Get-AntiPhishPolicy -ErrorAction SilentlyContinue
$existingSafeLinks = Get-SafeLinksPolicy -ErrorAction SilentlyContinue
$existingSafeAttach = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue
$existingTransportRules = Get-TransportRule -ErrorAction SilentlyContinue
$existingATPSharePoint = Get-ATPPolicyForSharePoint -ErrorAction SilentlyContinue

Write-Host "  Anti-Phish policies   : $(if ($existingAntiPhish) { $existingAntiPhish.Count } else { 0 })" -ForegroundColor Gray
Write-Host "  Safe Links policies   : $(if ($existingSafeLinks) { $existingSafeLinks.Count } else { 0 })" -ForegroundColor Gray
Write-Host "  Safe Attach policies  : $(if ($existingSafeAttach) { $existingSafeAttach.Count } else { 0 })" -ForegroundColor Gray
Write-Host "  Transport rules       : $(if ($existingTransportRules) { $existingTransportRules.Count } else { 0 })" -ForegroundColor Gray
Write-Host "----------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define Anti-Phishing Policies
# ==========================================
$antiPhishPolicies = @(
    # --- POLICY 1: Executive Impersonation Protection ---
    @{
        Name   = "APP-EXEC-01 - Executive Impersonation Protection"
        Config = @{
            Name                            = "APP-EXEC-01 - Executive Impersonation Protection"
            AdminDisplayName                = "Protects C-suite executives from impersonation attacks"
            EnableTargetedUserProtection    = $true
            TargetedUsersToProtect          = $executiveSendsAs
            TargetedUserAction               = "Block"
            EnableMailboxIntelligenceProtection = $true
            MailboxIntelligenceAction        = "MoveToJmf"
            EnableSimilarUsersSafetyTips     = $true
            EnableSimilarDomainsSafetyTips   = $true
            EnableFirstContactSafetyTips     = $true
            EnableUnusualCharactersSafetyTips = $true
            AuthenticationFailAction        = "MoveToJmf"
            SpamAction                       = "MoveToJmf"
            PhishAction                      = "Quarantine"
            HighConfidencePhishAction        = "Block"
            EnableRegionMatch                = $true
            DmarcQuarantineAction            = "MoveToJmf"
            DmarcRejectAction                = $false
            SpoofAction                      = "MoveToJmf"
            EnableSpoofIntelligence          = $true
            HonorDmarcPolicy                 = $true
        }
    },

    # --- POLICY 2: Domain Impersonation Protection ---
    @{
        Name   = "APP-DOMAIN-01 - Domain Impersonation Protection"
        Config = @{
            Name                            = "APP-DOMAIN-01 - Domain Impersonation Protection"
            AdminDisplayName                = "Protects against lookalike domain impersonation"
            EnableTargetedDomainProtection   = $true
            TargetedDomainsToProtect         = $domainNames
            TargetedDomainAction             = "Quarantine"
            EnableMailboxIntelligenceProtection = $true
            MailboxIntelligenceAction        = "MoveToJmf"
            EnableSimilarUsersSafetyTips     = $true
            EnableSimilarDomainsSafetyTips   = $true
            EnableFirstContactSafetyTips     = $true
            EnableUnusualCharactersSafetyTips = $true
            AuthenticationFailAction        = "MoveToJmf"
            SpamAction                       = "MoveToJmf"
            PhishAction                      = "Quarantine"
            HighConfidencePhishAction        = "Block"
            EnableRegionMatch                = $true
            DmarcQuarantineAction            = "MoveToJmf"
            DmarcRejectAction                = $false
            SpoofAction                      = "MoveToJmf"
            EnableSpoofIntelligence          = $true
            HonorDmarcPolicy                 = $true
        }
    },

    # --- POLICY 3: Standard Anti-Phish (All Users) ---
    @{
        Name   = "APP-STANDARD-01 - Standard Anti-Phishing"
        Config = @{
            Name                            = "APP-STANDARD-01 - Standard Anti-Phishing"
            AdminDisplayName                = "Baseline anti-phishing for all mailboxes"
            EnableTargetedUserProtection    = $false
            EnableMailboxIntelligenceProtection = $true
            MailboxIntelligenceAction        = "MoveToJmf"
            EnableSimilarUsersSafetyTips     = $true
            EnableSimilarDomainsSafetyTips   = $true
            EnableFirstContactSafetyTips     = $true
            EnableUnusualCharactersSafetyTips = $true
            AuthenticationFailAction        = "MoveToJmf"
            SpamAction                       = "MoveToJmf"
            PhishAction                      = "Quarantine"
            HighConfidencePhishAction        = "Block"
            EnableRegionMatch                = $true
            DmarcQuarantineAction            = "MoveToJmf"
            DmarcRejectAction                = $false
            SpoofAction                      = "MoveToJmf"
            EnableSpoofIntelligence          = $true
            HonorDmarcPolicy                 = $true
        }
    }
)

# ==========================================
# Create Anti-Phishing Policies
# ==========================================
Write-Host "--- Creating Anti-Phishing Policies ---" -ForegroundColor Cyan

$created = 0
$skipped = 0
$failed  = 0

foreach ($policy in $antiPhishPolicies) {

    $policyName = $policy.Name
    $policyConfig = $policy.Config

    try {
        if ($existingAntiPhish -and ($existingAntiPhish | Where-Object { $_.Name -eq $policyName })) {
            Write-Host "[SKIP] Already exists: $policyName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create anti-phishing policy: $policyName" -ForegroundColor Magenta
            $created++
            continue
        }

        $result = New-AntiPhishPolicy @policyConfig -ErrorAction Stop
        Write-Host "[CREATED] $policyName" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $policyName - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Create Anti-Phishing Rules (assign policies to scope)
# ==========================================
Write-Host "--- Creating Anti-Phishing Rules ---" -ForegroundColor Cyan

$antiPhishRules = @(
    @{
        Name     = "APP-EXEC-01 Rule"
        Policy   = "APP-EXEC-01 - Executive Impersonation Protection"
        Scope    = "Organization"
        Comment  = "Applies executive impersonation protection to all recipients"
    },
    @{
        Name     = "APP-DOMAIN-01 Rule"
        Policy   = "APP-DOMAIN-01 - Domain Impersonation Protection"
        Scope    = "Organization"
        Comment  = "Applies domain impersonation protection to all recipients"
    },
    @{
        Name     = "APP-STANDARD-01 Rule"
        Policy   = "APP-STANDARD-01 - Standard Anti-Phishing"
        Scope    = "Organization"
        Comment  = "Baseline anti-phishing policy for all mailboxes"
    }
)

foreach ($rule in $antiPhishRules) {
    try {
        $existingRule = Get-AntiPhishRule -Identity $rule.Name -ErrorAction SilentlyContinue
        if ($existingRule) {
            Write-Host "[SKIP] Rule already exists: $($rule.Name)" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create rule: $($rule.Name) -> $($rule.Policy)" -ForegroundColor Magenta
            $created++
            continue
        }

        New-AntiPhishRule -Name $rule.Name `
            -AntiPhishPolicy $rule.Policy `
            -RecipientDomainIs $rule.Scope `
            -Comments $rule.Comment `
            -ErrorAction Stop | Out-Null

        Write-Host "[CREATED] $($rule.Name) -> $($rule.Policy)" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $($rule.Name) - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define Safe Links Policies
# ==========================================
$safeLinksPolicies = @(
    # --- POLICY 1: Organization-Wide Safe Links ---
    @{
        Name   = "SL-ORG-01 - Organization Safe Links"
        Config = @{
            Name                         = "SL-ORG-01 - Organization Safe Links"
            AdminDisplayName             = "Organization-wide URL detonation and click tracking"
            EnableSafeLinksForTeams      = $true
            EnableSafeLinksForEmail      = $true
            EnableSafeLinksForOffice     = $true
            EnableSafeLinksForSharePoint = $true
            EnableTrackClicks            = $true
            EnableOrganizationBranding   = $true
            ScanUrls                     = $true
            DeliverMessageAfterScan      = $true
            AllowClickThrough            = $false
            BlockUrl                     = $true
            CustomWarningText            = "This link has been identified as potentially harmful by Microsoft Defender for Office 365."
            CustomBlockClickThroughText  = "Access to this link has been blocked by your organization's security policy."
        }
    },

    # --- POLICY 2: Executive Safe Links (Restricted) ---
    @{
        Name   = "SL-EXEC-01 - Executive Safe Links"
        Config = @{
            Name                         = "SL-EXEC-01 - Executive Safe Links"
            AdminDisplayName             = "Enhanced URL protection for executive mailboxes"
            EnableSafeLinksForTeams      = $true
            EnableSafeLinksForEmail      = $true
            EnableSafeLinksForOffice     = $true
            EnableSafeLinksForSharePoint = $true
            EnableTrackClicks            = $true
            EnableOrganizationBranding   = $true
            ScanUrls                     = $true
            DeliverMessageAfterScan      = $true
            AllowClickThrough            = $false
            BlockUrl                     = $true
            CustomWarningText            = "This link has been blocked for executive protection. Contact IT Security if you believe this is a false positive."
            CustomBlockClickThroughText  = "Blocked by executive security policy."
        }
    }
)

# ==========================================
# Create Safe Links Policies
# ==========================================
Write-Host "--- Creating Safe Links Policies ---" -ForegroundColor Cyan

foreach ($policy in $safeLinksPolicies) {

    $policyName = $policy.Name
    $policyConfig = $policy.Config

    try {
        if ($existingSafeLinks -and ($existingSafeLinks | Where-Object { $_.Name -eq $policyName })) {
            Write-Host "[SKIP] Already exists: $policyName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create Safe Links policy: $policyName" -ForegroundColor Magenta
            $created++
            continue
        }

        $result = New-SafeLinksPolicy @policyConfig -ErrorAction Stop
        Write-Host "[CREATED] $policyName" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $policyName - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Create Safe Links Rules
# ==========================================
Write-Host "--- Creating Safe Links Rules ---" -ForegroundColor Cyan

$safeLinksRules = @(
    @{
        Name     = "SL-ORG-01 Rule"
        Policy   = "SL-ORG-01 - Organization Safe Links"
        Scope    = "Organization"
        Comment  = "Applies Safe Links to all users"
    },
    @{
        Name     = "SL-EXEC-01 Rule"
        Policy   = "SL-EXEC-01 - Executive Safe Links"
        Users    = $executiveSendsAs
        Comment  = "Enhanced Safe Links for executives"
    }
)

foreach ($rule in $safeLinksRules) {
    try {
        $existingRule = Get-SafeLinksRule -Identity $rule.Name -ErrorAction SilentlyContinue
        if ($existingRule) {
            Write-Host "[SKIP] Rule already exists: $($rule.Name)" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create rule: $($rule.Name) -> $($rule.Policy)" -ForegroundColor Magenta
            $created++
            continue
        }

        $params = @{
            Name                = $rule.Name
            SafeLinksPolicy     = $rule.Policy
            Comments            = $rule.Comment
            Enabled             = $true
            Priority            = 0
        }

        if ($rule.Scope) {
            $params.RecipientDomainIs = $rule.Scope
        }
        elseif ($rule.Users) {
            $params.SentTo = $rule.Users
        }

        New-SafeLinksRule @params -ErrorAction Stop | Out-Null
        Write-Host "[CREATED] $($rule.Name) -> $($rule.Policy)" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $($rule.Name) - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Define Safe Attachments Policies
# ==========================================
$safeAttachPolicies = @(
    # --- POLICY 1: Block Unknown Malware ---
    @{
        Name   = "SA-BLOCK-01 - Block Unknown Malware"
        Config = @{
            Name                       = "SA-BLOCK-01 - Block Unknown Malware"
            AdminDisplayName           = "Blocks attachments identified as unknown malware"
            Action                     = "Block"
            EnableMonitor              = $false
            Redirect                   = $false
            RedirectAddress            = ""
        }
    },

    # --- POLICY 2: Monitor and Deliver (Standard) ---
    @{
        Name   = "SA-MONITOR-01 - Monitor and Deliver"
        Config = @{
            Name                       = "SA-MONITOR-01 - Monitor and Deliver"
            AdminDisplayName           = "Delivers suspicious attachments and sends report to admin"
            Action                     = "Deliver"
            EnableMonitor              = $true
            Redirect                   = $true
            RedirectAddress            = "security@yourtenant.com"
        }
    },

    # --- POLICY 3: High Confidence Block ---
    @{
        Name   = "SA-HIGHCONF-01 - High Confidence Block"
        Config = @{
            Name                       = "SA-HIGHCONF-01 - High Confidence Block"
            AdminDisplayName           = "Blocks high-confidence malware and quarantines for investigation"
            Action                     = "Block"
            EnableMonitor              = $true
            Redirect                   = $true
            RedirectAddress            = "security@yourtenant.com"
        }
    }
)

# ==========================================
# Create Safe Attachments Policies
# ==========================================
Write-Host "--- Creating Safe Attachments Policies ---" -ForegroundColor Cyan

foreach ($policy in $safeAttachPolicies) {

    $policyName = $policy.Name
    $policyConfig = $policy.Config

    try {
        if ($existingSafeAttach -and ($existingSafeAttach | Where-Object { $_.Name -eq $policyName })) {
            Write-Host "[SKIP] Already exists: $policyName" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create Safe Attachments policy: $policyName" -ForegroundColor Magenta
            $created++
            continue
        }

        $result = New-SafeAttachmentPolicy @policyConfig -ErrorAction Stop
        Write-Host "[CREATED] $policyName" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $policyName - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Create Safe Attachments Rules
# ==========================================
Write-Host "--- Creating Safe Attachments Rules ---" -ForegroundColor Cyan

$safeAttachRules = @(
    @{
        Name     = "SA-BLOCK-01 Rule"
        Policy   = "SA-BLOCK-01 - Block Unknown Malware"
        Scope    = "Organization"
        Comment  = "Blocks unknown malware for all mailboxes"
    },
    @{
        Name     = "SA-MONITOR-01 Rule"
        Policy   = "SA-MONITOR-01 - Monitor and Deliver"
        Scope    = "Organization"
        Comment  = "Monitors and delivers suspicious attachments to all users"
    },
    @{
        Name     = "SA-HIGHCONF-01 Rule"
        Policy   = "SA-HIGHCONF-01 - High Confidence Block"
        Scope    = "Organization"
        Comment  = "High confidence malware block for all users"
    }
)

foreach ($rule in $safeAttachRules) {
    try {
        $existingRule = Get-SafeAttachmentRule -Identity $rule.Name -ErrorAction SilentlyContinue
        if ($existingRule) {
            Write-Host "[SKIP] Rule already exists: $($rule.Name)" -ForegroundColor Yellow
            $skipped++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would create rule: $($rule.Name) -> $($rule.Policy)" -ForegroundColor Magenta
            $created++
            continue
        }

        New-SafeAttachmentRule -Name $rule.Name `
            -SafeAttachmentPolicy $rule.Policy `
            -RecipientDomainIs $rule.Scope `
            -Comments $rule.Comment `
            -Enabled $true `
            -ErrorAction Stop | Out-Null

        Write-Host "[CREATED] $($rule.Name) -> $($rule.Policy)" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $($rule.Name) - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# External Sender Tagging (Transport Rules)
# ==========================================
Write-Host "--- Configuring External Sender Tagging ---" -ForegroundColor Cyan

$externalTagRuleName = "SEC-EXTERNAL-01 - External Sender Tag"

try {
    $existingExtRule = Get-TransportRule -Identity $externalTagRuleName -ErrorAction SilentlyContinue

    if ($existingExtRule) {
        Write-Host "[SKIP] Already exists: $externalTagRuleName" -ForegroundColor Yellow
        $skipped++
    }
    elseif ($WhatIf) {
        Write-Host "[WhatIf] Would create transport rule: $externalTagRuleName" -ForegroundColor Magenta
        $created++
    }
    else {
        New-TransportRule -Name $externalTagRuleName `
            -Comments "Prepends [EXTERNAL] tag to inbound emails from outside the organization to help users identify phishing attempts" `
            -FromScope "NotInOrganization" `
            -SentToScope "InOrganization" `
            -PrependSubject "[EXTERNAL] " `
            -SetHeaderName "X-External-Sender" `
            -SetHeaderValue "True" `
            -ApplyHtmlDisclaimerText "<p style='color:orange; font-weight:bold;'>&#9888; WARNING: This email originated from outside your organization. Do not open attachments or click links unless you trust the sender.</p>" `
            -ApplyHtmlDisclaimerLocation "Prepend" `
            -ApplyHtmlDisclaimerFallbackAction "Wrap" `
            -Enabled $true `
            -Mode "Enforce" `
            -ErrorAction Stop

        Write-Host "[CREATED] $externalTagRuleName" -ForegroundColor Green
        $created++
    }
}
catch {
    Write-Host "[FAIL] $externalTagRuleName - $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# ATP Policy for SharePoint, OneDrive, and Teams
# ==========================================
Write-Host "--- Configuring ATP for SharePoint/OneDrive/Teams ---" -ForegroundColor Cyan

try {
    $existingATP = Get-ATPPolicyForSharePoint -ErrorAction SilentlyContinue

    if ($existingATP) {
        Write-Host "  Current ATP settings for SharePoint/OneDrive:" -ForegroundColor Gray
        Write-Host "    EnableATPForSPOTeamsODB : $($existingATP.EnableATPForSPOTeamsODB)" -ForegroundColor Gray
    }

    if ($WhatIf) {
        Write-Host "[WhatIf] Would enable ATP for SharePoint, OneDrive, and Teams" -ForegroundColor Magenta
        $created++
    }
    else {
        Set-ATPPolicyForSharePoint -EnableATPForSPOTeamsODB $true -ErrorAction Stop

        $updatedATP = Get-ATPPolicyForSharePoint -ErrorAction SilentlyContinue
        Write-Host "[ENABLED] ATP for SharePoint, OneDrive, and Teams" -ForegroundColor Green
        Write-Host "  EnableATPForSPOTeamsODB : $($updatedATP.EnableATPForSPOTeamsODB)" -ForegroundColor Gray
        $created++
    }
}
catch {
    Write-Host "[FAIL] ATP for SharePoint/OneDrive/Teams - $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Configure Safe Attachments unknown malware response
# ==========================================
Write-Host "--- Configuring Safe Attachments Unknown Malware Response ---" -ForegroundColor Cyan

try {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would configure ATP Safe Attachments global settings" -ForegroundColor Magenta
    }
    else {
        Set-ATPAdvancedThreatProtection -EnableATPForSPOTeamsODB $true -ErrorAction Stop
        Write-Host "[ENABLED] Global ATP advanced threat protection for cloud resources" -ForegroundColor Green
    }
}
catch {
    Write-Host "[WARN] Could not set global ATP advanced settings - $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "-------------------------------------------`n" -ForegroundColor Cyan

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Defender for Office 365 Summary ---" -ForegroundColor Cyan
Write-Host "  Created  : $created" -ForegroundColor Green
Write-Host "  Skipped  : $skipped" -ForegroundColor Yellow
Write-Host "  Failed   : $failed" -ForegroundColor Red
if ($WhatIf) {
    Write-Host "  Mode     : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "----------------------------------------`n" -ForegroundColor Cyan

Write-Host "  Anti-Phishing:" -ForegroundColor White
Write-Host "    - Executive impersonation protection (CEO, CFO, CTO)" -ForegroundColor Gray
Write-Host "    - Domain impersonation protection (all tenant domains)" -ForegroundColor Gray
Write-Host "    - Standard anti-phishing baseline for all users" -ForegroundColor Gray
Write-Host "  Safe Links:" -ForegroundColor White
Write-Host "    - Organization-wide URL detonation and click tracking" -ForegroundColor Gray
Write-Host "    - Executive-specific enhanced Safe Links" -ForegroundColor Gray
Write-Host "  Safe Attachments:" -ForegroundColor White
Write-Host "    - Block unknown malware (quarantine)" -ForegroundColor Gray
Write-Host "    - Monitor and deliver suspicious files" -ForegroundColor Gray
Write-Host "    - High confidence block with admin redirect" -ForegroundColor Gray
Write-Host "  ATP for Cloud Resources:" -ForegroundColor White
Write-Host "    - SharePoint, OneDrive, and Teams protection enabled" -ForegroundColor Gray
Write-Host "  External Tagging:" -ForegroundColor White
Write-Host "    - [EXTERNAL] tag prepended to inbound emails" -ForegroundColor Gray
Write-Host "    - HTML disclaimer warning for external senders" -ForegroundColor Gray

Write-Host "`n[NEXT STEPS]" -ForegroundColor Green
Write-Host "  1. Update executive UPNs in the script header before running" -ForegroundColor White
Write-Host "  2. Update redirect addresses (security@yourtenant.com)" -ForegroundColor White
Write-Host "  3. Update external tag disclaimer text as needed" -ForegroundColor White
Write-Host "  4. Monitor quarantine at security.microsoft.com > Email & collaboration > Review" -ForegroundColor White
Write-Host "  5. Create notification policies for high-confidence detections" -ForegroundColor White
Write-Host ""
