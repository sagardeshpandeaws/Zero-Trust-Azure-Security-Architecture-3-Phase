#Requires -Modules Microsoft.Graph.Groups, Microsoft.Graph.Users

<#
.SYNOPSIS
    Creates Entra ID dynamic groups for Zero Trust JML automation.

.DESCRIPTION
    Creates department-based, Intune, CA, and company-based dynamic groups.
    Users are auto-populated based on Azure AD user attributes.

.PARAMETER ExcludedUsers
    Array of UPNs to exclude from broad-scope dynamic groups.

.EXAMPLE
    .\1. Create Dynamic Groups with department rule.ps1
    .\1. Create Dynamic Groups with department rule.ps1 -ExcludedUsers @("admin@tenant.com")
#>

param(
    [string[]]$ExcludedUsers = @(
        "admin1@YourTenant.onmicrosoft.com",
        "admin2@YourTenant.onmicrosoft.com"
    )
)

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes "Group.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All"

# ==========================================
# Build exclusion condition
# ==========================================
$excludedCondition = ($ExcludedUsers | ForEach-Object {
    "(user.userPrincipalName -ne `"$($_)`")"
}) -join " and "

# ==========================================
# Dynamic rule templates
# ==========================================

# Broad rule: all enabled internal members, excluding specified users
$ruleAllEnabled = "(user.accountEnabled -eq true) and (user.userType -eq `"Member`") and $excludedCondition"

# CA rule: all enabled internal members with a company set
$ruleCACompliant = "(user.accountEnabled -eq true) and (user.userType -eq `"Member`") and (user.companyName -ne `"`") and $excludedCondition"

# Intune rule: all enabled internal members (Intune auto-enrolls on MAM/MDM)
$ruleIntune = $ruleAllEnabled

# ==========================================
# Group definitions
# ==========================================

$dynamicGroups = @(
    # --- Department groups ---
    @{ Name = "DG-Default";      Description = "All enabled users with department = Default (fallback)"; Rule = '(user.department -eq "Default")' }
    @{ Name = "DG-Finance";      Description = "All enabled users in Finance department";                 Rule = '(user.department -eq "Finance")' }
    @{ Name = "DG-IT";           Description = "All enabled users in IT department";                      Rule = '(user.department -eq "IT")' }
    @{ Name = "DG-HR";           Description = "All enabled users in HR department";                      Rule = '(user.department -eq "HR")' }
    @{ Name = "DG-Sales";        Description = "All enabled users in Sales department";                   Rule = '(user.department -eq "Sales")' }
    @{ Name = "DG-Engineering";  Description = "All enabled users in Engineering department";             Rule = '(user.department -eq "Engineering")' }
    @{ Name = "DG-Operations";   Description = "All enabled users in Operations department";              Rule = '(user.department -eq "Operations")' }

    # --- Scope groups ---
    @{ Name = "DG-Intune-Users";          Description = "All enabled internal users - Intune enrollment scope";          Rule = $ruleIntune }
    @{ Name = "DG-CA-Compliant-Users";    Description = "All enabled internal users with company - CA policy scope";     Rule = $ruleCACompliant }

    # --- Company groups (multi-company support) ---
    @{ Name = "DG-Company-YourTenant";    Description = "All enabled users belonging to YourTenant";      Rule = '(user.companyName -eq "YourTenant")' }
    @{ Name = "DG-Company-Fabrikam";      Description = "All enabled users belonging to Fabrikam";       Rule = '(user.companyName -eq "Fabrikam")' }

    # --- Location groups (for geo-based CA policies) ---
    @{ Name = "DG-City-EastCampus";       Description = "All enabled users located in East Campus";       Rule = '(user.city -eq "East Campus")' }
    @{ Name = "DG-City-WestCampus";       Description = "All enabled users located in West Campus";       Rule = '(user.city -eq "West Campus")' }
    @{ Name = "DG-Country-US";            Description = "All enabled users in US";                        Rule = '(user.country -eq "US")' }

    # --- Break glass / protection groups (static - empty, managed manually) ---
    @{ Name = "SG-BreakGlass-Exclude";    Description = "Break glass accounts - excluded from all CA policies";   Rule = $null }
    @{ Name = "SG-Admins-Protected";       Description = "Admin accounts requiring elevated CA protection";       Rule = $null }
    @{ Name = "Emergency Account";         Description = "Emergency access accounts";                             Rule = $null }
)

# ==========================================
# Create groups
# ==========================================

$created = 0
$skipped = 0
$failed  = 0

foreach ($g in $dynamicGroups) {

    try {
        $existing = Get-MgGroup -Filter "displayName eq '$($g.Name)'" -ErrorAction Stop

        if ($existing) {
            Write-Host "[SKIP] Already exists: $($g.Name)" -ForegroundColor Yellow
            $skipped++
            continue
        }

        $params = @{
            DisplayName     = $g.Name
            Description     = $g.Description
            MailEnabled     = $false
            MailNickname    = ($g.Name -replace "[^a-zA-Z0-9]", "")
            SecurityEnabled = $true
        }

        # Dynamic group with rule
        if ($g.Rule) {
            $params.GroupTypes        = @("DynamicMembership")
            $params.MembershipRule    = $g.Rule
            $params.MembershipRuleProcessingState = "On"
        }

        New-MgGroup @params -ErrorAction Stop | Out-Null
        Write-Host "[CREATE] $($g.Name)" -ForegroundColor Green
        $created++
    }
    catch {
        Write-Host "[FAIL] $($g.Name) - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

# ==========================================
# Helper: Generate random password
# ==========================================
function New-RandomPassword {
    param([int]$Length = 24)
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?".ToCharArray()
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $Length
    $random.GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

# ==========================================
# Break-Glass Emergency Access Accounts
# ==========================================

Write-Host "`n=== Break-Glass Emergency Access Accounts ===" -ForegroundColor Cyan

$breakGlassAccounts = @(
    @{ UserPrincipalName = "bgadmin1@YourTenant.onmicrosoft.com"; DisplayName = "Break-Glass Admin 1" }
    @{ UserPrincipalName = "bgadmin2@YourTenant.onmicrosoft.com"; DisplayName = "Break-Glass Admin 2" }
)

$bgCreated = 0
$bgSkipped = 0
$bgFailed  = 0
$bgCredentials = @()

foreach ($account in $breakGlassAccounts) {

    try {
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($account.UserPrincipalName)'" -ErrorAction SilentlyContinue

        if ($existingUser) {
            Write-Host "[SKIP] Break-glass account already exists: $($account.UserPrincipalName)" -ForegroundColor Yellow
            $bgSkipped++
            continue
        }

        $securePassword = New-RandomPassword -Length 24
        $passwordProfile = @{
            Password                             = $securePassword
            ForceChangePasswordNextSignIn         = $false
            ForceChangePasswordNextSignInWithMfa  = $false
        }

        $newUser = if (-not $WhatIfPreference) {
            New-MgUser -UserPrincipalName $account.UserPrincipalName `
                       -DisplayName $account.DisplayName `
                       -AccountEnabled `
                       -MailNickname ($account.UserPrincipalName.Split("@")[0]) `
                       -PasswordProfile $passwordProfile `
                       -UsageLocation "US" `
                       -ErrorAction Stop
        }

        Write-Host "[CREATE] $($account.UserPrincipalName)" -ForegroundColor Green
        $bgCreated++

        $bgCredentials += [PSCustomObject]@{
            UPN       = $account.UserPrincipalName
            Password  = $securePassword
            CreatedOn = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }

        # Assign to break-glass security groups
        $targetGroups = @("SG-BreakGlass-Exclude", "Emergency Account")

        foreach ($groupName in $targetGroups) {
            try {
                $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction Stop

                if ($group -and -not $WhatIfPreference) {
                    New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $newUser.Id -ErrorAction Stop | Out-Null
                    Write-Host "  [ASSIGN] $($account.UserPrincipalName) -> $groupName" -ForegroundColor DarkGreen
                }
                elseif ($WhatIfPreference) {
                    Write-Host "  [WHATIF] Would assign $($account.UserPrincipalName) -> $groupName" -ForegroundColor DarkCyan
                }
            }
            catch {
                Write-Host "  [WARN] Failed to add $($account.UserPrincipalName) to $groupName - $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "[FAIL] $($account.UserPrincipalName) - $($_.Exception.Message)" -ForegroundColor Red
        $bgFailed++
    }
}

# ==========================================
# Break-Glass Credentials Report
# ==========================================
if ($bgCredentials.Count -gt 0) {
    Write-Host "`n--- Break-Glass Credentials (Store Offline Securely) ---" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta

    foreach ($cred in $bgCredentials) {
        Write-Host "  UPN      : $($cred.UPN)" -ForegroundColor White
        Write-Host "  Password : $($cred.Password)" -ForegroundColor White
        Write-Host "  Created  : $($cred.CreatedOn)" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Magenta
    }

    Write-Host "`n[WARNING] Store these credentials in a password manager immediately!" -ForegroundColor Red
    Write-Host "          Do not save passwords in plaintext files or share via email." -ForegroundColor Red
    Write-Host "========================================`n" -ForegroundColor Magenta
}

Write-Host "--- Break-Glass Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $bgCreated" -ForegroundColor Green
Write-Host "  Skipped : $bgSkipped" -ForegroundColor Yellow
Write-Host "  Failed  : $bgFailed" -ForegroundColor Red
Write-Host "---------------------------`n" -ForegroundColor Cyan

# ==========================================
# Summary
# ==========================================
Write-Host "`n--- Dynamic Group Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $created" -ForegroundColor Green
Write-Host "  Skipped : $skipped" -ForegroundColor Yellow
Write-Host "  Failed  : $failed" -ForegroundColor Red
Write-Host "  Total   : $($dynamicGroups.Count)" -ForegroundColor White
Write-Host "-------------------------------`n" -ForegroundColor Cyan
