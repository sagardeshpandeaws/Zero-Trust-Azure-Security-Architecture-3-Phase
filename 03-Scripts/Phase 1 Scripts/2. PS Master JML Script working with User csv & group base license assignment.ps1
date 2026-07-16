#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users.Actions, Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Zero Touch JML (Joiner/Mover/Leaver) automation via CSV + Microsoft Graph.

.DESCRIPTION
    Processes a CSV file to automate user lifecycle:
    - Joiner : Creates user, sets manager, generates TAP
    - Mover  : Updates department/role (triggers dynamic group reassignment)
    - Leaver: Disable -> Revoke -> Unlicense -> Wipe Intune Devices -> Remove Manager -> Delete

    Supports scheduled actions via StartDate/EndDate columns.

.PARAMETER CsvPath
    Path to the input CSV file. Defaults to .\Users.csv in script directory.

.PARAMETER LogPath
    Path to the log file. Defaults to .\JML_Log.txt in script directory.

.PARAMETER TapOutputPath
    Path to export TAP codes. Defaults to .\JML_TAP.csv in script directory.

.PARAMETER WhatIf
    Shows what Leaver operations would do without executing them.

.EXAMPLE
    .\2. PS Master JML Script working with User csv & group base license assignment.ps1
    .\2. PS Master JML Script working with User csv & group base license assignment.ps1 -CsvPath "C:\data\users.csv" -WhatIf
#>

param(
    [string]$CsvPath       = "$PSScriptRoot\Users.csv",
    [string]$LogPath       = "$PSScriptRoot\JML_Log.txt",
    [string]$TapOutputPath = "$PSScriptRoot\JML_TAP.csv",
    [switch]$WhatIf
)

# ==========================================
# Initialize
# ==========================================
Add-Type -AssemblyName System.Web

$requiredColumns = @('Action','DisplayName','UserPrincipalName','GivenName','Surname','Department')
$tapResults      = [System.Collections.Generic.List[PSObject]]::new()
$stats           = @{ Success = 0; Failed = 0; Skipped = 0; Total = 0 }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $entry
    switch ($Level) {
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "WARN"    { Write-Host $entry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry -ForegroundColor Cyan }
    }
}

# ==========================================
# Connect
# ==========================================
Connect-MgGraph -Scopes @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All"
)

# ==========================================
# Validate CSV
# ==========================================
if (-not (Test-Path -LiteralPath $CsvPath)) {
    Write-Log "CSV file not found: $CsvPath" "ERROR"
    exit 1
}

$users = Import-Csv -Path $CsvPath

if (-not $users -or $users.Count -eq 0) {
    Write-Log "CSV is empty or has no valid rows" "ERROR"
    exit 1
}

$csvColumns = $users[0].PSObject.Properties.Name
$missingColumns = $requiredColumns | Where-Object { $_ -notin $csvColumns }
if ($missingColumns) {
    Write-Log "CSV missing required columns: $($missingColumns -join ', ')" "ERROR"
    exit 1
}

Write-Log "Loaded $($users.Count) rows from $CsvPath"

# ==========================================
# Process each user
# ==========================================
foreach ($u in $users) {

    $stats.Total++

    try {
        $upn = $u.UserPrincipalName.Trim()
        Write-Log "Processing: $upn (Action: $($u.Action))"

        # --- Validate required fields ---
        if (-not $upn -or -not $u.DisplayName -or -not $u.Action) {
            Write-Log "Skipping row - missing UPN, DisplayName, or Action" "WARN"
            $stats.Skipped++
            continue
        }

        # --- Default Department fallback ---
        if (-not $u.Department -or $u.Department.Trim() -eq "") {
            $u.Department = "Default"
        }

        # --- Schedule check: Skip future Joiners ---
        if ($u.Action -eq "Joiner" -and $u.StartDate) {
            $startDate = [datetime]::Parse($u.StartDate)
            if ($startDate -gt (Get-Date)) {
                Write-Log "Skipping $upn - StartDate ($($u.StartDate)) is in the future" "WARN"
                $stats.Skipped++
                continue
            }
        }

        # --- Schedule check: Auto-trigger Leaver when EndDate <= today ---
        if ($u.Action -ne "Leaver" -and $u.EndDate) {
            $endDate = [datetime]::Parse($u.EndDate)
            if ($endDate -le (Get-Date)) {
                Write-Log "Auto-converting $upn to Leaver (EndDate $($u.EndDate) has passed)" "WARN"
                $u.Action = "Leaver"
            }
        }

        # ==========================================
        # JOINER
        # ==========================================
        if ($u.Action -eq "Joiner") {

            $existingUser = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Log "User already exists, skipping: $upn" "WARN"
                $stats.Skipped++
                continue
            }

            # Generate random password (TAP is primary auth, this is fallback)
            $randomPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)

            $userParams = @{
                DisplayName       = $u.DisplayName
                UserPrincipalName = $upn
                MailNickname      = $upn.Split("@")[0]
                GivenName         = $u.GivenName
                Surname           = $u.Surname
                Department        = $u.Department
                JobTitle          = $u.JobTitle
                OfficeLocation    = $u.OfficeLocation
                City              = $u.City
                Country           = $u.Country
                MobilePhone       = $u.MobilePhone
                UsageLocation     = $u.UsageLocation
                EmployeeId        = $u.EmployeeID
                AccountEnabled    = $true
                PasswordProfile   = @{
                    Password                      = $randomPassword
                    ForceChangePasswordNextSignIn  = $true
                }
            }

            if ($WhatIf) {
                Write-Log "[WhatIf] Would create user: $upn" "WARN"
            }
            else {
                $newUser = New-MgUser @userParams -ErrorAction Stop
                Write-Log "Created user: $upn (ID: $($newUser.Id))" "SUCCESS"

                # --- Set Manager ---
                if ($u.ManagerUPN) {
                    try {
                        $manager = Get-MgUser -UserId $u.ManagerUPN.Trim() -ErrorAction Stop
                        Set-MgUserManagerByRef -UserId $newUser.Id -BodyParameter @{
                            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($manager.Id)"
                        } -ErrorAction Stop
                        Write-Log "Set manager: $($u.ManagerUPN) -> $upn"
                    }
                    catch {
                        Write-Log "Failed to set manager for $upn - $($_.Exception.Message)" "WARN"
                    }
                }

                # --- Generate TAP ---
                try {
                    $tap = New-MgUserAuthenticationTemporaryAccessPassMethod `
                        -UserId $newUser.Id `
                        -BodyParameter @{
                            lifetimeInMinutes = 60
                            isUsableOnce      = $true
                        } -ErrorAction Stop

                    $tapResults.Add([PSCustomObject]@{
                        UserPrincipalName = $upn
                        DisplayName       = $u.DisplayName
                        TAP               = $tap.TemporaryAccessPass
                        ExpiresAt         = (Get-Date).AddMinutes(60).ToString("yyyy-MM-dd HH:mm:ss")
                        Department        = $u.Department
                    })
                    Write-Log "TAP generated for $upn"
                }
                catch {
                    Write-Log "Failed to generate TAP for $upn - $($_.Exception.Message)" "WARN"
                }
            }

            Write-Log "Joiner completed: $upn" "SUCCESS"
            $stats.Success++
        }

        # ==========================================
        # MOVER
        # ==========================================
        elseif ($u.Action -eq "Mover") {

            $userObj = Get-MgUser -UserId $upn -ErrorAction Stop

            # --- Detect department change (triggers dynamic group reassignment) ---
            $deptChanged = $false
            if ($u.Department -and $u.Department.Trim() -ne "" -and $u.Department -ne $userObj.Department) {
                Write-Log "Department change detected: $($userObj.Department) -> $($u.Department) for $upn" "WARN"
                $deptChanged = $true
            }

            if ($WhatIf) {
                Write-Log "[WhatIf] Would update user: $upn" "WARN"
            }
            else {
                $updateParams = @{}

                if ($u.Department)      { $updateParams.Department     = $u.Department }
                if ($u.JobTitle)        { $updateParams.JobTitle       = $u.JobTitle }
                if ($u.OfficeLocation)  { $updateParams.OfficeLocation = $u.OfficeLocation }
                if ($u.MobilePhone)     { $updateParams.MobilePhone    = $u.MobilePhone }
                if ($u.City)            { $updateParams.City           = $u.City }
                if ($u.Country)         { $updateParams.Country        = $u.Country }
                if ($u.Company)         { $updateParams.CompanyName    = $u.Company }
                if ($u.JobTitle)        { $updateParams.JobTitle       = $u.JobTitle }

                if ($updateParams.Count -gt 0) {
                    Update-MgUser -UserId $userObj.Id @updateParams -ErrorAction Stop
                    Write-Log "Updated profile for $upn"
                }

                # --- Update Manager ---
                if ($u.ManagerUPN) {
                    try {
                        $manager = Get-MgUser -UserId $u.ManagerUPN.Trim() -ErrorAction Stop
                        Set-MgUserManagerByRef -UserId $userObj.Id -BodyParameter @{
                            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($manager.Id)"
                        } -ErrorAction Stop
                        Write-Log "Updated manager: $($u.ManagerUPN) -> $upn"
                    }
                    catch {
                        Write-Log "Failed to update manager for $upn - $($_.Exception.Message)" "WARN"
                    }
                }
            }

            if ($deptChanged) {
                Write-Log "Mover completed: $upn (department changed - dynamic groups will auto-reassign)" "SUCCESS"
            }
            else {
                Write-Log "Mover completed: $upn" "SUCCESS"
            }
            $stats.Success++
        }

        # ==========================================
        # LEAVER
        # ==========================================
        elseif ($u.Action -eq "Leaver") {

            $userObj = Get-MgUser -UserId $upn -ErrorAction Stop

            if ($WhatIf) {
                Write-Log "[WhatIf] Would DISABLE + WIPE + DELETE user: $upn" "WARN"
            }
            else {
                # Step 1: Disable account
                Update-MgUser -UserId $userObj.Id -AccountEnabled:$false -ErrorAction Stop
                Write-Log "Step 1/6: Disabled account for $upn"

                # Step 2: Revoke all active sessions
                try {
                    Revoke-MgUserSignInSession -UserId $userObj.Id -ErrorAction Stop
                    Write-Log "Step 2/6: Revoked all sessions for $upn"
                }
                catch {
                    Write-Log "Step 2/6: Session revoke failed (may have no active sessions) - $($_.Exception.Message)" "WARN"
                }

                # Step 3: Remove assigned licenses
                try {
                    $userLicenses = Get-MgUserLicenseDetail -UserId $userObj.Id -ErrorAction Stop
                    if ($userLicenses) {
                        $licenseIds = $userLicenses.SkuId
                        $removeLicenses = @($licenseIds)
                        Set-MgUserLicense -UserId $userObj.Id -AddLicenses @() -RemoveLicenses $removeLicenses -ErrorAction Stop
                        Write-Log "Step 3/6: Removed $($licenseIds.Count) license(s) from $upn"
                    }
                    else {
                        Write-Log "Step 3/6: No assigned licenses to remove for $upn"
                    }
                }
                catch {
                    Write-Log "Step 3/6: License removal failed for $upn - $($_.Exception.Message)" "WARN"
                }

                # Step 4: Wipe Intune managed devices
                try {
                    $registeredDevices = Get-MgUserRegisteredDevice -UserId $userObj.Id -ErrorAction Stop
                    if ($registeredDevices -and $registeredDevices.Count -gt 0) {
                        $wipedCount = 0
                        $wipeFailed = 0
                        foreach ($device in $registeredDevices) {
                            try {
                                $managedDevice = Get-MgDeviceManagementManagedDevice -Filter "azureADDeviceId eq '$($device.Id)'" -ErrorAction Stop
                                if ($managedDevice) {
                                    Invoke-MgDeviceManagementManagedDeviceWipe `
                                        -ManagedDeviceId $managedDevice.Id `
                                        -KeepEnrollmentData:$false `
                                        -KeepUserData:$false `
                                        -ErrorAction Stop
                                    Write-Log "  Wiped device: $($managedDevice.DeviceName) (ID: $($managedDevice.Id))"
                                    $wipedCount++
                                }
                            }
                            catch {
                                Write-Log "  Failed to wipe device $($device.Id) - $($_.Exception.Message)" "WARN"
                                $wipeFailed++
                            }
                        }
                        Write-Log "Step 4/6: Intune wipe complete - $wipedCount wiped, $wipeFailed failed"
                    }
                    else {
                        Write-Log "Step 4/6: No registered devices found for $upn"
                    }
                }
                catch {
                    Write-Log "Step 4/6: Intune device lookup failed for $upn - $($_.Exception.Message)" "WARN"
                }

                # Step 5: Remove manager reference
                try {
                    $currentManager = Get-MgUserManagerByRef -UserId $userObj.Id -ErrorAction Stop
                    if ($currentManager) {
                        Remove-MgUserManagerByRef -UserId $userObj.Id -ErrorAction Stop
                        Write-Log "Step 5/6: Removed manager reference for $upn"
                    }
                    else {
                        Write-Log "Step 5/6: No manager to remove for $upn"
                    }
                }
                catch {
                    Write-Log "Step 5/6: Manager removal failed for $upn - $($_.Exception.Message)" "WARN"
                }

                # Step 6: Delete user
                try {
                    Remove-MgUser -UserId $userObj.Id -Confirm:$false -ErrorAction Stop
                    Write-Log "Step 6/6: Deleted user $upn" "SUCCESS"
                }
                catch {
                    Write-Log "Step 6/6: User deletion failed for $upn - $($_.Exception.Message)" "ERROR"
                }
            }

            $stats.Success++
        }

        else {
            Write-Log "Unknown action '$($u.Action)' for $upn - skipping" "WARN"
            $stats.Skipped++
        }
    }
    catch {
        Write-Log "ERROR processing $upn - $($_.Exception.Message)" "ERROR"
        $stats.Failed++
    }
}

# ==========================================
# Export TAP results
# ==========================================
if ($tapResults.Count -gt 0) {
    $tapResults | Export-Csv -Path $TapOutputPath -NoTypeInformation
    Write-Log "TAP codes exported to: $TapOutputPath"
    Write-Host "  [WARNING] TAP file contains temporary access passes — delete after use" -ForegroundColor Red
}

# ==========================================
# Summary
# ==========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  JML Automation Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total rows : $($stats.Total)" -ForegroundColor White
Write-Host "  Success    : $($stats.Success)" -ForegroundColor Green
Write-Host "  Failed     : $($stats.Failed)" -ForegroundColor Red
Write-Host "  Skipped    : $($stats.Skipped)" -ForegroundColor Yellow
Write-Host "  TAP codes  : $($tapResults.Count)" -ForegroundColor White
if ($WhatIf) {
    Write-Host "  Mode       : WhatIf (no changes made)" -ForegroundColor Magenta
}
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Log "JML Automation completed - Success: $($stats.Success) | Failed: $($stats.Failed) | Skipped: $($stats.Skipped)"
