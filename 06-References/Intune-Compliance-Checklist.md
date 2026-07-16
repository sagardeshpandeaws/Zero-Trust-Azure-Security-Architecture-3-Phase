✅ 1. Verify MDM Authority

Go to:
👉 Microsoft Intune Admin Center
→ Tenant Administration → Tenant Status

✔ Ensure:

MDM Authority = Microsoft Intune

✅ 2. Enable Automatic Enrollment

Go to:
👉 Devices → Enrollment → Automatic Enrollment

Configure:

MDM user scope = All
MAM user scope = None (for now)

✅ 3. Configure Enrollment Restrictions

Go to:
👉 Devices → Enrollment → Enrollment restrictions

Create policy:

Block personal devices (optional enterprise)
Allow only:
Windows
Corporate devices

✅ 1. Get Device Hardware Hash

On new device:

Install-Script Get-WindowsAutopilotInfo
Get-WindowsAutopilotInfo.ps1 -OutputFile AutoPilotHWID.csv
✅ 2. Upload to Intune

Go to:
👉 Devices → Windows → Windows Enrollment → Autopilot

Upload CSV

✅ 3. Create Autopilot Profile

Settings:

Deployment mode → User-driven
Join type → Azure AD Join
Skip privacy → Yes
Skip EULA → Yes
Auto-enroll → Yes
✅ 4. Assign Profile

Assign to:

Autopilot device group
🔁 JOINER FLOW (NOW COMPLETE)
Your script creates user ✔
User gets groups ✔
User logs into new device
Autopilot runs
Device auto-configured
🔹 STEP 3 — DEVICE GROUP STRATEGY (CRITICAL)

This is where most people fail. You must design properly.

✅ Create Core Groups
🔸 1. All Devices

Dynamic:

(device.deviceOSType -eq "Windows")
🔸 2. Intune Users (you already have)
SG-Intune-Users
🔸 3. Role-Based Groups

Examples:

SG-App-Finance
SG-App-IT
SG-App-HR

👉 Your JML script will control these

🔸 4. Compliance Group
SG-CA-Compliant-Users
🔹 STEP 4 — COMPLIANCE POLICIES
🎯 Goal

Only secure devices get access

✅ Create Policy

Go:
👉 Devices → Compliance policies → Create

Set:

Require BitLocker = Yes
Require Secure Boot = Yes
Require Antivirus = Yes
Min OS version
Assign to:

👉 SG-Intune-Users

🔹 STEP 5 — CONFIGURATION PROFILES
🎯 Goal

Control device settings

✅ Create Profile

Go:
👉 Devices → Configuration profiles

Examples:

🔐 Security Baseline
Defender settings
Firewall ON
USB restrictions
💻 Device Settings
Disable Control Panel
Set lock screen
Password policy
Assign to:

👉 Groups (not users directly)

🔹 STEP 6 — APPLICATION DEPLOYMENT
🎯 Goal

Auto-install apps

✅ Apps to Deploy
Microsoft 365 Apps
Teams
Chrome / Edge
Company tools
Assignment Strategy:
App Type	Assign To
Core apps	SG-Intune-Users
Role apps	Role-based groups
🔹 STEP 7 — CONDITIONAL ACCESS (ZERO TRUST)
🎯 Goal

Block insecure access

✅ Create Policy

Go:
👉 Entra ID → Security → Conditional Access

Policy:
Users → All users (exclude break glass)
Apps → All cloud apps
Conditions:
Device must be compliant ✅
Require MFA ✅
Link to:

👉 SG-CA-Compliant-Users

🔹 STEP 8 — MOVER FLOW (AUTOMATIC)

Now your JML script becomes powerful 🔥

When Mover happens:

Your script:

Updates group ✔
Intune reacts:
Removes old apps ❌
Adds new apps ✅
Changes policies ✅

👉 No extra Intune config needed

🔹 STEP 9 — LEAVER FLOW (CRITICAL SECURITY)
✅ 1. Your Script

Already does:

Disable user ✔
Remove groups ✔
Delete user ✔
✅ 2. Intune Action

Add this:

🔥 Device Wipe
$devices = Get-MgUserRegisteredDevice -UserId $userObj.Id

foreach ($device in $devices) {
    Invoke-MgDeviceManagementManagedDeviceWipe `
        -ManagedDeviceId $device.Id `
        -KeepEnrollmentData:$false `
        -KeepUserData:$false
}
Result:
Device wiped
Data removed
Access blocked
🔹 STEP 10 — MONITORING
Check:

👉 Intune → Devices
👉 Reports

Look for:

Compliance failures
App failures
Enrollment issues