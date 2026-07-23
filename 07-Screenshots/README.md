# Screenshots

Required screenshots for project documentation. Replace placeholders with actual captures.

## Phase 1 — Identity & Device Foundation

| # | Filename | Description | Script |
|---|----------|-------------|--------|
| 1 | `01-dynamic-groups-azure-portal.png` | Azure Portal > Groups > Dynamic groups list | 01 |
| 2 | `01-dynamic-group-rule.png` | Dynamic membership rule syntax | 01 |
| 3 | `01-break-glass-accounts.png` | Break-glass accounts in Users list | 01 |
| 4 | `02-jml-csv-import.png` | PowerShell terminal showing JML CSV import | 02 |
| 5 | `03-license-assignment.png` | License assignment output in terminal | 03 |
| 6 | `04-ca-policies-list.png` | Azure Portal > Conditional Access > Policies | 04 |
| 7 | `04-ca-policy-detail.png` | Single CA policy configuration detail | 04 |
| 8 | `05-ca-enabled-state.png` | All policies showing "Enabled" state | 05 |
| 9 | `06-intune-compliance.png` | Intune Portal > Device compliance policies | 06 |
| 10 | `07-intune-config-profiles.png` | Intune Portal > Device configuration | 07 |
| 11 | `08-autopilot-profiles.png` | Intune > Device enrollment > Windows | 08 |
| 12 | `09-sharepoint-site.png` | SharePoint site with Zero Trust settings | 09 |
| 13 | `10-onedrive-kfm.png` | OneDrive KFM policy in Intune | 10 |
| 14 | `11-pim-role-assignments.png` | PIM > Azure AD roles > Assignments | 11 |
| 15 | `12-dlp-policies.png` | Microsoft Purview > Data loss prevention | 12 |
| 16 | `13-defender-office365.png` | Defender for Office 365 settings | 13 |
| 17 | `14-defender-edr.png` | Defender for Endpoint EDR settings | 14 |
| 18 | `15-windows-update-rings.png` | Intune > Windows update rings | 15 |
| 19 | `16-backup-policies.png` | M365 Backup policies (if configured) | 16 |
| 20 | `17-named-locations.png` | Azure AD > Named locations | 17 |
| 21 | `18-audit-log-config.png` | Microsoft Purview > Audit > Settings | 18 |
| 22 | `19-mobile-access-policy.png` | Intune > App protection policies | 19 |

## Phase 2 — Application Access

| # | Filename | Description | Script |
|---|----------|-------------|--------|
| 23 | `20-app-proxy-config.png` | Entra > Application proxy overview | 20 |
| 24 | `21-sharepoint-secure.png` | SharePoint secure access configuration | 21 |
| 25 | `22-phase2-ca-policies.png` | Phase 2 CA policies list | 22 |
| 26 | `23-phase2-ca-enabled.png` | Phase 2 policies in Enabled state | 23 |

## Phase 3 — Security Monitoring

| # | Filename | Description | Script |
|---|----------|-------------|--------|
| 27 | `24-sentinel-workspace.png` | Azure Portal > Sentinel workspace | 24 |
| 28 | `25-data-connectors.png` | Sentinel > Data connectors | 25 |
| 29 | `26-analytics-rules.png` | Sentinel > Analytics > Rules | 26 |
| 30 | `27-playbooks.png` | Sentinel > Automation > Playbooks | 27 |
| 31 | `28-workbooks.png` | Sentinel > Workbooks | 28 |

## Architecture

| # | Filename | Description |
|---|----------|-------------|
| 32 | `architecture-3phase.png` | 3-phase implementation diagram |
| 33 | `architecture-overview.png` | Full Zero Trust architecture |

## How to capture

```powershell
# Run any script with -WhatIf to get terminal output
.\01.\ Create Dynamic Groups with department rule.ps1 -WhatIf

# Capture Azure portal screens with Win+Shift+S or Snipping Tool
# Save to this folder with the filenames listed above
```
