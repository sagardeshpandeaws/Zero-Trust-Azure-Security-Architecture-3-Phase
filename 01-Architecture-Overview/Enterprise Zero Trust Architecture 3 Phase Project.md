# Enterprise Zero Trust Architecture — 3 Phase Implementation

> For visual diagrams and Mermaid flows, see [Architecture Diagram.md](Architecture%20Diagram.md).

---

## Executive Summary

A complete Zero Trust security architecture across three deployment phases, covering identity, device, network, application, and SOC layers. Fully automated with PowerShell + Microsoft Graph API — **31 scripts**, **20 automation modules**, **zero manual steps** for day-to-day operations.

| Metric | Value |
|--------|-------|
| Total Scripts | 31 |
| Phase 1 Scripts | 19 (Identity & Device Trust) |
| Phase 2 Scripts | 4 (Secure Application Access) |
| Phase 3 Scripts | 8 (SOC & Threat Detection) |
| Conditional Access Policies | 11 |
| Intune Compliance Policies | 4 |
| Intune Config Profiles | 5 |
| Dynamic Groups | 18 + Break-Glass |
| SOAR Playbooks | 4 |
| KQL Detection Rules | 30+ |
| Workbooks | 6 |

---

## Zero Trust Principles Applied

| Principle | Implementation |
|-----------|---------------|
| **Verify Explicitly** | Conditional Access policies validate user, device, location, and risk |
| **Use Least Privilege** | Dynamic groups + role-based access, PIM JIT activation, no standing admin |
| **Assume Breach** | Sentinel SIEM, KQL detection rules, automated incident response, TI feeds |
| **Never Trust, Always Verify** | Device compliance required for all cloud app access |
| **Segment Access** | Department-based dynamic groups, per-app access policies |
| **Encrypt Everything** | BitLocker (AES-256), TLS 1.2+, sensitivity labels |
| **Monitor Continuously** | Unified Audit Log, Sentinel analytics, threat hunting, TI matching |

---

## Phase 1 — Identity & Device Trust (Scripts 1–19)

### JML Lifecycle Flow

| Stage | Action | Script |
|-------|--------|--------|
| **Joiner (Day 1)** | Create user, set manager, generate TAP, assign to dynamic group | Script 2 |
| **Joiner (Day 1)** | Auto-assign group-based license | Script 3 |
| **Joiner (Day 1)** | Autopilot provisions device, applies compliance + config profiles | Script 8 |
| **Mover** | Update profile, dynamic groups auto-reassign, Intune policies update | Script 2 |
| **Leaver** | Disable → Revoke sessions → Wipe Intune → Unlicense → Remove manager → Delete | Script 2 |

### Conditional Access Policy Summary

| # | Policy | Action | Scope | Script |
|---|--------|--------|-------|--------|
| 1 | Require MFA | Block if no MFA | All users | Script 4 |
| 2 | Block Legacy Auth | Block | All users | Script 4 |
| 3 | Require Compliant Device | MFA + Compliant | All users | Script 4 |
| 4 | Sign-in Risk (Medium/High) | MFA | All users | Script 4 |
| 5 | User Risk (High) | Password Change | All users | Script 4 |
| 6 | Admin Protection | MFA + Compliant + FIDO2 | 6 admin roles | Script 4 |
| 7 | Block Untrusted Locations | Block | All users | Script 4 |
| 8 | SharePoint Zero Trust Access | Compliant + Joined | All users | Script 4 |
| 9 | Admin FIDO2 Protection | FIDO2 Only | 6 admin roles | Script 4 |
| 10 | Country Restriction | Block untrusted | All users | Script 4 |
| 11 | Session Control | 1-hour re-auth | All users | Script 4 |

### Phase 1 Extended Controls

| Script | Control | Tool | Key Features |
|--------|---------|------|-------------|
| 9 | SharePoint Zero Trust | SharePoint Online | External sharing disabled, audit logging, version history |
| 10 | OneDrive Auto-Mapping | Intune + Entra | Silent sign-in, compliance-gated file sync |
| 11 | Privileged Identity Management | Entra ID PIM | JIT activation, approval, MFA, 8-hour max |
| 12 | DLP + Sensitivity Labels | Microsoft Purview | PAN/Aadhaar detection, 4 label levels |
| 13 | Defender for Office 365 | Microsoft Defender | Anti-phishing, Safe Links, Safe Attachments |
| 14 | Defender for Endpoint EDR | Microsoft Defender | EDR block mode, AIR, ransomware rollback |
| 15 | Windows Update Rings | Windows Update for Business | Pilot/Production/Emergency ring strategy |
| 16 | M365 Backup + BCDR | Microsoft 365 Backup | RPO 24h, RTO 4-8h, restore testing |
| 17 | Named Locations + Geo | Entra ID CA | Country block, TOR block, trusted locations |
| 18 | Audit + Logging | M365 Unified Audit Log | 90-day retention, admin activity alerts |
| 19 | Mobile Access Control | Intune MAM | Block mobile default, app protection policies |

---

## Phase 2 — Secure Application Access (Scripts 20–23)

### Application Proxy Architecture

```
Internal Azure VM (no public IP)
    │
    ▼
Entra App Proxy Connector (on-premises agent)
    │
    ▼
Entra ID Authentication + Risk-Adaptive CA
    │
    ├──▶ Device Compliance Check (Intune)
    ├──▶ Device Risk Check (Defender for Endpoint)
    ├──▶ Sign-in Risk Check (Entra ID Protection)
    └──▶ Location Risk Check (Geo Controls)
```

### Phase 2 Scripts

| Script | Control | Tool | Key Features |
|--------|---------|------|-------------|
| 20 | App Proxy Setup | Entra App Proxy | Pre-auth = Azure AD, connector group, custom domain |
| 21 | SharePoint Secure Access | SharePoint + Intune | Sharing restrictions, device access, session policies |
| 22 | Risk-Adaptive CA | Entra ID + Defender | 6 CA policies scoped to App Proxy app, device risk levels |
| 23 | Enable Phase 2 CA | Entra ID | Transition report-only → enforced, filtered to CA-Phase2* |

### Risk-Adaptive CA Policy Summary

| # | Policy | Trigger | Action | Scope |
|---|--------|---------|--------|-------|
| 1 | App Proxy Block Legacy | Legacy auth | Block | App Proxy app |
| 2 | App Proxy Require MFA | All access | MFA + Compliant | App Proxy app |
| 3 | App Proxy Risk MFA | Medium risk sign-in | MFA | App Proxy app |
| 4 | App Proxy High Risk Block | High risk sign-in | Block | App Proxy app |
| 5 | App Proxy Session Control | All access | 1-hour re-auth | App Proxy app |
| 6 | App Proxy Device Risk Block | High device risk | Block | App Proxy app |

---

## Phase 3 — SOC & Threat Detection (Scripts 24–31)

### Data Flow

```
Data Sources → Log Analytics Workspace → Microsoft Sentinel
                                            │
                    ┌───────────┬────────────┼────────────┬──────────┐
                    ▼           ▼            ▼            ▼          ▼
              KQL Rules    Workbooks    Playbooks      TI       Investigation
              (30+ rules)  (6 dash)    (4 SOAR)    Matching    (21 KQL queries)
                    │           │            │            │          │
                    ▼           ▼            ▼            ▼          ▼
              Incidents    Visibility   Auto-Response  Enrich    Hunt Proactively
```

### Phase 3 Scripts

| Script | Control | Tool | Key Features |
|--------|---------|------|-------------|
| 24 | Sentinel Workspace | Log Analytics + Sentinel | 90-day retention, 30-day interactive |
| 25 | Data Connectors | Sentinel | Entra, M365, Defender, Intune, Cloud Apps (5 connectors) |
| 26 | Analytics Rules | Sentinel | Impossible travel, malware, risk, brute force (6 rules) |
| 27 | Deploy Playbooks | Sentinel + Logic Apps | Disable account, reset password, isolate endpoint, notify SOC |
| 28 | Create Workbooks | Sentinel | Auth, alerts, endpoints, CA, SOC, app access (6 dashboards) |
| 29 | Threat Hunting | KQL | Suspicious logins, lateral movement, data exfil, persistence |
| 30 | Incident Investigation | Sentinel | 8-step workbook, 21 KQL queries, MITRE-mapped |
| 31 | Threat Intelligence | Sentinel + TI | Microsoft TI, STIX/TAXII, 5 TI matching rules |

---

## Security Controls Matrix

| Layer | Control | Tool | Automation |
|-------|---------|------|------------|
| Identity | MFA | Entra ID + CA | Script 4 |
| Identity | Risk-based access | Entra ID Protection | Script 4, 22 |
| Identity | Break glass accounts | Entra ID Groups | Script 1 |
| Identity | FIDO2 phishing-resistant | Entra ID CA | Script 4 |
| Identity | Privileged access | PIM | Script 11 |
| Identity | JML automation | PowerShell + Graph | Script 2 |
| Device | Compliance check | Intune | Script 6 |
| Device | Configuration | Intune Profiles | Script 7 |
| Device | Zero-touch deploy | Autopilot | Script 8 |
| Device | Remote wipe | Intune | Script 2 |
| Device | ASR rules | Intune Profiles | Script 7 |
| Device | EDR + ransomware rollback | Defender for Endpoint | Script 14 |
| Device | Update rings | Windows Update | Script 15 |
| Application | App Proxy | Entra App Proxy | Script 20 |
| Application | SharePoint secure | Entra ID | Script 21, 9 |
| Application | Risk-adaptive CA | Entra ID + Defender | Script 22 |
| Application | OneDrive auto-sync | Intune + Entra | Script 10 |
| Application | Mobile app protection | Intune MAM | Script 19 |
| Data | BitLocker encryption | Intune | Script 7 |
| Data | USB restrictions | Intune | Script 7 |
| Data | DLP + sensitivity labels | Purview | Script 12 |
| Data | Backup + BCDR | M365 Backup | Script 16 |
| Network | Location-based | CA Policy | Script 4, 22, 17 |
| Network | Country + TOR blocking | CA Policy | Script 17 |
| Email | Anti-phishing | Defender for Office 365 | Script 13 |
| Email | Safe Links + Attachments | Defender for Office 365 | Script 13 |
| Patch | Update governance | Windows Update Rings | Script 15 |
| Audit | Unified Audit Log | M365 | Script 18 |
| SOC | SIEM monitoring | Sentinel | Script 24 |
| SOC | Data connectors | Sentinel | Script 25 |
| SOC | Threat detection | Analytics Rules | Script 26 |
| SOC | Incident response | SOAR Playbooks | Script 27 |
| SOC | Security dashboards | Workbooks | Script 28 |
| SOC | Threat hunting | KQL Queries | Script 29 |
| SOC | Incident investigation | Investigation Workbook | Script 30 |
| SOC | Threat intelligence | TI Integration | Script 31 |
| SOC | Detection rules | KQL Reference | 30+ Scenarios |

---

## Compliance & Standards

| Standard | Coverage |
|----------|----------|
| NIST SP 800-207 | Zero Trust Architecture principles |
| CISA Zero Trust Maturity | Identity, Device, Network, Application pillars |
| MITRE ATT&CK | 30+ detection rules mapped |
| CIS Controls | Device hardening, access control |
| ISO 27001 | Access management, monitoring |

---

## Deployment Timeline

```
WEEK 1-2                      WEEK 3-4                      WEEK 5-6
Phase 1 Core                  Phase 1 Extended              Phase 2 + 3
──────────────                ──────────────                ─────────────
Scripts 1-8                   Scripts 9-19                  Scripts 20-31
├── Dynamic Groups            ├── SharePoint ZT             ├── App Proxy
├── JML Automation            ├── OneDrive                 ├── SharePoint Secure
├── License Assignment        ├── PIM                      ├── Risk-Adaptive CA
├── CA Policies (11)          ├── DLP                      ├── Enable Phase 2
├── Enable CA                 ├── Defender O365             ├── Sentinel Setup
├── Intune Compliance         ├── Defender EDR              ├── Data Connectors
├── Config Profiles           ├── Update Rings              ├── Analytics Rules
├── Autopilot                 ├── Backup/BCDR              ├── Playbooks
└── Testing                   ├── Geo Controls             ├── Workbooks
                              ├── Audit/Logging            ├── Threat Hunting
                              └── Mobile Access            ├── Investigation
                                                           └── TI Integration
```

---

## Author

**Sagar Deshpande** — Cloud & Security Engineer
- LinkedIn: [sagardeshpandeaws](https://www.linkedin.com/in/sagar-deshpande-8793357387dsp/)
- GitHub: [sagardeshpandeaws](https://github.com/sagardeshpandeaws)
