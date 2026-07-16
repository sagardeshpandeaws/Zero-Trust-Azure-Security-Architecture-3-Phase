# Architecture Diagrams

> Visual reference for the 3-phase Zero Trust architecture. See [Enterprise Zero Trust Architecture 3 Phase Project.md](Enterprise%20Zero%20Trust%20Architecture%203%20Phase%20Project.md) for narrative details, security controls, and deployment timeline.

---

## End-to-End Architecture

```mermaid
graph TB
    subgraph "PHASE 1 — Identity & Device Trust"
        direction TB
        U[Users] --> DG[18 Dynamic Groups]
        DG --> GL[Group-Based Licensing]
        GL --> JML[JML Automation]
        JML --> CA1[11 Conditional Access Policies]
        CA1 --> IC[Intune Compliance]
        IC --> CP[Configuration Profiles]
        CP --> AP[Autopilot Deployment]
    end

    subgraph "PHASE 2 — Secure Application Access"
        direction TB
        AZVM[Azure VM - Internal App] --> APC[App Proxy Connector]
        APC --> EID[Entra ID Authentication]
        EID --> CA2[Risk-Adaptive CA Policies]
        CA2 --> DFE[Defender for Endpoint]
        DFE --> DFCA[Defender for Cloud Apps]
        DFCA --> CAE[Continuous Access Evaluation]
    end

    subgraph "PHASE 3 — SOC & Threat Detection"
        direction TB
        SL[SigninLogs] --> LA[Log Analytics Workspace]
        AL[AuditLogs] --> LA
        SE[SecurityEvent] --> LA
        DE[DeviceEvents] --> LA
        LA --> SENT[Microsoft Sentinel]
        SENT --> KQL[KQL Detection Rules]
        KQL --> IR[Incident Response]
    end

    AP --> AZVM
    CAE --> SL

    style U fill:#4A90D9,stroke:#357ABD,color:#fff
    style AZVM fill:#4A90D9,stroke:#357ABD,color:#fff
    style SENT fill:#4A90D9,stroke:#357ABD,color:#fff
```

---

## Phase 1 — Identity & Device Trust

### Component Flow

```mermaid
graph LR
    subgraph "Identity"
        BG[Break-Glass Accounts] --> DG[18 Dynamic Groups]
        DG --> L[Group Licensing]
    end

    subgraph "JML Lifecycle"
        CSV[Users.csv] --> J[Joiner]
        CSV --> M[Mover]
        CSV --> V[Leaver]
        J --> DG
        M --> DG
        V --> DG
    end

    subgraph "Conditional Access"
        DG --> CA[11 CA Policies]
        CA --> MFA[MFA Enforcement]
        CA --> FIDO2[FIDO2 Phishing-Resistant]
        CA --> GEO[Geo Blocking]
        CA --> COMP[Compliant Device]
    end

    subgraph "Intune"
        COMP --> POL[4 Compliance Policies]
        POL --> PROF[5 Config Profiles]
        PROF --> ASR[ASR Rules]
        PROF --> BL[BitLocker]
        PROF --> USB[USB Restrictions]
        POL --> AUTO[Autopilot]
    end

    subgraph "Phase 1 Extended"
        CA --> SP[SharePoint Zero Trust]
        CA --> PIM[Privileged Identity Mgmt]
        CA --> DLP[DLP + Sensitivity Labels]
        CA --> DEF[Defender O365 + EDR]
        AUTO --> UPD[Windows Update Rings]
        CA --> BC[Backup + BCDR]
        CA --> GEO2[Named Locations + Geo]
        CA --> AUD[Audit + Logging]
        CA --> MOB[Mobile Access Control]
    end

    style BG fill:#E74C3C,stroke:#C0392B,color:#fff
    style CA fill:#F39C12,stroke:#E67E22,color:#fff
    style SENT fill:#2ECC71,stroke:#27AE60,color:#fff
```

### Conditional Access Policy Matrix

| # | Policy | Action | Scope |
|---|--------|--------|-------|
| 1 | Require MFA | Block if no MFA | All users |
| 2 | Block Legacy Auth | Block | All users |
| 3 | Require Compliant Device | MFA + Compliant | All users |
| 4 | Sign-in Risk (Medium/High) | MFA | All users |
| 5 | User Risk (High) | Password Change | All users |
| 6 | Admin Protection | MFA + Compliant + FIDO2 | 6 admin roles |
| 7 | Block Untrusted Locations | Block | All users |
| 8 | SharePoint Zero Trust Access | Compliant + Joined | All users |
| 9 | Admin FIDO2 Protection | FIDO2 Only | 6 admin roles |
| 10 | Country Restriction | Block untrusted | All users |
| 11 | Session Control | 1-hour re-auth | All users |

### Intune Compliance Policies

| Policy | Platform | Key Settings |
|--------|----------|-------------|
| COMP-WIN-01 | Windows 10/11 | BitLocker, Secure Boot, Defender, Min OS 19041 |
| COMP-WIN-02 | Windows 10/11 | 12-char password, 90-day expiry, 5 history |
| COMP-MOB-01 | Android | Encryption, Jailbreak detect, Min OS 10 |
| COMP-MOB-02 | iOS | Passcode, Jailbreak detect, Min OS 16 |

### Intune Configuration Profiles

| Profile | Setting Area | Key Controls |
|---------|-------------|-------------|
| CFG-WIN-01 | Defender + Firewall | Real-time protection, ASR rules, IPSec |
| CFG-WIN-02 | USB + Bluetooth | Block storage, clipboard control |
| CFG-WIN-03 | Lock Screen + Password | 12-char, biometric, lockout |
| CFG-WIN-04 | Device Restrictions | Block Control Panel, power options |
| CFG-WIN-05 | BitLocker Encryption | AES-256, TPM, recovery key |

### Autopilot Deployment Flow

```mermaid
sequenceDiagram
    participant User
    participant Intune
    participant Device
    
    Device->>Intune: Hardware Hash Upload
    Intune->>Intune: Assign Autopilot Profile
    Note over Intune: User-Driven AAD Join
    Device->>Device: First Boot
    Device->>Intune: Auto-Enroll
    Intune->>Intune: Compliance Check
    Intune->>Intune: Apply Config Profiles
    User->>Device: Sign In
    User->>Intune: Access Granted
```

---

## Phase 2 — Secure Application Access

### Application Proxy Architecture

```mermaid
graph LR
    subgraph "External"
        U[User Device] -->|Internet| EP[Entra ID]
    end

    subgraph "Entra ID"
        EP --> CA[Risk-Adaptive CA]
        CA --> MFA[MFA]
        CA --> COMP[Compliance Check]
        CA --> RISK[Device Risk Check]
    end

    subgraph "Internal Network"
        EP -->|Pre-Auth| PP[App Proxy]
        PP --> APP[Internal Web App]
    end

    subgraph "Security Integration"
        RISK --> DFE[Defender for Endpoint]
        DFE --> MCAS[Defender for Cloud Apps]
    end

    style EP fill:#4A90D9,stroke:#357ABD,color:#fff
    style PP fill:#2ECC71,stroke:#27AE60,color:#fff
```

### Risk-Adaptive Access Flow

```mermaid
sequenceDiagram
    participant User
    participant EntraID
    participant Defender
    participant AppProxy
    participant InternalApp
    
    User->>EntraID: Access App URL
    EntraID->>EntraID: Evaluate CA Policy
    EntraID->>Defender: Check Device Risk
    Defender-->>EntraID: Low/Medium/High Risk
    alt Risk = Low + Compliant
        EntraID->>AppProxy: Allow Access
        AppProxy->>InternalApp: Forward Request
        InternalApp-->>User: Access Granted
    else Risk = High
        EntraID-->>User: Access Denied
    else Risk = Medium
        EntraID->>User: Require MFA
        User->>EntraID: MFA Complete
        EntraID->>AppProxy: Allow Access
    end
```

---

## Phase 3 — SOC & Threat Detection

### Sentinel Architecture

```mermaid
graph TB
    subgraph "Data Sources"
        SL[SigninLogs]
        AL[AuditLogs]
        SE[SecurityEvent]
        DE[DeviceEvents]
        EE[EmailEvents]
        NE[NetworkEvents]
    end

    subgraph "Log Analytics Workspace"
        SL --> LA
        AL --> LA
        SE --> LA
        DE --> LA
        EE --> LA
        NE --> LA
    end

    subgraph "Microsoft Sentinel"
        LA --> SENT
        SENT --> KQL[KQL Detection Rules]
        SENT --> WB[Workbooks]
        SENT --> PB[Playbooks - SOAR]
        SENT --> TI[Threat Intelligence]
        SENT --> INV[Incident Investigation]
    end

    subgraph "Response"
        KQL --> INC[Incidents]
        PB --> AUTO[Auto-Response]
        TI --> MATCH[TI Matching]
        INV --> HUNT[Threat Hunting]
    end

    style SENT fill:#4A90D9,stroke:#357ABD,color:#fff
    style LA fill:#2ECC71,stroke:#27AE60,color:#fff
```

### Data Connector Coverage

| Connector | Log Types | Purpose |
|-----------|-----------|---------|
| Entra ID | SigninLogs, AuditLogs | Authentication & admin activity |
| M365 | Exchange, SharePoint, Teams | Email & collaboration data |
| Defender for Endpoint | DeviceEvents, DeviceLogonEvents | Endpoint detection |
| Intune | DeviceCompliance, DeviceConfig | Device management |
| Defender for Cloud Apps | CloudAppEvents | Shadow IT & SaaS |

### SOAR Playbook Triggers

```mermaid
graph LR
    subgraph "Sentinel Alerts"
        A1[High Risk Sign-in]
        A2[Impossible Travel]
        A3[Privilege Escalation]
        A4[Malware Detected]
        A5[Brute Force]
    end

    subgraph "Auto-Triggered Playbooks"
        A1 --> PB1[Force Password Reset]
        A2 --> PB2[Disable Account]
        A3 --> PB3[Isolate Endpoint]
        A5 --> PB1
    end

    subgraph "Manual/Alert-Triggered"
        A4 --> PB4[Notify SOC Team]
        A1 --> PB4
        A3 --> PB4
    end

    style A1 fill:#E74C3C,stroke:#C0392B,color:#fff
    style A2 fill:#E74C3C,stroke:#C0392B,color:#fff
    style A3 fill:#E74C3C,stroke:#C0392B,color:#fff
    style A4 fill:#E74C3C,stroke:#C0392B,color:#fff
    style A5 fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

## End-to-End Access Flow

```mermaid
sequenceDiagram
    participant User
    participant EntraID as Entra ID
    participant Defender
    participant Intune
    participant AppProxy as App Proxy
    participant Sentinel
    participant App as Internal App
    
    User->>EntraID: 1. Access URL
    EntraID->>EntraID: 2. Evaluate CA Policies
    EntraID->>Intune: 3. Check Device Compliance
    Intune-->>EntraID: Compliant / Not
    EntraID->>Defender: 4. Check Device Risk
    Defender-->>EntraID: Low / Medium / High
    EntraID->>Sentinel: 5. Log Sign-in Event
    
    alt All Conditions Met
        EntraID->>User: 6. MFA Challenge
        User->>EntraID: 7. MFA Complete
        EntraID->>AppProxy: 8. Pre-Auth Token
        AppProxy->>App: 9. Forward Request
        App-->>User: 10. Access Granted
    else Condition Failed
        EntraID-->>User: Access Denied
    end
    
    Sentinel->>Sentinel: 11. Analytics Rules Evaluate
    alt Anomaly Detected
        Sentinel->>Sentinel: 12. Create Incident
        Sentinel->>Sentinel: 13. Trigger Playbook
    end
```

---

## Deployment Sequence

```mermaid
gantt
    title 6-Week Deployment Timeline
    dateFormat  YYYY-MM-DD
    section Phase 1 - Identity
    Dynamic Groups (Script 1)           :a1, 2024-01-01, 1d
    JML Automation (Script 2)           :a2, after a1, 2d
    License Assignment (Script 3)       :a3, after a1, 1d
    CA Policies (Script 4)              :a4, after a3, 2d
    Enable CA (Script 5)                :a5, after a4, 1d
    section Phase 1 - Device
    Intune Compliance (Script 6)        :b1, after a5, 2d
    Config Profiles (Script 7)          :b2, after b1, 2d
    Autopilot (Script 8)                :b3, after b2, 1d
    section Phase 1 - Extended
    SharePoint ZT (Script 9)            :c1, after b3, 1d
    OneDrive (Script 10)                :c2, after b3, 1d
    PIM (Script 11)                     :c3, after b3, 1d
    DLP (Script 12)                     :c4, after b3, 1d
    Defender O365 (Script 13)           :c5, after b3, 1d
    Defender EDR (Script 14)            :c6, after b3, 1d
    Update Rings (Script 15)            :c7, after b3, 1d
    Backup BCDR (Script 16)             :c8, after b3, 1d
    Geo Controls (Script 17)            :c9, after b3, 1d
    Audit Logging (Script 18)           :c10, after b3, 1d
    Mobile Access (Script 19)           :c11, after b3, 1d
    section Phase 2
    App Proxy (Script 20)               :d1, after c11, 2d
    SharePoint Secure (Script 21)       :d2, after d1, 2d
    Risk-Adaptive CA (Script 22)        :d3, after d2, 2d
    Enable Phase 2 (Script 23)          :d4, after d3, 1d
    section Phase 3
    Sentinel Setup (Script 24)          :e1, after d4, 2d
    Data Connectors (Script 25)         :e2, after e1, 1d
    Analytics Rules (Script 26)         :e3, after e2, 2d
    Playbooks (Script 27)               :e4, after e3, 2d
    Workbooks (Script 28)               :e5, after e4, 1d
    Threat Hunting (Script 29)          :e6, after e5, 1d
    Investigation (Script 30)           :e7, after e6, 1d
    TI Integration (Script 31)          :e8, after e7, 1d
```
