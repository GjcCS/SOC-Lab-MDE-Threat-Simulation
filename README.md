[README.md](https://github.com/user-attachments/files/29555841/README.md)
# 🛡️ SOC Home Lab — Threat Simulation & Detection with Microsoft Defender for Endpoint

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Defender](https://img.shields.io/badge/Microsoft%20Defender-00A4EF?style=for-the-badge&logo=microsoftdefender&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows%2011-0067B8?style=for-the-badge&logo=windows11&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Advanced%20Hunting-purple?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)

---

## 📋 Project Overview

This project documents the design and implementation of a **cloud-based SOC home lab** built on Microsoft Azure, used to simulate, detect, and investigate real cyberattack scenarios using **Microsoft Defender for Endpoint (MDE)**.

### Objectives

- Deploy and configure a cloud VM with MDE onboarding via Microsoft Defender for Cloud
- Simulate three real-world attack techniques mapped to the MITRE ATT&CK framework
- Generate and analyze real security incidents in the Microsoft Defender portal
- Write and validate KQL (Kusto Query Language) detection queries in Advanced Hunting
- Document the full incident response lifecycle: detection → investigation → remediation

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AZURE CLOUD ENVIRONMENT                      │
│                                                                 │
│  Resource Group: RG-SOC-Lab                                     │
│  ┌─────────────────────────────────────┐                        │
│  │   VM: vm-soc-lab-01                 │                        │
│  │   OS: Windows 11 Pro (10.0.26xxx)   │                        │
│  │   Size: Standard_B2s                │                        │
│  │   IP: 10.0.0.4 (Private)           │                        │
│  │                                     │                        │
│  │   ┌─────────────────────────────┐   │                        │
│  │   │  MDE Sensor (MsSense.exe)   │   │                        │
│  │   │  Status: Onboarded ✅       │   │                        │
│  │   └────────────┬────────────────┘   │                        │
│  └────────────────│────────────────────┘                        │
│                   │ HTTPS :443 (Telemetry)                      │
│                   ▼                                             │
│  ┌─────────────────────────────────────┐                        │
│  │  Microsoft Defender for Cloud       │                        │
│  │  Defender for Servers Plan 2        │                        │
│  └────────────────┬────────────────────┘                        │
└───────────────────│─────────────────────────────────────────────┘
                    │
                    ▼
     security.microsoft.com
  ┌─────────────────────────────────────┐
  │  Microsoft 365 Defender Portal      │
  │                                     │
  │  • Incidents & Alerts               │
  │  • Advanced Hunting (KQL)           │
  │  • Device Timeline                  │
  │  • Automated Investigation          │
  │  • MITRE ATT&CK Mapping             │
  └─────────────────────────────────────┘
```

### Tech Stack

| Component | Technology |
|---|---|
| Cloud Platform | Microsoft Azure |
| Target OS | Windows 11 Pro (Build 26xxx) |
| Security Platform | Microsoft Defender for Endpoint Plan 2 |
| Cloud Security | Microsoft Defender for Cloud (Servers Plan 2) |
| Detection Language | KQL — Kusto Query Language |
| Attack Framework | MITRE ATT&CK v14 |
| VM Size | Standard_B2s (2 vCPU, 4 GB RAM) |

---

## ⚔️ Attack Scenarios

### Attack #1 — Brute Force Attack

| Field | Detail |
|---|---|
| **MITRE Tactic** | TA0006 — Credential Access |
| **MITRE Technique** | T1110 — Brute Force |
| **Sub-technique** | T1110.001 — Password Guessing |
| **Target** | Local user account `TargetUser_BF` |
| **Method** | Repeated WMI authentication failures via PowerShell |
| **Key Events** | Windows Event ID 4625 (Logon Failure) |
| **MDE Table** | `DeviceLogonEvents` |
| **ActionType** | `LogonFailed` |

**What was simulated:** Multiple consecutive failed authentication attempts against a local user account, generating a pattern consistent with automated password guessing tools like Hydra or Medusa.

**Detection validated:** Telemetry confirmed in `DeviceLogonEvents` with 15+ `LogonFailed` events targeting `targetuser` within a 2-minute window.

---

### Attack #2 — Local Privilege Escalation

| Field | Detail |
|---|---|
| **MITRE Tactic** | TA0004 — Privilege Escalation / TA0003 — Persistence |
| **MITRE Technique** | T1098 — Account Manipulation |
| **Sub-technique** | T1098.001 — Additional Local Groups |
| **Method** | Created non-privileged user and added to local Administrators group |
| **Key Events** | Event ID 4720 (Account Created), Event ID 4732 (Member Added to Group) |
| **MDE Table** | `DeviceEvents` |
| **ActionType** | `UserAccountCreated`, `UserAccountAddedToLocalGroup` |

**What was simulated:** A threat actor who gained initial access creates a backdoor local admin account to maintain persistent elevated access — a common post-exploitation technique.

**Detection validated:** `UserAccountAddedToLocalGroup` (3 events) and `UserAccountCreated` (2 events) confirmed in `DeviceEvents`.

---

### Attack #3 — Obfuscated PowerShell + Registry Persistence

| Field | Detail |
|---|---|
| **MITRE Tactic** | TA0005 — Defense Evasion / TA0002 — Execution / TA0003 — Persistence |
| **MITRE Technique** | T1059.001 — PowerShell, T1547.001 — Registry Run Keys, T1027 — Obfuscation |
| **Sub-technique** | T1564.003 — Hidden Window |
| **Method** | Base64-encoded PowerShell with evasion flags + HKCU Run key modification |
| **Key Events** | Event ID 4688 (Process Creation), Event ID 4104 (Script Block Logging) |
| **MDE Tables** | `DeviceProcessEvents`, `DeviceRegistryEvents` |
| **Alert Generated** | 🟠 **"Anomaly detected in ASEP registry"** — Severity: Medium |

**What was simulated:** Attacker executes a Base64-encoded PowerShell payload using `-EncodedCommand -WindowStyle Hidden -ExecutionPolicy Bypass` flags, then establishes persistence by writing a disguised entry to the Windows Registry Run key (ASEP — Auto-Start Extensibility Point).

**Detection validated:** Portal generated a **Medium severity alert** with full Process Tree showing the attack chain: `powershell.exe → powershell.exe → reg.exe → HKCU\Run modification`.

---

## 🔍 Incidents & Alerts Generated

| Alert | Severity | Category | Status | Technique |
|---|---|---|---|---|
| Anomaly detected in ASEP registry | 🟠 Medium | Defense Evasion, Privilege Escalation | New | T1547.001 |
| 'EICAR_Test_File' malware was prevented | ⬜ Informational | Malware | Resolved | — |

**Process Tree captured (Attack #3):**
```
6/30/2026 6:25 PM
└── powershell.exe [PID 10948]
        │
        7:09 PM — Remote execution
        └── powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden
                │
        7/1/2026 12:42 AM — Remote execution
                └── powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden
                        │
                12:54 AM — Remote execution
                        └── reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                                │
                        12:54 AM
                                └── ⚡ ALERT: Anomaly detected in ASEP registry [MEDIUM]
```

---

## 📊 Telemetry Confirmed (Advanced Hunting)

Data confirmed across all 4 MDE tables within 24 hours of attack execution:

| MDE Table | Events Captured | Attack Covered |
|---|---|---|
| `DeviceNetworkEvents` | 434 | Network reconnaissance |
| `DeviceProcessEvents` | 228 | PowerShell execution chain |
| `DeviceEvents` | 225 | Account manipulation, Antivirus |
| `DeviceLogonEvents` | 40 | Brute force attempts |

---

## 🔎 KQL Detection Queries

All queries validated in Microsoft Defender Advanced Hunting.

### Query 1 — Brute Force Detection

```kql
DeviceLogonEvents
| where DeviceName == "vm-soc-lab-01"
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| summarize 
    TotalAttempts = count(),
    FirstAttempt  = min(Timestamp),
    LastAttempt   = max(Timestamp),
    UsersTried    = make_set(AccountName),
    SourceIPs     = make_set(RemoteIP)
    by RemoteIP, RemoteIPType
| where TotalAttempts >= 5
| extend AttackDuration = LastAttempt - FirstAttempt
| order by TotalAttempts desc
```

### Query 2 — Privilege Escalation Detection

```kql
DeviceEvents
| where DeviceName == "vm-soc-lab-01"
| where Timestamp > ago(24h)
| where ActionType in (
    "UserAccountAddedToLocalGroup",
    "UserAccountCreated",
    "UserAccountModified"
)
| project 
    Timestamp,
    ActionType,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp asc
```

### Query 3 — Obfuscated PowerShell Detection

```kql
DeviceProcessEvents
| where DeviceName == "vm-soc-lab-01"
| where Timestamp > ago(24h)
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any (
    "-EncodedCommand", "-enc ", "-NoExit",
    "-WindowStyle Hidden", "-ExecutionPolicy Bypass",
    "FromBase64String", "DownloadString",
    "DownloadFile", "IEX", "Invoke-Expression"
)
| project
    Timestamp,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc
```

### Query 4 — ASEP Registry Persistence Detection

```kql
DeviceRegistryEvents
| where DeviceName == "vm-soc-lab-01"
| where Timestamp > ago(24h)
| where RegistryKey has_any (
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
)
| project
    Timestamp,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc
```

### Query 5 — Unified Attack Timeline (All Scenarios)

```kql
let TimeRange = ago(24h);
let TargetDevice = "vm-soc-lab-01";

let BruteForce = DeviceLogonEvents
| where DeviceName == TargetDevice and Timestamp > TimeRange
| where ActionType == "LogonFailed"
| project Timestamp, Category = "BruteForce",
    Detail = strcat("LogonFailed: ", AccountName, " from ", RemoteIP),
    Process = "lsass.exe";

let PrivEsc = DeviceEvents
| where DeviceName == TargetDevice and Timestamp > TimeRange
| where ActionType in ("UserAccountCreated","UserAccountAddedToLocalGroup")
| project Timestamp, Category = "PrivilegeEscalation",
    Detail = strcat(ActionType, ": ", AccountName),
    Process = InitiatingProcessFileName;

let ObfPS = DeviceProcessEvents
| where DeviceName == TargetDevice and Timestamp > TimeRange
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand","-NoExit","-WindowStyle Hidden","Bypass")
| project Timestamp, Category = "ObfuscatedPowerShell",
    Detail = substring(ProcessCommandLine, 0, 100),
    Process = InitiatingProcessFileName;

let ASEPReg = DeviceRegistryEvents
| where DeviceName == TargetDevice and Timestamp > TimeRange
| where RegistryKey has "CurrentVersion\\Run"
| project Timestamp, Category = "ASEPPersistence",
    Detail = strcat(RegistryKey, " = ", RegistryValueData),
    Process = InitiatingProcessFileName;

union BruteForce, PrivEsc, ObfPS, ASEPReg
| order by Timestamp asc
| project Timestamp, Category, Process, Detail
```

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Simulated |
|---|---|---|---|
| T1110.001 | Password Guessing | Credential Access | ✅ |
| T1098.001 | Additional Local Groups | Privilege Escalation | ✅ |
| T1059.001 | PowerShell | Execution | ✅ |
| T1027 | Obfuscated Files or Information | Defense Evasion | ✅ |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | ✅ |
| T1564.003 | Hidden Window | Defense Evasion | ✅ |
| T1036 | Masquerading | Defense Evasion | ✅ |
| T1057 | Process Discovery | Discovery | ✅ |
| T1087.001 | Local Account Discovery | Discovery | ✅ |

---

## 📁 Repository Structure

```
soc-lab-mde-threat-simulation/
│
├── README.md
├── docs/
│   ├── 01-environment-setup.md
│   ├── 02-attack-simulation.md
│   ├── 03-detection-analysis.md
│   └── 04-cleanup.md
├── kql-queries/
│   ├── brute-force-detection.kql
│   ├── privesc-detection.kql
│   ├── obfuscated-ps-detection.kql
│   ├── asep-persistence-detection.kql
│   └── unified-attack-timeline.kql
└── screenshots/
    ├── 01-device-onboarded.png
    ├── 02-telemetry-tables.png
    ├── 03-alerts-list.png
    ├── 04-process-tree-attack-story.png
    ├── 05-asep-registry-alert.png
    └── 06-advanced-hunting-results.png
```

---

## 🎓 Key Learnings

- **MDE vs Sentinel schema:** `Timestamp` is used in MDE Advanced Hunting; `TimeGenerated` is Sentinel-specific — a critical distinction for SC-200
- **`withsource=` syntax:** Required for identifying source tables in `union` queries within MDE (not `$table` or `Type`)
- **Alert severity tiers:** Only Medium+ alerts automatically generate Incidents with Attack Story visualization
- **EICAR behavior:** Defender handles EICAR entirely offline due to its known signature — it generates `AntivirusDetection` telemetry but not a portal Incident
- **PassiveMode vs Active:** Azure VMs can be placed in Defender passive mode by Defender for Cloud — understanding this distinction is essential for troubleshooting
- **ASEP Registry as detection signal:** Modifications to `HKCU\...\CurrentVersion\Run` using PowerShell child processes generate reliable Medium-severity alerts even in a lab environment

---

## 🔧 Prerequisites to Reproduce

- Microsoft Azure subscription (Pay-as-you-go or Free Trial)
- Microsoft 365 Developer tenant (free, includes MDE Plan 2) — [developer.microsoft.com](https://developer.microsoft.com/microsoft-365/dev-program)
- Access to `security.microsoft.com`
- Windows 11 VM (Standard_B2s minimum)

---

## ⚠️ Disclaimer

All attack simulations in this lab were performed in a **controlled, isolated environment** owned and managed by the author. No production systems, networks, or third-party infrastructure were involved. This project is intended solely for educational purposes and cybersecurity skill development.

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com)
