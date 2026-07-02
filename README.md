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
- Write and validate 4 KQL detection queries in Advanced Hunting with confirmed results
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
│  │   IP: 10.0.0.4 (Private)            │                        │
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

**Results confirmed:** 40 failed logon attempts against `targetuser` over a 29-minute window (6:45 PM → 7:14 PM). Source IP `::1` (loopback) confirms controlled self-attack lab scenario.

![KQL Query 1 - Brute Force Results](https://raw.githubusercontent.com/GjcCS/SOC-Lab-MDE-Threat-Simulation/main/KQL-QUERIES/KQL-QUERY-1/KQL_QUERY_1.png)

---

### Attack #2 — Local Privilege Escalation

| Field | Detail |
|---|---|
| **MITRE Tactic** | TA0004 — Privilege Escalation / TA0003 — Persistence |
| **MITRE Technique** | T1098 — Account Manipulation |
| **Sub-technique** | T1098.001 — Additional Local Groups |
| **Method** | Created non-privileged users and added to local Administrators group |
| **Key Events** | Event ID 4720 (Account Created), Event ID 4732 (Member Added to Group) |
| **MDE Table** | `DeviceEvents` |
| **ActionType** | `UserAccountCreated`, `UserAccountAddedToLocalGroup` |

**What was simulated:** A threat actor who gained initial access creates backdoor local admin accounts to maintain persistent elevated access — a common post-exploitation technique.

**Results confirmed:** Two separate escalation chains detected and captured by MDE in `DeviceEvents`.

![KQL Query 2 - Privilege Escalation Results](https://raw.githubusercontent.com/GjcCS/SOC-Lab-MDE-Threat-Simulation/main/KQL-QUERIES/KQL-QUERY-2/KQL_QUERY_2.png)

---

### Attack #3 — Obfuscated PowerShell Execution

| Field | Detail |
|---|---|
| **MITRE Tactic** | TA0005 — Defense Evasion / TA0002 — Execution |
| **MITRE Technique** | T1059.001 — PowerShell / T1027 — Obfuscation |
| **Sub-technique** | T1564.003 — Hidden Window |
| **Method** | PowerShell with `-NoExit -ExecutionPolicy Bypass -WindowStyle Hidden` spawning child processes |
| **Key Events** | Event ID 4688 (Process Creation), Event ID 4104 (Script Block Logging) |
| **MDE Table** | `DeviceProcessEvents` |

**What was simulated:** Attacker executes PowerShell with evasion flags designed to bypass execution policy, hide the window, and suppress errors — consistent with living-off-the-land (LOtL) techniques.

**Results confirmed:** Multiple `powershell.exe → powershell.exe` child chains detected. Activity spanning Jun 30 7:09 PM through Jul 1 12:53 AM.

![KQL Query 3 - Obfuscated PowerShell Results](https://raw.githubusercontent.com/GjcCS/SOC-Lab-MDE-Threat-Simulation/main/KQL-QUERIES/KQL-QUERY-3/KQL_QUERY_3.png)

---

### Attack #4 — Registry Persistence (ASEP)

| Field | Detail |
|---|---|
| **MITRE Tactic** | TA0003 — Persistence / TA0005 — Defense Evasion |
| **MITRE Technique** | T1547.001 — Registry Run Keys / Startup Folder |
| **Related** | T1036 — Masquerading (entry disguised as "WindowsUpdate") |
| **Method** | `reg.exe` modified `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **MDE Table** | `DeviceRegistryEvents` |
| **Alert Generated** | 🟠 **"Anomaly detected in ASEP registry"** — Severity: **Medium** |

**What was simulated:** Attacker establishes persistence by writing a disguised Run key entry named `WindowsUpdate` pointing to a hidden PowerShell process — combining T1547.001 with T1036 masquerading.

**Results confirmed:** `RegistryValueSet` event captured at Jul 1 12:54 AM. Triggered a **Medium severity alert** in the Defender portal with full Process Tree visualization.

![KQL Query 4 - ASEP Registry Results](https://raw.githubusercontent.com/GjcCS/SOC-Lab-MDE-Threat-Simulation/main/KQL-QUERIES/KQL-QUERY-4/KQL_QUERY_4.png)

---

## 🚨 Incidents & Alerts Generated in Portal

| Alert | Severity | Category | Status | Technique |
|---|---|---|---|---|
| Anomaly detected in ASEP registry | 🟠 Medium | Defense Evasion, Privilege Escalation | Resolved | T1547.001 |
| 'EICAR_Test_File' malware was prevented | ⬜ Informational | Malware | Resolved | — |

### Process Tree — Attack Chain Visualization

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

**Portal Screenshots:**

![Alerts and Anomalies](INCIDENTS-AND-ALERTS/Alerts-and-Anomalies)
![Process Tree](INCIDENTS-AND-ALERTS/Process-Tree-Alerts)
![Device Onboarded](INCIDENTS-AND-ALERTS/Device-Onboarded)

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

All 4 queries validated in Microsoft Defender Advanced Hunting with confirmed results.

> **Critical SC-200 note:** MDE Advanced Hunting uses `Timestamp` — NOT `TimeGenerated` (that is Microsoft Sentinel). This distinction is tested on the exam.

### Query 1 — Brute Force Detection
> Table: `DeviceLogonEvents` | Technique: T1110.001

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
> Table: `DeviceEvents` | Technique: T1098.001

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
> Table: `DeviceProcessEvents` | Technique: T1059.001 + T1027

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
> Table: `DeviceRegistryEvents` | Technique: T1547.001

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

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Confirmed |
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
SOC-Lab-MDE-Threat-Simulation/
│
├── README.md
├── KQL-QUERY-1/               ← Brute Force query + results screenshot
├── KQL-QUERY-2/               ← Privilege Escalation query + results screenshot
├── KQL-QUERY-3/               ← Obfuscated PowerShell query + results screenshot
├── KQL-QUERY-4/               ← ASEP Registry query + results screenshot
└── INCIDENTS-AND-ALERTS/
    ├── alerts-and-anomalies/  ← Portal alerts list screenshot
    ├── alerts-resolved/       ← Resolved alerts screenshot
    ├── device-evidence/       ← Device evidence artifacts
    ├── device-onboarded/      ← MDE onboarding confirmation
    └── process-tree-alerts/   ← Attack chain Process Tree visualization
```

---

## 🎓 Key Learnings

- **MDE vs Sentinel schema:** `Timestamp` in MDE Advanced Hunting vs `TimeGenerated` in Sentinel — critical SC-200 distinction
- **`withsource=` syntax:** Required for identifying source tables in `union` queries in MDE — `$table` and `Type` do not work
- **Alert severity tiers:** Only Medium+ alerts automatically generate Incidents with Attack Story visualization — Informational alerts do not create Incidents
- **EICAR offline handling:** Defender processes EICAR entirely offline due to its known signature — generates `AntivirusDetection` telemetry but not a portal Incident
- **Defender PassiveMode:** Azure VMs can be placed in Defender passive mode by Defender for Cloud — understanding this is essential for troubleshooting missing alerts
- **ASEP Registry detection:** `HKCU\...\CurrentVersion\Run` modifications via PowerShell child processes reliably trigger Medium-severity alerts

---

## 🔧 Prerequisites to Reproduce

- Microsoft Azure subscription (Pay-as-you-go or Free Trial)
- Microsoft 365 Developer tenant — free 90-day renewable, includes MDE Plan 2 → [developer.microsoft.com](https://developer.microsoft.com/microsoft-365/dev-program)
- Access to `security.microsoft.com`
- Windows 11 VM (Standard_B2s minimum)

---

## ⚠️ Disclaimer

All attack simulations in this lab were performed in a **controlled, isolated environment** owned and managed by the author. No production systems, networks, or third-party infrastructure were involved. This project is intended solely for educational purposes and cybersecurity skill development.

---

## 👤 Author

**Guillermo Costa**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Guillermo%20Costa-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/guillermo-costa)
[![GitHub](https://img.shields.io/badge/GitHub-GjcCS-black?style=flat&logo=github)](https://github.com/GjcCS)
