# Elastic-Lab16-Lateral-Movement-Investigation
## Overview

Lateral movement is the stage of an intrusion where an attacker attempts to move from one compromised system to another system within an environment. The objective may be to access additional systems, obtain higher-value credentials, reach sensitive resources, or expand control across the network.

In Windows environments, lateral movement can involve techniques such as SMB/Windows Admin Shares, Remote Desktop Protocol (RDP), Windows Remote Management (WinRM), and remote service execution.

This lab investigates Windows network authentication activity associated with a potential lateral movement scenario.

The investigation focuses on SMB-based authentication and Windows Security Event ID 4625, particularly **Logon Type 3 (Network)**. A controlled SMB authentication attempt was generated against the local host using the Windows `net use` command with invalid credentials.

The objective was to determine what evidence was available in Windows Security logs and Elastic SIEM, while avoiding assumptions that a network authentication event automatically represents lateral movement.

> **Evidence principle:** Network authentication is not automatically proof of lateral movement. The investigation must establish the source, destination, account, authentication type, and supporting telemetry before making that determination.

---

## Lab Scenario

A SOC analyst is investigating activity that may be related to **Windows lateral movement through network authentication**. The investigation focuses on SMB authentication because attackers can use SMB and Windows administrative shares to access other systems after obtaining valid or compromised credentials.

The lab uses a controlled authentication attempt against the local Windows system rather than a real remote host. The following command is used with intentionally invalid credentials:

    net use \\localhost\IPC$ /user:FakeLabUser WrongPassword

The objective is to observe how Windows records the failed network authentication and determine what evidence is available in Elastic SIEM.

The investigation focuses on:

- Windows Security Event ID `4625` for failed logons.
- Logon Type `3`, which represents a network logon.
- The test account `FakeLabUser`.
- Available authentication and source information.
- Whether Elastic telemetry can directly identify TCP port `445`.
- Whether process telemetry is available to correlate the authentication attempt with the executed command.

Because the test uses `localhost`, it does **not** reproduce true host-to-host lateral movement. The investigation therefore evaluates the available evidence without treating the network authentication event itself as proof of lateral movement.

The final assessment should distinguish between **confirmed authentication evidence**, **potential SMB-related activity**, and **telemetry that could not be confirmed**.

---

## Lab Objectives

- Understand how SMB-based network authentication can be associated with lateral movement activity.
- Generate a controlled failed SMB authentication attempt using the Windows `IPC$` share.
- Identify and investigate Windows Security Event ID `4625`.
- Analyze **Logon Type 3 (Network)** and understand its relevance to SMB authentication.
- Investigate the test account, authentication details, and available source information.
- Search Elastic SIEM for evidence related to the controlled authentication activity.
- Investigate whether available Elastic telemetry can directly confirm TCP port `445`.
- Compare Windows Security log evidence with Elastic SIEM telemetry.
- Identify gaps in process and network telemetry during the investigation.
- Distinguish confirmed evidence from assumptions when assessing potential lateral movement.
  
---

## MITRE ATT&CK Context

This investigation is related to:

- **T1021.002 — SMB/Windows Admin Shares**
- **T1078 — Valid Accounts** as an investigative consideration

These techniques provide context for the investigation but do not by themselves establish that malicious lateral movement occurred.

---

## Environment

| Item | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| User | `desktop-9mmm37v\dell` |
| OS | Windows 11 |
| PowerShell | 7.6.6 |
| Elastic Agent | 9.5.4 |
| Security Log | Enabled |
| Test Target | `\\localhost\IPC$` |
| Test Account | `FakeLabUser` |
| Authentication Result | Failed |
| Windows Event ID | `4625` |
| Logon Type | `3` |

---

## Investigation Summary

The controlled SMB authentication attempt failed with Windows error `1326`.

Windows Security Event ID `4625` was then observed:

```text
05-10-2026 07:00:46
Event ID: 4625
Provider: Microsoft-Windows-Security-Auditing
```

Elastic also returned the corresponding event:

```text
event.code: 4625
user.name: FakeLabUser
winlog.event_data.LogonType: 3
host.name: desktop-9mmm37v
```

The presence of Logon Type `3` confirms that the event represents a network logon attempt.

However, the available Elastic data did not contain a usable `destination.port` field or network connection dataset. A search for the value `445` across available fields returned no matches.

Therefore, **TCP/445 was not independently confirmed in Elastic telemetry**.

---

## Key Findings

### Finding 1 — Controlled authentication failure generated Event 4625

The invalid SMB authentication attempt generated Windows Event ID `4625`.

This confirms that the authentication attempt reached Windows authentication processing and failed.

### Finding 2 — The event was a network logon

The Elastic event contained:

```text
LogonType: 3
```

Logon Type `3` represents a network logon.

This is consistent with the controlled SMB authentication scenario.

### Finding 3 — Port 445 could not be independently confirmed

The initial investigation attempted to identify network activity involving port `445`.

The environment did not provide a usable `destination.port` field or a network event dataset.

A wildcard search for `445` across available fields returned no results.

Therefore:

> The investigation established a network authentication event, but did not independently establish that TCP port 445 was observed in Elastic telemetry.

### Finding 4 — Process telemetry was unavailable

A search for:

```text
net.exe
powershell.exe
pwsh.exe
cmd.exe
```

returned zero documents.

Therefore, Elastic did not provide process telemetry linking the authentication event to the command execution.

This does not prove that the command was not executed. The local PowerShell session and Windows command output independently confirm that the test command was executed.

---

## Evidence Assessment

| Evidence | Result | Interpretation |
|---|---|---|
| `net use \\localhost\IPC$` | Confirmed locally | Controlled SMB authentication test |
| Error `1326` | Confirmed | Invalid username/password |
| Event `4625` | Confirmed | Failed Windows logon |
| Logon Type `3` | Confirmed | Network logon |
| `FakeLabUser` | Confirmed | Account used in test |
| Port `445` in Elastic | Not confirmed | No usable network port telemetry |
| Process telemetry | Not returned | No matching Elastic process events |
| True host-to-host movement | Not established | Test was performed against `localhost` |

---

