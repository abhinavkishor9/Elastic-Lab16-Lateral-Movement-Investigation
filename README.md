# Elastic Lab 16 — Lateral Movement Investigation

## Overview

This lab investigates Windows network authentication activity associated with a potential lateral movement scenario.

The investigation focuses on SMB-based authentication and Windows Security Event ID 4625, particularly **Logon Type 3 (Network)**. A controlled SMB authentication attempt was generated against the local host using the Windows `net use` command with invalid credentials.

The objective was to determine what evidence was available in Windows Security logs and Elastic SIEM, while avoiding assumptions that a network authentication event automatically represents lateral movement.

> **Evidence principle:** Network authentication is not automatically proof of lateral movement. The investigation must establish the source, destination, account, authentication type, and supporting telemetry before making that determination.

---

## Scenario

An analyst is investigating possible lateral movement involving SMB/Windows network authentication.

The environment contains a single Windows workstation:

- Host: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- Platform: Windows 11
- PowerShell: 7.6.6
- Elastic Agent: 9.5.4
- Security Event Log: Enabled

Because only one Windows host is available, a true host-to-host lateral movement scenario cannot be reproduced. Instead, a controlled authentication attempt was performed against the local `IPC$` share.

The test used:

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

The command returned:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

Windows subsequently recorded Event ID `4625`, showing a failed logon with Logon Type `3`.

---

## Objectives

- Understand the relationship between SMB authentication and lateral movement.
- Identify Windows Event ID `4625` associated with failed network logons.
- Investigate Logon Type `3`.
- Search Elastic SIEM for the resulting authentication event.
- Investigate whether port `445` could be confirmed from available Elastic telemetry.
- Compare local Windows Security evidence with Elastic SIEM telemetry.
- Document telemetry limitations without treating missing data as proof of absence.

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

## Conclusion

The lab successfully demonstrated how a controlled SMB authentication attempt can generate Windows Event ID `4625` with Logon Type `3` and how that event can be investigated in Elastic SIEM.

The available evidence supports a **failed network authentication attempt**, but it does not establish malicious lateral movement or independently confirm TCP port `445`.

The main limitation was the absence of network connection telemetry exposing the destination port. The investigation therefore relied on Windows Security authentication evidence rather than assuming that every Logon Type `3` event represents SMB traffic on port `445`.

This distinction is important in a real SOC investigation because authentication evidence, network evidence, and process evidence should be correlated before concluding that lateral movement occurred.
