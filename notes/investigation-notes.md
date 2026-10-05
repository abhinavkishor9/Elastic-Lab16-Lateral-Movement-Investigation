# Investigation Notes — Elastic Lab 16

## Investigation Title

Lateral Movement Investigation — Windows Network Authentication

---

## 1. Investigation Objective

Investigate a controlled Windows network authentication attempt and determine whether the available telemetry supports a potential SMB-based lateral movement scenario.

The investigation focuses on:

- Windows Event ID `4625`
- Logon Type `3`
- SMB/IPC$ authentication
- Port `445` investigation
- Elastic SIEM correlation
- Process telemetry
- Evidence limitations

---

## 2. Host Discovery

The initial host information was collected using:

```powershell
whoami
hostname
Get-Date
ipconfig
```

Observed values:

```text
User:
desktop-9mmm37v\dell

Hostname:
DESKTOP-9MMM37V

Time:
05 October 2026 06:51:37
```

Network adapters included VMware interfaces:

```text
VMnet1:
192.168.174.1

VMnet8:
```

The environment consisted of a single Windows workstation available for the lab.

---

## 3. SMB Authentication Test

A controlled SMB authentication attempt was performed against the local IPC$ share:

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

Result:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

This provided a controlled failed authentication scenario.

Because the target was `localhost`, this test does not represent actual host-to-host lateral movement.

---

## 4. Windows Security Log Verification

The Security log was checked using:

```powershell
Get-WinEvent -ListLog Security |
Select-Object LogName, RecordCount, IsEnabled
```

Result:

```text
LogName  RecordCount IsEnabled
Security          11      True
```

The Security log was enabled and contained events.

---

## 5. Event ID 4625 Investigation

The most recent Event ID `4625` events were retrieved using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
} -MaxEvents 5 |
Select-Object TimeCreated, Id, ProviderName, Message
```

The latest event was:

```text
05-10-2026 07:00:46
4625
Microsoft-Windows-Security-Auditing
An account failed to log on....
```

The event occurred after the controlled authentication attempt.

---

## 6. Event Data Extraction

The XML event data was inspected using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
} -MaxEvents 1 |
ForEach-Object {
    [xml]$_.ToXml()
} |
Select-Object -ExpandProperty Event |
Select-Object -ExpandProperty EventData
```

The event contained standard Windows Security event data fields including:

```text
SubjectUserSid
SubjectUserName
SubjectDomainName
SubjectLogonId
...
```

---

## 7. 4624 and 4625 Review

Both successful and failed logon events were queried:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625
} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName
```

The returned events were Event ID `4625` events.

No Event ID `4624` was returned in this query.

This should not be interpreted as proof that no successful logons occurred on the system. It only reflects the events available in the queried Security log range.

---

## 8. Elastic Event ID 4625 Investigation

Elastic was queried for Event ID `4625`:

```esql
FROM logs-*
| WHERE event.code == "4625"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       winlog.event_data.LogonType,
       winlog.event_data.TargetUserName
```

Result:

```text
@timestamp:
Oct 5, 2026 @ 07:00:46.195

host.name:
desktop-9mmm37v

user.name:
FakeLabUser

event.code:
4625

LogonType:
3
```

---

## 9. Network Logon Investigation

The event was further filtered for Logon Type `3`:

```esql
FROM logs-*
| WHERE event.code == "4625"
  AND winlog.event_data.LogonType == "3"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       winlog.event_data.LogonType
```

The event remained:

```text
event.code:
4625

user.name:
FakeLabUser

LogonType:
3
```

This confirms that the failed authentication event was classified as a network logon.

---

## 10. Port 445 Investigation

The initial network query attempted to use:

```esql
destination.port
```

However, Elastic returned:

```text
Unknown column [destination.port]
```

The available dataset groups were then checked.

Available datasets:

```text
system.system
elastic_agent.metricbeat
elastic_agent
```

No network dataset was present in the available data.

A wildcard search for `445` was also performed:

```esql
FROM logs-*
| WHERE TO_STRING(winlog.event_data.IpAddress) LIKE "*445*"
   OR TO_STRING(winlog.event_data.TargetUserName) LIKE "*445*"
   OR TO_STRING(winlog.event_data.AuthenticationPackageName) LIKE "*445*"
   OR TO_STRING(message) LIKE "*445*"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       winlog.event_data.IpAddress
```

Result:

```text
26 documents processed
No results match your search criteria
```

Therefore, port `445` was not independently observed in the available Elastic telemetry.

---

## 11. Process Telemetry Investigation

The following process names were searched:

```text
net.exe
powershell.exe
pwsh.exe
cmd.exe
```

Query:

```esql
FROM logs-*
| WHERE process.name IN ("net.exe", "powershell.exe", "pwsh.exe", "cmd.exe")
| KEEP @timestamp,
       host.name,
       user.name,
       process.name,
       process.pid
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
No results match your search criteria
```

Therefore, Elastic did not return process telemetry for the controlled command.

The local PowerShell console remains the evidence that the command was executed.

---

## 12. Evidence Assessment

### Confirmed

- Controlled `net use` command was executed locally.
- SMB IPC$ authentication was attempted.
- Authentication failed with Windows error `1326`.
- Windows generated Event ID `4625`.
- Elastic received the Event ID `4625`.
- The event involved `FakeLabUser`.
- The event had Logon Type `3`.

### Not Confirmed

- TCP port `445` in Elastic network telemetry.
- Source/destination network connection details.
- Process telemetry for `net.exe`.
- Host-to-host lateral movement.

### Interpretation

The strongest supported conclusion is:

> A controlled failed network authentication attempt generated Windows Event ID 4625 with Logon Type 3 and was successfully ingested into Elastic.

The evidence does not support the stronger conclusion that malicious lateral movement occurred.
