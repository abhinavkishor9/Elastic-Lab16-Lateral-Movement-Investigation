# Troubleshooting Notes — Elastic Lab 16

## Issue 1 — Expected Event 4624 Was Not Returned

### Query

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624
} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Result

```text
No event found
```

### Investigation

The Security log was checked:

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

A combined query for Event IDs `4624` and `4625` showed multiple `4625` events:

```text
04-10-2026 21:46:20   4625
04-10-2026 12:46:08   4625
04-10-2026 12:03:35   4625
04-10-2026 12:02:14   4625
04-10-2026 12:01:12   4625
04-10-2026 11:53:11   4625
04-10-2026 11:51:36   4625
```

### Conclusion

The issue was not that the Security log was disabled.

No relevant `4624` event was available in the queried event range.

This was treated as a telemetry result rather than evidence that successful logons never occurred.

---

## Issue 2 — Initial SMB Test Did Not Immediately Show the Event

### Command

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

### Result

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

The Security log was subsequently checked for Event ID `4625`.

The new event was later observed:

```text
05-10-2026 07:00:46
4625
Microsoft-Windows-Security-Auditing
```

### Conclusion

The controlled failed authentication generated the expected Windows Security event.

---

## Issue 3 — `destination.port` Was Not Available

### Initial ES|QL

```esql
FROM logs-*
| WHERE destination.port == 445
| KEEP @timestamp,
       host.name,
       source.ip,
       destination.ip,
       destination.port,
       network.transport
| SORT @timestamp DESC
```

### Error

```text
verification_exception

Unknown column [destination.port]
```

### Investigation

Dataset counts were checked:

```esql
FROM logs-*
| STATS event_count = count() BY event.dataset
```

Available datasets:

```text
system.system
elastic_agent.metricbeat
elastic_agent
```

No network dataset was available.

### Conclusion

The Elastic environment did not expose a usable `destination.port` field.

The original port-445 network query therefore could not be used.

---

## Issue 4 — Search for `445` Returned No Results

A wildcard search was performed across available authentication-related fields:

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

### Conclusion

There was no literal `445` match in the searched fields.

This does not prove that the SMB authentication did not use port `445`. It only shows that the available Elastic telemetry did not expose evidence containing the value `445`.

---

## Issue 5 — Event 4625 + Logon Type 3 Returned a Result

The following query returned one document:

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

Observed:

```text
event.code:
4625

user.name:
FakeLabUser

LogonType:
3
```

### Conclusion

The Elastic event provides useful evidence of a failed network authentication attempt.

This was used as the primary Elastic evidence for the lab.

---

## Issue 6 — Process Search Returned No Documents

### Query

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

### Result

```text
0 documents processed
No results match your search criteria
```

### Conclusion

Elastic did not provide process telemetry for the controlled command.

The local PowerShell output remains independent evidence of command execution.

The absence of process telemetry was not treated as proof that the command did not execute.

---

## Overall Troubleshooting Conclusion

The main limitation encountered during Lab 16 was incomplete network and process telemetry in Elastic.

Available evidence supported:

- Windows Event ID `4625`
- Logon Type `3`
- `FakeLabUser`
- Failed network authentication
- Local controlled SMB authentication attempt

Unavailable evidence included:

- `destination.port`
- Source/destination network connection fields
- Direct Elastic confirmation of TCP port `445`
- Process execution telemetry

The investigation was therefore completed using the telemetry that was actually available rather than inventing or assuming missing network evidence.
