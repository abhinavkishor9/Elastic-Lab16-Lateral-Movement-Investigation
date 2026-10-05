# Timeline

| Date/Time | Source | Event | Interpretation |
|---|---|---|---|
| 05 Oct 2026 06:51:37 | PowerShell | `whoami`, `hostname`, `Get-Date`, `ipconfig` executed | Host and network baseline collected |
| 05 Oct 2026 06:51:37 | PowerShell | Host identified as `DESKTOP-9MMM37V` | Investigation host confirmed |
| 05 Oct 2026 06:51:37 | PowerShell | User identified as `desktop-9mmm37v\dell` | Test context established |
| 05 Oct 2026 ~07:00 | PowerShell | `net use \\localhost\IPC$ /user:FakeLabUser WrongPassword` | Controlled SMB authentication attempt |
| 05 Oct 2026 ~07:00 | PowerShell | Error `1326` returned | Authentication failed because credentials were invalid |
| 05 Oct 2026 07:00:46 | Windows Security | Event ID `4625` generated | Failed logon recorded |
| 05 Oct 2026 07:00:46 | Windows Security | Logon Type `3` identified | Event represents a network logon |
| 05 Oct 2026 07:00:46 | Elastic | Event ID `4625` ingested | Windows authentication telemetry available in Elastic |
| 05 Oct 2026 ~07:xx | Elastic | `4625` + Logon Type `3` query returned one document | Network authentication event confirmed in Elastic |
| 05 Oct 2026 ~07:xx | Elastic | `destination.port == 445` query failed | `destination.port` unavailable |
| 05 Oct 2026 ~07:xx | Elastic | Dataset investigation performed | Available datasets: `system.system`, `elastic_agent.metricbeat`, `elastic_agent` |
| 05 Oct 2026 ~07:xx | Elastic | Wildcard search for `445` returned no results | Port `445` not independently observed |
| 05 Oct 2026 ~07:xx | Elastic | Process search returned zero documents | No matching process telemetry available |

---

