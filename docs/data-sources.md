# Data sources and field mappings

The rules use Sigma's generic Windows process-creation taxonomy. Collection can
come from Sysmon process creation, Windows Security event 4688 with command-line
logging, or an EDR process stream, provided the fields are normalized before
the rules are evaluated.

| Sigma field | Defender XDR | Splunk CIM `Endpoint.Processes` |
| --- | --- | --- |
| `Image` | `FolderPath`, `FileName` | `process_path`, `process_name` |
| `CommandLine` | `ProcessCommandLine` | `process` |
| `ParentImage` | `InitiatingProcessFolderPath`, `InitiatingProcessFileName` | `parent_process_path`, `parent_process_name` |
| `User` | `AccountDomain`, `AccountName`, `AccountUpn` | `user` |
| Host | `DeviceName` | `dest` |

## Microsoft Defender XDR

The KQL translations use `DeviceProcessEvents`, which records process creation
and related events from Microsoft Defender for Endpoint. Query results include
`ReportId` alongside `DeviceName` and `Timestamp` so individual records can be
identified consistently.

## Splunk

The SPL translations use the CIM `Endpoint.Processes` data set through
`tstats`. They assume that the relevant endpoint add-on populates at least
`process_name`, `process`, `parent_process_name`, `dest`, and `user`.

Data-model acceleration is not required by the searches because
`summariesonly=false` is explicit, but acceleration is normally preferable for
scheduled production searches.

## Sigma

All rules are marked `test`. Paths and command lines are matched without case
sensitivity by the local regression evaluator, matching common Windows and SIEM
behavior. Backend conversion may require a processing pipeline appropriate to
the actual log source.
