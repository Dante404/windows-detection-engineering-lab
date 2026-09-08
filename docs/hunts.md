# Hunt notes

The entries in `hunts/catalog.yml` distinguish queries that were previously
used as working hunts from reconstructed or experimental analysis. A `test`
entry has stable query logic but still needs local baselining. An
`experimental` entry depends on assumptions that should be verified before it
is scheduled or converted into an alert.

## Microsoft Defender XDR

### SCID-2090 removable-drive context

The query keeps the latest applicable, noncompliant Windows assessment per
device and looks for related removable-drive events from seven days before the
assessment through ten minutes after it. It excludes assessments where a drive
letter from the TVM context matches an observed drive event.

The query uses `DeviceInfo.DeviceType == Workstation`. Replace this with the
local hostname convention if device type classification is incomplete. The TVM
assessment table returns data in Defender XDR Advanced Hunting but is not
ingested into Microsoft Sentinel without a separate ingestion path.

### Attack surface reduction activity

The rule map contains the block action names previously used during ASR policy
work. The query also normalizes equivalent `Audited` and `WarnBypassed` suffixes
when the tenant emits them. Confirm available `ActionType` values in the
in-portal schema because event availability depends on platform and policy.

### Browser cookie WAL and domain activity

This query detects bursts of writes to Chromium `Cookies-wal` and Firefox
`cookies.sqlite-wal`, then correlates the same one-minute device bucket with
domain activity. It cannot count cookies, read WAL contents, or see HTTP
`Set-Cookie` headers. Treat the result as a browser-activity lead and validate
the `30` network-event and `50` WAL-write thresholds locally.

### Safe Links click-to-email correlation

The query retains interesting email clicks even when `EmailEvents` has no
matching `NetworkMessageId`. Draft and Sent-item clicks can lack joinable email
metadata, and forwarding can produce a recipient that differs from the
clicking account. The `EmailMetadataStatus` field makes those cases visible
instead of dropping them.

### Ransomware posture score

The analysis calculates daily compliance for Tamper Protection (`scid-2003`),
Controlled Folder Access (`scid-2021`), real-time protection (`scid-2012`),
antivirus enabled (`scid-2010`), current definitions (`scid-2011`), and cloud
protection (`scid-2016`). It publishes a score only when all six controls are
present for that day. The day-to-assessment expansion is intentionally clear;
for very large environments, materialize or pre-aggregate the assessment
history before running it over a longer period.

## CrowdStrike LogScale

The CQL hunts assign from both current process identifiers and the `_decimal`
variants seen in older Falcon event schemas. Run them over a narrow time window
first, then review the path and domain exclusions against local software
distribution and browser activity.

The BITS query requires a `BitsJobCreated` event and matching
`ProcessRollup2` process context. Network and domain events enrich the grouped
result when they share the same agent and Falcon process identifier.

The Office chain query treats a process with an Office parent or grandparent as
the source, then recovers the command line of the next child process. Common
document converters, add-ins, and management tooling are expected tuning
candidates.

## Splunk and Sysmon

The SPL expects the Sysmon operational log in the example `index` and
`sourcetype`; change both to match the deployment. Event ID 1 provides process
context, event ID 3 provides network connections, and event ID 22 provides DNS
queries. Sysmon network connection logging is disabled by default and must be
enabled in the Sysmon configuration.

The base query correlates events by host and `ProcessGuid`. Enrichment from
Palo Alto, Check Point, proxy, Snort, GlobalProtect, or Microsoft Entra data is
environment-specific and should be appended using local indexes and identity
keys. Useful extensions include proxy download followed by execution, exploit
signal followed by a successful VPN session, and periodic outbound activity.

## References

- [DeviceTvmSecureConfigurationAssessment](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table)
- [DeviceEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [UrlClickEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table)
- [EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Falcon LogScale `selfJoinFilter`](https://library.humio.com/data-analysis/functions-selfjoinfilter.html)
