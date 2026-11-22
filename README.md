# Windows detection engineering lab

[![Validate detections](https://github.com/Dante404/windows-detection-engineering-lab/actions/workflows/validate.yml/badge.svg)](https://github.com/Dante404/windows-detection-engineering-lab/actions/workflows/validate.yml)

A working collection of Windows endpoint detections with equivalent queries for
Microsoft Defender XDR and Splunk. Rules are kept in `test` status until they
have been tuned against the target environment.

## Start here

For a representative end-to-end example, see **PowerShell download and execute**:

- [Sigma detection rule](rules/sigma/powershell_download_and_execute.yml) - process-creation selection and rule logic.
- [Microsoft Defender XDR KQL](queries/kql/powershell_download_and_execute.kql) - an equivalent hunting query.
- [Splunk SPL](queries/spl/powershell_download_and_execute.spl) - a CIM-based equivalent.
- [Synthetic positive and negative cases](tests/cases/process_events.json) - expected match and non-match examples used in the offline tests.

The rule looks for PowerShell combining a download primitive with an execution primitive in one command line. Legitimate administrative or software-deployment scripts can resemble this behavior, so tuning and telemetry checks are required before using it as a production alert.

**Validation scope:** GitHub Actions runs structure checks and tests with synthetic cases; it does not connect to a live tenant or validate live alert quality. The rules in this repository remain in `test` or `experimental` status until tuned against the target environment.

## Detection coverage

| Detection | ATT&CK technique | Level |
| --- | --- | --- |
| PowerShell download and execute pattern | T1059.001, T1105 | High |
| WMI-spawned command shell | T1047 | High |
| PsExec service child shell | T1569.002 | High |
| Defender preference tampering | T1562.001 | High |
| MSHTA loading remote content | T1218.005 | High |
| Scheduled task with script or shell payload | T1053.005 | Medium |

## Hunts and analytics

| Query | Platform | Status |
| --- | --- | --- |
| [BITS download activity](hunts/logscale/bits_download_activity.cql) | CrowdStrike LogScale | Test |
| [Office descendant child-process chain](hunts/logscale/office_child_process_chain.cql) | CrowdStrike LogScale | Test |
| [TVM SCID-2090 removable-drive context](hunts/mde/tvm_scid_2090_removable_drive_context.kql) | Microsoft Defender XDR | Test |
| [Attack surface reduction activity](hunts/mde/asr_activity.kql) | Microsoft Defender XDR | Test |
| [Browser cookie WAL and domain activity](hunts/mde/browser_cookie_wal_domain_activity.kql) | Microsoft Defender XDR | Experimental |
| [Safe Links click-to-email correlation](hunts/mde/safe_links_click_to_email.kql) | Microsoft Defender XDR | Experimental |
| [Suspicious execution with network or DNS activity](hunts/splunk/sysmon_suspicious_execution_network.spl) | Splunk with Sysmon | Experimental |
| [Ransomware control posture score](analytics/mde/ransomware_posture_score.kql) | Microsoft Defender XDR | Test |

Query assumptions, known limitations, and tuning points are documented in
[`docs/hunts.md`](docs/hunts.md). Machine-readable metadata lives in
[`hunts/catalog.yml`](hunts/catalog.yml).

## Layout

```text
rules/sigma/       Source rules using the Sigma process-creation taxonomy
queries/kql/       Microsoft Defender XDR advanced-hunting queries
queries/spl/       Splunk CIM Endpoint.Processes searches
hunts/             Investigative KQL, CQL, and SPL grouped by platform
analytics/         Security-control measurement queries
tests/cases/       Synthetic process events used for regression testing
tools/             Lightweight repository validation and rule evaluator
docs/              Data-source mappings and tuning notes
```

The KQL queries expect the Defender XDR `DeviceProcessEvents` table. The SPL
queries expect the Splunk Common Information Model `Endpoint.Processes` data
set. Field mappings and collection assumptions are documented in
[`docs/data-sources.md`](docs/data-sources.md).

## Validation

```bash
python -m pip install --requirement requirements-dev.txt
python tools/validate_rules.py
python -m unittest discover --start-directory tests --verbose
```

The tests check rule metadata, UUIDs, condition references, query parity, hunt
catalog integrity, expected hunt signals, and positive and negative synthetic
events. They do not replace validation against the telemetry, administrative
patterns, and data quality of a live environment.

## References

- [Sigma rule documentation](https://sigmahq.io/docs/basics/rules.html)
- [Microsoft Defender XDR DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Splunk CIM Endpoint data model](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.0/data-models/endpoint)
- [MITRE ATT&CK](https://attack.mitre.org/)

## License

MIT
