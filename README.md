# Windows detection engineering lab

A working collection of Windows endpoint detections with equivalent queries for
Microsoft Defender XDR and Splunk. Rules are kept in `test` status until they
have been tuned against the target environment.

## Detection coverage

| Detection | ATT&CK technique | Level |
| --- | --- | --- |
| PowerShell download and execute pattern | T1059.001, T1105 | High |
| WMI-spawned command shell | T1047 | High |
| PsExec service child shell | T1569.002 | High |
| Defender preference tampering | T1562.001 | High |
| MSHTA loading remote content | T1218.005 | High |
| Scheduled task with script or shell payload | T1053.005 | Medium |

## Layout

```text
rules/sigma/       Source rules using the Sigma process-creation taxonomy
queries/kql/       Microsoft Defender XDR advanced-hunting queries
queries/spl/       Splunk CIM Endpoint.Processes searches
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

The tests check rule metadata, UUIDs, condition references, query parity, and
positive and negative synthetic events. They do not replace validation against
the telemetry, administrative patterns, and data quality of a live environment.

## References

- [Sigma rule documentation](https://sigmahq.io/docs/basics/rules.html)
- [Microsoft Defender XDR DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Splunk CIM Endpoint data model](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.0/data-models/endpoint)
- [MITRE ATT&CK](https://attack.mitre.org/)

## License

MIT
