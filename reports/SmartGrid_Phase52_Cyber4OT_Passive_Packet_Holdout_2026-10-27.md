# Phase 52: Independent Raw-PCAPNG Passive Modbus/MAC Audit

Date: 27 October 2026 (India). Publisher: Krzysztof Cabaj et al., Warsaw University of Technology, *Cyber4OT: ICS network traces containing normal activity and full attack traffic*, Zenodo https://zenodo.org/records/15005190. Published archive `Cyber4OT.zip`, verified publisher MD5 `55510cbb43d8af72a69dfbcd6940daa5`. Publisher describes 96 files and over 4.25 million packets, including reconnaissance, MAC flooding, TCP disconnection, Modbus PLC hijacking, and both successful and unsuccessful attack executions.

## Purpose and isolation

This is a second independent **publication and test-bed**, separate from Data4Cyber and the KIOS flow-feature spreadsheet benchmark. It exposes raw PCAPNG frames rather than precomputed flow features. It can validate a **narrow passive-network signal** but has no aligned meter physics, tariff trust, or complete per-packet attack-active truth. It therefore cannot directly validate the previously reported Data4Cyber four-lane F1.

In this experiment, only PLC-port sensor captures are comparable. `Cyber4OT_069.pcapng` is a 5-minute **normal-only training baseline**. Its observed IPv4 Modbus (TCP port 502) client addresses and peer IP↔Ethernet-MAC mappings are frozen. `Cyber4OT_070–071` are separate 10- and 15-minute benign PLC-port captures; `082`, `084`, `086`, `088`, `090`, `092`, `094`, and `095` are publisher-described PLC-port attack-scenario captures. The odd-numbered attack-trace counterparts were made at a different (attacker) observation point and are excluded. The mixed normal-then-attack capture `095` has **no exact transition time supplied** and is scored only as an attack-containing capture.

## Raw observations

| PLC-port trace | Publisher interpretation | Modbus packets | Modbus client novelty packets | Unseen source-MAC packets | Fusion capture alert |
|---|---|---:|---:|---:|---|
| 070 | Benign | 7,198 | 0 | 0 | No |
| 071 | Benign | 10,773 | 0 | 0 | No |
| 082 | MAC flooding / redirect | 86 | 0 | 1,349 | Yes |
| 084 | MAC flooding + TCP kill | 128 | 0 | 989 | Yes |
| 086 | MAC flooding + TCP kill | 94 | 0 | 827 | Yes |
| 088 | MAC flooding + TCP kill | 118 | 0 | 763 | Yes |
| 090 | Successful hijack | 1,057 | 479 | 3,360 | Yes |
| 092 | Unsuccessful hijack attempt | 919 | 366 | 2,817 | Yes |
| 094 | Post-hijack activity | 11,232 | 5,627 | 5,627 | Yes |
| 095 | Normal + successful attack | 16,339 | 2,711 | 9,513 | Yes |

No tested capture had a Modbus-specific IP-to-MAC identity conflict for a known source, even during attacks. This is a useful negative result: it demonstrates that the packet observation point matters, and that a rule expecting known Modbus identities to change MAC may completely miss these attacks. The Modbus client-IP allowlist alone detects 4/8 attack-containing captures; source Ethernet MAC novelty catches 8/8, with 0/2 benign captures flagged.

## Scientific limitations

1. The Ethernet-source novelty lane was **added after inspecting the Modbus-only experiment's failure cases**. Its 8/8 descriptive result is **post-hoc and exploratory**, not prospective detection performance.
2. Any unfamiliar legitimate device, switch change, maintenance action, virtual-machine reconfiguration, MAC randomization or traffic vantage shift could cause false positives. The two benign captures were drawn from the same testbed and do not establish false-alerts/day on a changing plant network.
3. Each attack trace may contain substantial benign traffic. Capturing at least one alert in an attack-labeled file **is not** proof that the alert occurred during malicious activity. These data have no trustworthy packet-level labels or event-start/stop annotations for an unbiased time-to-detection metric.
4. Threshold is simply `>0` novel source MAC or Modbus client packets in a whole capture. Longer observation windows naturally increase novelty probability; continuous operation requires trusted inventory, aging, maintenance windows and explicit alert episode accounting. Source IP/MAC are spoofable, so this is detection context rather than authentication.
5. Neither the raw archive nor inferred attack IPs should be redistributed as sensitive site credentials or trusted policy defaults. They exist here only as published testbed metadata. The raw dataset is excluded from the user ZIP.
6. A successful offline packet test is not a live Docker deployment or independent utility-site approval.

## Reproduction

Install `dpkt` and run from the release directory:

`python cyber4ot_independent_modbus_probe.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase52_Cyber4OT_Passive_Modbus_2026-10-27.json`

`python -m unittest -q test_cyber4ot_independent_modbus_probe`

The program checks the original publisher archive MD5 before scoring; reads required PCAPNG members without extracting or repackaging them; freezes only trace 069; and reports all capture-level counts and rule outcomes. No research paper has been written.

## Next evidence gate

Precommit MAC inventory rules and maintenance exceptions on a third untouched capture source; test both actual attacks and benign network changes. Evaluate alert episodes per clean day, packet observation completeness, and operationally meaningful attack-event recall. Do not promote the 8/8 capture flag fraction to a universal 100% detection claim.
