# Phase 58 — Exploratory TCP transport-pattern alternative

The Phase 57 external negative control invalidated unrestricted MAC-novelty deployment: under one normal session all 458 later benign minutes alert; under the opposite normal inventory both publisher attack files have no MAC novelty. We therefore inspected **source-MAC-independent transport behavior** in the same four MD5-verified [Zero-SWARM PCAPs](https://zenodo.org/records/15082260).

## Experiment

Count distinct TCP destination ports and SYN-without-ACK packets in each 60-second bucket. A strictly **post-hoc proposal** for a research review trigger requires (a) more distinct destination ports than the maximum observed in the short normal capture (2), **and** (b) at least one SYN-without-ACK packet in the bucket. TCP parsing is defensive; malformed/non-TCP packets are not assigned a port. The criterion is explicitly **not a deployed model** or prospectively selected threshold.

| Publisher recording | Minute-buckets with packets | Review flags | Maximum TCP destination ports in a minute | Total SYN-without-ACK |
|---|---:|---:|---:|---:|
| Short normal | 34 | 0 | 2 | 0 |
| Long normal | 458 | 0 | 2 | 0 |
| Nmap attack scenario | 11 | 11 | 56 | 510 |
| Flooding attack scenario | 10 | 10 | 56 | 493 |

The **492 benign buckets had zero flags; the 21 attack-scenario buckets all flagged**. This is a positive *retrospective fit on one external publisher testbed*, not 100% independent-site detection. The two attack recordings have closely related traffic, and only file-level scenario labels; a flagged bucket is not necessarily a true event-level positive. More varied benign commissioning, engineering-client port scans, upgrades, backup services, and attack types could change the false-alarm/recall tradeoff.

## Architectural recommendation

Keep source-MAC novelty as a weak contextual/review feature. Develop a **separate protocol behavior research lane** (TCP connection attempts, Modbus function/transaction consistency and source allowlist with authenticated asset records), with explicit abstention for missing sensor provenance and a separate benign maintenance set. Freeze specifications and thresholds *before* testing on genuinely untouched new sites and attack families. Do not combine post-hoc Zero-SWARM and Data4Cyber scores into a claimed universal F1.

No backend detector or production threshold was changed. Docker/PostgreSQL private-host validation, real utility trust material, live benign maintenance days and pre-registered blind site evaluation are still outstanding. Readiness remains **88/100**. No paper was written. Exact per-minute data: `SmartGrid_Phase58_ZeroSWARM_TCP_Scan_Audit_2026-10-27.json`.
