# Phase 59 — Frozen TCP transport rule transferred to Cyber4OT

## Setup

The Phase 58 exploratory [Zero-SWARM](https://zenodo.org/records/15082260) review rule requires more than **two distinct TCP destination ports** AND one or more SYN-without-ACK packets in a one-minute bucket. This exact threshold and conjunction were **frozen before this Cyber4OT application**, with no Cyber4OT fitting. Cyber4OT was already examined for other research lanes in prior phases, so this is **cross-dataset rule transfer, not prospective blinded evaluation**. Cyber4OT publisher PCAPNG ZIP MD5 `55510cbb43d8af72a69dfbcd6940daa5` was verified.

The test uses all **83 attack-scenario** and four benign **comparable-sensor-view** files from the Phase 54 selection; attacker-endpoint capture counterparts are excluded. Scenario labels apply to an entire capture, not to packet-by-packet attack onset.

| Capture group | Scenario files flagged | 60-second buckets flagged |
|---|---:|---:|
| Central-switch normal | 0/2 | 0/27 |
| Central-switch full host scans | 60/60 | 316/328 |
| Central-switch ping scans | **0/5** | 0/17 |
| PLC-port normal | 0/2 | 0/27 |
| PLC-port scans | 5/5 | 25/25 |
| PLC-port ping scans | **0/5** | 0/17 |
| PLC-port MAC spoofing/hijack scenario | 8/8 | 14/30 |

Overall: **73/83 attack-scenario files flagged; 0/4 benign files falsely flagged**. More detailed per-file counts, port breadth, SYN packets and bucket totals are in `SmartGrid_Phase59_Cyber4OT_Frozen_TCP_Transfer_2026-10-27.json`.

## Interpretation

- The fixed protocol feature exhibits useful transfer for **port-scan families** between two distinct publisher testbeds.
- It **fails completely on Cyber4OT ping-scan files** (10/10 missed). Ping discovery is not necessarily a broad TCP destination-port scan, so this is an expected semantic limit, not evidence of zero attacks.
- The MAC lane flagged these particular Cyber4OT scenarios in the previous post-hoc audit, but its Zero-SWARM long benign false flags prohibit naive OR fusion without stronger trust/provenance controls.
- A review flag in a capture containing a hijack scenario does **not** establish hijack event onset detection, attacker identification, or causality. Legitimate Modbus reconnection could contribute SYN activity.
- Only four Cyber4OT benign captures were available at the two comparable viewpoints. Engineering workstations, maintenance clients, site-specific multiport services, or new factory traffic may exceed the transport rule's thresholds.

## Recommended next architecture

1. Keep the production **meter self-consistency** detector frozen and distinct from exploratory network lanes.
2. Develop an independently predeclared **TCP port-scan review lane** and a separately scoped **ping/ARP discovery lane**, using protocol semantics, authorized inventory and trusted sensor provenance. Distinguish *review* from *confirmed attack*.
3. Calibrate on site-local benign data and test against untouched maintenance and attacks, including a negative control with a legitimate engineering scanner. Evaluate attack events and false alerts/day, with abstention coverage.
4. Never claim the 73/83 as detection F1, unseen-site robustness, or combined deployed model accuracy.

No online controller access, production threshold, or dashboard inference was changed. The externally dependent prospective-site and private Docker-host gates still prevent a claim of completion beyond the current **88/100** readiness estimate. No paper was written.
