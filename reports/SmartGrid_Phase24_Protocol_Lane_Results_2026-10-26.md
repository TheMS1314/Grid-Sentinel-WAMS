# Grid Sentinel Phase 24 — Passive Modbus Command Evidence and Two-Lane Audit

26 October 2026 — offline **defensive** research, no active packet transmission, no paper written.

## Executive result

The project now has a **new, independently scoped passive Modbus-command source policy** complementing the previously frozen 15-feature power-meter physics head. This specifically addresses the previously failed S1/S2 PV/battery Modbus families. The policy examines recorded TCP/502 write-request origins and compares each source IP to the S0 inventory's *management-system role*, without training on S1/S2 labels. The published role map designates `192.168.1.11` as DMS/EMS; S0's legitimate write requests are consistent with it. S1/S2/S1-alt separately contain 520/698/862 write requests from `192.168.1.20`, identified as the attacker node in the publisher's mapping.

**This is a useful narrow research advance, not authenticated intrusion attribution.** IP addresses can be forged. An OT owner must verify real authorization policy and network vantage-point integrity before real deployment. Both the detector choice and persistence sensitivity were explored after we had seen these dataset families; all scores are **posthoc exploratory**. The production FastAPI inference endpoint remains the original frozen physics-only model. The packet parser is an offline script, not an active sensor.

## Frozen physics vs instantaneous unexpected Modbus writer

| Test | Physics F1 | Modbus writer policy F1 | Simple OR F1 | Writer policy clean row FPR |
|---|---:|---:|---:|---:|
| S0 last 360 clean rows | N/A | N/A | N/A | **0/360** |
| **S1 PV Modbus** | 0.02355 | **0.64849** | 0.64770 | 4/885 = 0.45% |
| **S2 Battery Modbus** | 0.01095 | **0.86571** | 0.86372 | 5/865 = 0.58% |
| S3 battery MITM | 0.56875 | 0.00000 | 0.56875 | 0 |
| S4 loads/PV MITM | 0.99202 | 0.00000 | 0.99202 | 0 |
| S5 multi-meter MITM | 0.77092 | 0.00000 | 0.77092 | 0 |
| S6 MQTT compromise | 0.06034 | 0.00000 | 0.06034 | 0 |
| **Reserved S1-alt PV Modbus** | 0.04038 | **0.75000** | 0.74814 | 5/882 = 0.57% |

No Modbus writer-source alarm is expected for ARP/MITM telemetry tampering or MQTT-price attacks in these captures. **OR fusion adds unrelated physics false alarms** and *slightly reduces S1/S2/S1-alt F1 relative to the narrow protocol head*. We therefore preserve separate review channels and do not pretend a universal OR score is a superior operating policy.

The new source policy is not a statistically independent S1-alt blind result: the architecture and data-family inspection were already exposed before testing it on the alternate run. Its outcome remains useful as a replication-oriented stress test, not proof of cross-site transfer.

## Five-second persistence: explicit posthoc sensitivity only

An alternative *fixed five-second persistence* retains an unexpected-write review for five seconds after an observed source-rule violation. On already inspected same-testbed runs:

| Scenario | 5-s row F1 | Activity recall | Benign-row alert rate | First manipulation-episode alert latency |
|---|---:|---:|---:|---:|
| S1 | **0.98350** | 97.92% | **1.243%** | 8 s |
| S2 | **0.98949** | 99.00% | **1.156%** | 7 s |
| S1-alt | **0.98400** | 98.02% | **1.247%** | 9 s |

These numbers are **not a new blind benchmark or deployment-ready policy**. The persistence interval was examined after viewing preliminary source-policy results, and it expands one command event into multiple one-second positive rows. Therefore the apparent F1 improvement does not prove additional independent malicious actions were discovered. Its false-alarm rates are concerning and not measured across clean multi-day sites. We include the sensitivity transparently in the dashboard without changing the production model.

## Protocol visibility and MQTT block

The offline Modbus decoder scanned network-tap pcapng and decoded Modbus TCP messages at the beginning of TCP payload segments only; it does **not** perform full TCP stream reassembly, retry de-duplication, PLC register semantics, or sender authentication. It counted ~189k S0, 169k S1, 182k S2 and 174k S6 TCP/502 segment starts with recognizable Modbus headers, illustrating why casual traffic-count heuristics alone will not isolate attacks.

An independent passive MQTT check found **0 TCP packets on typical broker ports 1883/8883 in the S0 and S6 network-tap captures**. This is an observability limitation for this vantage point, *not proof that S6 lacks an MQTT compromise*. There are no authoritative, signed legitimate price publications or enough authenticated per-packet origin evidence to build the needed S6 detector here. No fabricated labels were introduced.

## Reproducibility and software integration

Added files:

- `data4cyber_passive_modbus_audit.py` — packet-level Modbus visibility and source summary.
- `data4cyber_modbus_allowlist_benchmark.py` — fixed S0 role-derived command writer anomaly policy and sensitivity.
- `data4cyber_two_lane_benchmark.py` — independent physics, protocol and naïve OR score comparison.
- `data4cyber_passive_mqtt_audit.py` — MQTT port/publisher visibility only.
- `test_data4cyber_protocol_lane.py` — synthetic pcapng fixtures: 3/3 tests passed.
- Full JSONL outputs for the packet, MQTT, baseline and five-second sensitivity studies.

FastAPI now has separate **historical, read-only** `/api/protocol-research` and `/api/protocol-sensitivity` routes. The React Research evidence page compares the saved results. **The live `/api/analyses` endpoint has not been changed to ingest packets, sniff a network, or send Modbus commands.**

Verification:

- React Vite production build: **passed**.
- FastAPI API tests: **8/8 passed** (one non-failing test-client dependency deprecation warning).
- Existing offline replay and attribution tests: **5/5 passed**.
- New protocol parser tests: **3/3 passed**.
- Earlier six-scenario research acceptance commands: **6/6 reproduced**; scientific readiness remains **3/10**.
- Docker/PostgreSQL actual startup and on-PC browser QA: **not performed**; Docker unavailable here.

## What is needed for a defensible 10/10

1. Independent clean multi-day source-IP/MAC/command-authority traces from each site and versioned legitimate command policies.
2. A packet parser with full TCP reassembly, Modbus request/response correlation, source integrity and spoofing/replay resistance; test segment fragmentation, retransmits and NAT/proxies.
3. Independently labeled command injection, authorized maintenance, failover and unusual-but-benign operational changes; pre-register temporal persistence *before* those final test recordings are opened.
4. Authenticated MQTT publisher messages and a known, legitimate tariff schedule with delivery timestamps to validate S6.
5. Trusted telemetry anchors and a verified feeder state-estimation model for coherent S5 phase-2/MITM.
6. Operational deployment tests: PostgreSQL/Compose integration, authorization, TLS, observability, incident triage, throughput, data retention, recovery and documented safe operation.

The new protocol lane raises Modbus-family exploratory performance substantially and demonstrates why threat-specific evidence is more appropriate than parameter tuning on the wrong feature set. **It does not raise the scientific research-completion gate to 10/10.**

## Reproduce

Obtain the publisher's `Data4Cyber_v3_2026.zip` (not redistributed in our archive) from https://zenodo.org/records/22953576 and install `numpy`, `pandas`, `scikit-learn`, and `dpkt` for offline research only.

```bash
python -m unittest -v test_data4cyber_protocol_lane
python data4cyber_passive_modbus_audit.py
python data4cyber_modbus_allowlist_benchmark.py
python data4cyber_two_lane_benchmark.py
python data4cyber_modbus_allowlist_benchmark.py --scenarios S0_benign_baseline S1_industroyer_pv S2_industroyer_bss S1_industroyer_pv_alt --hold-seconds 5
python data4cyber_passive_mqtt_audit.py
```

No research paper was written.
