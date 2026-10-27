# Attack-family scope and weak-case diagnosis — Grid Sentinel WAMS

Date: 2026-10-27. **Research interpretation and fixed evaluation map; no newly tuned detector or paper.**

The following F1 percentages are retrospective **Data4Cyber v3 per-second row F1** from Phase 36, whose lane/persistence choices were made after inspecting these scenarios. They are *not* blinded, prospective or deployed-model performance.

| Scenario / publisher mechanism | Meter physics only | Modbus role | ARP claim | Price novelty | Four-lane OR |
|---|---:|---:|---:|---:|---:|
| S1 — PV Modbus write manipulation | **2.35%** | 98.35% | 0% | 0% | 97.81% |
| S2 — BSS Modbus write manipulation | **1.10%** | 98.95% | 0% | 0% | 98.68% |
| S3 — BSS meter MITM | 56.88% | 0% | 99.56% | 0% | 99.34% |
| S4 — loads/PV meter MITM | **99.20%** | 0% | 98.91% | 0% | **99.20%** |
| S5 — multiple-meter MITM | 77.09% | 0% | 98.34% | 0% | 99.07% |
| S6 — MQTT price-signal compromise | **6.03%** | 0% | 0% | 99.56% | 99.56% |

**Why S4 dominates the frozen physics detector:** S4 disturbs the relation between total and per-phase power readings, producing a directly observable algebraic mismatch. S1/S2 command writes may remain electrically plausible as the process follows the altered setpoints. S6 changes tariff context rather than necessarily breaking Kirchhoff/power-balance identities. S3 and S5 may modify a subset of meter signals in ways that are less visible to the frozen 15 algebraic checks. The latter causal explanations are mechanism-level inferences, not authenticated attack attribution.

**Why four-lane F1 is very high:** It routes the known campaign to a different signal—Modbus writer-role, ARP source-identity mismatch, or price-domain novelty. These signals were engineered with knowledge of the same dataset. A naive union increases coverage but also creates false alerts (69 FP rows on 4,088 benign rows; 17 benign alert episodes across S1–S6). It is not credible to claim all four components are a jointly deployed validated IDS.

## Recommended narrowly scoped research claims

| Evidence lane | Reviewable behavior | Scope/abstain boundary |
|---|---|---|
| Frozen deployed meter physics | Inconsistent three-phase measurements, especially S4-style mismatches | Consistent attacks/valid operating changes may pass; no source attribution |
| Offline passive Modbus writer role | Unexpected source-IP *claim* performing write operations | Spoofable IP, changing inventory; not authenticated controller identity |
| Offline ARP identity claim | Conflicting IP/MAC claims at a compatible vantage | NIC maintenance and ARP churn; abstain without trusted inventory/sensor viewpoint |
| Offline price novelty | Strong departure from established observed tariff range | Legitimate tariff changes; require signed provider context |
| Offline frozen TCP scan rule | Broad TCP port enumeration with SYN probes | Not ICMP ping-only scanning, GOOSE FDI/suppression or general MITM detection |
| GOOSE / IEC 61850 message semantics | **Not implemented** | Report two KIOS attack captures as unsupported; no GOOSE-attack detection |

## Next independent experiment (no post-hoc retuning)

1. Freeze lane versions, thresholds, expected sensors and supported classes.
2. Acquire fully disjoint testbed/operator capture with timestamped attack intervals, benign maintenance and valid price/inventory records.
3. Report per-family event recall, first alert latency, confidence intervals, abstention coverage, false alert **episodes** per verified benign day and operator burden.
4. Evaluate an attack-agnostic fusion only after independent support and benign calibration; do not choose an OR rule after seeing the target's labels.
5. If adding a new GOOSE/ICMP detector, label it **new exploratory architecture**; do not retroactively count it as a frozen feature's blind success.

## Publication-friendly *contribution proposition*, not a paper

**A protocol-scoped cyber-physical review framework that explicitly reports selective coverage, causal evidence and abstention under cross-dataset shift.** The scientific value would come from honest generalization and alert burden—rather than trying to force every attack type to S4's physics-only F1.

This is a conservative proposed contribution for future publication, not a demonstrated universally superior algorithm. No paper drafted.
