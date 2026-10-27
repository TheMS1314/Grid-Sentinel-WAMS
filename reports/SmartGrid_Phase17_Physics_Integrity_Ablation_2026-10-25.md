# Smart Grid Co-Pilot — Phase 17: Interpretable Three-Phase Integrity Detection

25 October 2026 — research-only exploratory results. **No paper written.**

## Executive finding

We discovered a more interpretable and, for specific attack scenarios, much stronger Data4Cyber v3 signal: **the total active/reactive/apparent power fields should agree with their own meter's per-phase sums**, allowing documented rounding and instrumentation effects. This detects internal inconsistencies of falsified telemetry without training on attack labels. The improvement is **attack-family selective** and **post hoc**: we devised this method after studying Phase 16 results on the same six tests; therefore it is not a blind generalization claim.

Source dataset: [Data4Cyber v3, Zenodo 22953576](https://zenodo.org/records/22953576), with time-aligned 1Hz measurements, scenario activity labels, device mappings, Modbus/ARP/MQTT logs. The publisher states that `attack_active` denotes attack activity, not necessarily affected samples with physical deviations. We evaluated primary S0–S6 and excluded publisher-designated alternate S1.

## Detector and faithful chronology

Train/calibrate only on benign S0: first **1,078** chronological seconds to determine normal residual center/scale; next **360** to set the 99th percentile of maximum standardized residual. The last **360** S0 seconds and all S1–S6 recordings are test. At run time, the reported confirmation requires **three consecutive anomalous 1-Hz readings**, resetting after an invalid timestamp gap. No attack labels enter parameters.

Five three-phase energy meters: battery inverter, Load A, Load B, PV inverter, and substation. For every meter compute three dimensionless self-consistency differences:

1. `abs(P_sum3 - (P_L1+P_L2+P_L3))/max(200, abs(P_sum3), abs(S_sum3))`;
2. the analogous Q sum residual;
3. the analogous S sum residual.

Each feature is centered by its benign-training median and scaled by its benign-training 90th-percentile absolute deviation (floor 0.0005). Take the maximum across the **15 named residuals** and flag if it exceeds the S0-only calibration threshold, then apply causal three-sample confirmation. These are **data-record internal algebraic integrity conditions**, not a cryptographic authentication scheme, network-topology WLS, or universal equations under all meter manufacturer's definitions.

The `S_sum3 - sqrt(P_sum3^2+Q_sum3^2)` residual is *not* treated as a strict law: for unbalanced three-phase circuits total apparent power can differ from the Euclidean combination of aggregate P and Q. We excluded this contextual feature from the selected clean-physics experiment. A separately reported exploratory optional setting includes it.

## Exact held-out outcome: strict 15-feature detector + three-second confirmation

| Scenario | TP | FP | Attack-state recall | F1 | Benign-period FPR |
|---|---:|---:|---:|---:|---:|
| S0 held-out benign (360 rows) | 0 | **4** | N/A | N/A | **1.11%** |
| S1 PV Modbus | 11 | 10 | **1.20%** | **0.0236** | 1.13% |
| S2 BSS Modbus | 5 | 5 | **0.55%** | **0.0110** | 0.58% |
| S3 BSS-meter ARP/MITM | 364 | 4 | **39.91%** | **0.5687** | 0.45% |
| **S4 loads/PV ARP/MITM** | **1,243** | **6** | **98.89%** | **0.9920** | 1.11% |
| **S5 loads/PV/BSS ARP/MITM** | **843** | **3** | **62.86%** | **0.7709** | 0.65% |
| S6 MQTT price compromise | 42 | 0 | **3.11%** | **0.0603** | 0.00% |

Comparison to Phase 16's previously tested 130-feature benign-only IsolationForest: S4 F1 rose from **0.7138 to 0.9920** and S5 from **0.6569 to 0.7709**. This is *not an independently validated upgrade* because the feature family was selected after seeing test outcomes. Scores are on the same experiment records and attack-active row targets, which do not prove the attacked measurements were altered at every row. Conversely S1/S2/S6 performance is poor; retaining the old system or combining heads without proper independent calibration is not recommended.

## Attribution supports a narrow, mechanistic interpretation

We counted raw per-feature threshold exceedances within attack-active windows, using the fixed S0 calibration threshold. Overlapping feature hits may occur within one row:

- **S4:** `PV-Inverter-AC-Meter.sum_p` exceeded in **1,245 attack-active rows**; `Load-A-AC-Meter.sum_p` in **599**, and `Load-B-AC-Meter.sum_p` in **599**. This directly supports a phase-total inconsistency detector as a plausible explanation for its unusually high score.
- **S5:** `PV-Inverter-AC-Meter.sum_p` exceeded in **759 attack-active rows**, and `BSS-Inverter-AC-Meter.sum_q` in **104**. The battery and PV routes differ across attack windows.
- **S3:** `BSS-Inverter-AC-Meter.sum_q` exceeded in **356 attack-active rows**, followed by `BSS-Inverter-AC-Meter.sum_s` in **84**. A single attack-active label spans activity beyond the visible physics violation.

These counts indicate **inconsistent readings**, not proven attacker identities. Sensor synchronization/missingness or meter protocol conventions could mimic mismatch and must be controlled before any autonomous action. The raw phase-sum discrepancy aligns with ARP/MITM spoofing in these recordings, but it would not detect an attacker who rewrites all dependent fields coherently.

## Comparison: cross-device aggregate-power balance head

A supplementary learned regression maps four meter P streams (battery, loads A/B, PV) to substation P, fitted only on S0 and converted to a normalized absolute residual. This is a weak **balance proxy**, not a grounded Kirchhoff/WLS topology model. Its three-confirmation F1 was S4 **0.9916**, S5 **0.7031**, S3 **0.0573**, S1 **0.0000**, S2 **0.0022**, S6 **0.0044**. It does not rescue the missed Modbus/MQTT families or meaningfully exceed the local algebraic rule. OR-like max fusion with the local head reproduced the local alarms because the local score dominated at the fixed threshold. No general fusion advantage was established.

## Failure modes and next decision

- **False alarm budget still insufficient:** four false-positive seconds in just six clean test minutes, even after persistence, is unacceptable for a practical system. Labels, missingness, synchronization and legitimate meter mismatch must be investigated on fresh benign captures.
- **Attack-type scope:** exact phase-total invariants are strong on this S4 MITM profile, moderately good on S5, partially good on S3, and poor on the Modbus/MQTT attacks. Treat as one specifically scoped head only.
- **Shared dataset exposure:** even with train/cal/test separation, this architecture follows inspection of the held-out attack families; its performance is exploratory, not confirmatory. A new, sealed campaign or different MITM testbed is required to support publication-grade generalization claims.
- **No trusted sender:** an attacker controlling both per-phase and total registers can satisfy all local algebraic equalities. Network-authenticated, timestamp-consistent evidence or independent physical observation remains necessary.

## Reproduction

Use the Data4Cyber **v3** public ZIP named `Data4Cyber_v3_2026.zip`; pandas/numpy/scikit-learn required. The companion code archive contains this evaluator and Phase 16's clean-trained baseline module.

```bash
python3 -B data4cyber_physics_invariants.py --head local --confirm-rows 3
python3 -B data4cyber_physics_invariants.py --head balance --confirm-rows 3
python3 -B data4cyber_physics_invariants.py --head both --confirm-rows 3
```

Read-only, offline experiments; no packet injection, intrusion, equipment control or incident attribution.
