# Grid Sentinel Phase 23 — Why the MITM Head Does Not Transfer to Every Attack

26 October 2026. Read-only exploratory root-cause analysis of the frozen meter-consistency detector. No paper written.

## Main finding

This is **not an all-attack classifier**. It is a within-meter arithmetic consistency check, so a corrupted total power field without a matching per-phase rewrite stands out (S4), while a setpoint change, MQTT-price manipulation, or jointly modified phases/totals can preserve the checked equations (S1/S2/S6 and S5 phase 2). Adding the same threshold to unrelated mechanisms cannot deliver S4-like results.

To verify that interpretation without fitting new coefficients, `smartgrid_phase23_failure_attribution.py` computes exactly which of the 15 frozen identities cross the existing decision threshold within each original Data4Cyber attack phase. A new fifth unit test checks feature-decomposition parity with the deployed detector.

| Published attack phase | Reviewed rows | Most common raw threshold-exceeding identity | What it means |
|---|---:|---|---|
| S1 PV Modbus manipulation | **11 / 902** | BSS reactive phase sum, 23 raw rows | Rare battery-meter inconsistency, *not a consistent PV command signal* |
| S2 battery Modbus manipulation | **5 / 901** | BSS and substation reactive phase sums, 4 raw hits each | Near-total failure for command manipulation |
| S3 BSS MITM impact | **364 / 911** | BSS reactive phase sum, 356 raw hits | Detects some spoofed fields, not the entire activity interval |
| S4 loads/PV MITM phase 1 | **620 / 624** | PV active phase sum, 622 raw hits | Directly matches this detector's assumption |
| S4 loads/PV MITM phase 2 | **623 / 623** | PV active phase sum, 623 raw hits | Near-continuous internal total/phase contradiction |
| S5 multi-meter MITM phase 1 | **745 / 749** | PV active phase sum, 749 raw hits | Same narrow weakness as S4 |
| **S5 multi-meter MITM phase 2** | **98 / 582** | BSS reactive phase sum, 78 raw hits | **Most of the phase does not violate the tested local meter identities** |
| S6 initial MQTT attack stage | **33 / 900** | BSS reactive phase sum, 56 raw hits | No direct evidence of forged MQTT message provenance |
| S6 MQTT price manipulation | **9 / 450** | BSS reactive phase sum, 13 raw hits | A meter-consistency alarm is not a price-message authenticity check |

Counts of raw feature hits can overlap and are **not** authenticated attacked-field localization. Confirmed review rows require three consecutive anomalous one-second inputs. Research-selected architecture and S1/S6 label exposure prohibit independent-validation claims. A separate S1-alt run is included in the JSONL for transparency, not for training or tuning.

## Why we cannot push every score to S4 with the same model

- **Different causal mechanisms:** S1/S2 affect operational commands; S6 affects economic signals; S4 corrupts the telemetry totals vs phases the model explicitly compares.
- **Coordinated evasion:** A joint total and per-phase rewrite can satisfy all 15 algebraic equalities. A synthetic paired control confirmed this remains completely invisible to this particular detector.
- **Weak authority:** The same measurement stream cannot cryptographically validate its own origin. We need a protected sensor or authenticated write/publication trail.
- **Calibration transfer:** A different operating regime can look anomalous while benign, so simply lowering the threshold would create false alerts. Phase 19's limited WLS already produced unacceptable 13–25% clean false alerts under transferred power factors.
- **Label semantics:** `attack_active` includes reconnaissance/preparatory stages. A physics-only detector should not be graded as though it were an IP reconnaissance sensor; all metrics must specify their detection target.

## The correct architecture path

1. **Freeze Tier A**: the local 15-feature meter head, dedicated to S4-like mismatched telemetry. Do not weaken it merely to increase global recall.
2. **Build Tier B (new, not yet implemented)**: protocol evidence from timestamped authorized Modbus write requests, device responses and independently observed physical state. Use explicit operation/asset command allowlists and causal timing; do not infer cyberattack from power changes alone.
3. **Build Tier C (new, not yet implemented)**: authenticated MQTT price publication provenance and baseline schedule comparison. The released S6 packet evidence currently lacks sufficient benign authenticated publisher traces to train/evaluate this faithfully.
4. **Build Tier D (new, not yet implemented)**: protected PMU/feeder anchors and topology-constrained state estimation for coherent FDI. Confirm line impedance, device mapping, covariance and live legitimate operating changes first.
5. **Set independent acceptance targets before new data**: false alarms per 24 h per site, latency per attack mechanism, minimum recall and precision per class, missingness/abstention budget, provenance assertions, unseen-site generalization, rollback/recovery and security penetration test coverage. These are *gates*, not percentages that can be manufactured.

Prioritize [CPDS-AD's model-consistent FDI and Modbus/MQTT feeder experiments](https://github.com/liuyulinlyl/CPDS-AD-Detection-Methods) and [Sherlock's process-aware IEC 60870-5-104 scenarios](https://zenodo.org/records/18467070) for **separate prospective protocol/process models**. They do not carry Data4Cyber's same 60-field meter schema, so a single unmodified transfer score would be scientifically invalid. Neither new corpus has been downloaded/scored in this phase.

## Updated verification

- New Phase 23 feature audit executed on locally available public Data4Cyber CSVs; result JSONL included in the release.
- **5/5** combined Phase 22/23 replay unit tests pass.
- Frontend production build and **6/6** FastAPI tests remain previously verified; new audit requires no production inference/model changes.
- Existing comprehensive acceptance gate: **6/6 reproducibility commands pass**, **3/10 scientific readiness checks pass**. Scientific 10/10 still blocked by independent evidence, not missing coding effort alone.
- React visual mockups generated for discussion are **illustrations**, not browser screenshots, because the preview browser cannot access localhost in the execution environment. They must not be presented as live dashboard data.
- Docker/PostgreSQL start on the user's PC, public networking/authentication and independent field validation remain unverified.

## Reproduce

```bash
python -m pip install numpy pandas scikit-learn
python -B -m unittest -v test_smartgrid_phase22_reliability
python -B smartgrid_phase23_failure_attribution.py --archive Data4Cyber_v3_2026.zip
```

Raw data are excluded from the release; obtain them from the publisher. The source model is unchanged; any future architecture modifications require a new model version and new prospective testing.
