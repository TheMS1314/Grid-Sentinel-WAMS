# Phase 38 — Temporal Attribution of Four-Lane False Alerts

Date: 26 October 2026. **Post-hoc observation study; not deployed.**

## Question

When the four-lane historical research fusion warns on a row labeled benign,
does that false alert occur close to an annotated attack, or during a more
distant part of the same recorded scenario? We must answer while retaining
**every** false positive in the primary FPR.

## Data and method

- Reused the publisher's checksum-verified Data4Cyber v3 archive and the
  Phase 37 four-lane architecture (unchanged meter model, 5s Modbus source
  hold, 2s ARP claim hold, frozen S0-calibrated price anomaly threshold).
- Took every row where `attack_active` is false and combined alarm is true;
  computed absolute time to the nearest row with `attack_active` true within
  the same scenario.
- Reported three disjoint windows: **≤5 seconds**, **>5 to ≤30 seconds**,
  and **>30 seconds**. Also retained the separate attack-free S0 holdout.
- These windows explain correlation with annotations, **not** an online
  threshold or a permissible label adjustment. Ground-truth attack timing
  is unavailable to a live detector.

| Scenario | All false-alert rows | ≤5s from attack | >5–30s | >30s |
|---|---:|---:|---:|---:|
| S0 clean last 20% (no attack in run) | 4 | 0 | 0 | 4 |
| S1 PV Modbus | 21 | 5 | 9 | 7 |
| S2 Battery Modbus | 15 | 5 | 5 | 5 |
| S3 Battery MITM | 4 | 2 | 1 | 1 |
| S4 Loads/PV MITM | 6 | 3 | 0 | 3 |
| S5 Multi-meter MITM | 11 | 5 | 6 | 0 |
| S6 MQTT/price | 12 | 5 | 7 | 0 |
| S1-alt extra PV reference | 23 | 7 | 6 | 10 |

**S1–S6 primary set:** 69 total falsely alerted benign seconds: **53/69
(76.81%)** within 30 seconds of a labeled attack, and **16/69 (23.19%)**
farther than 30 seconds away. S0's four false alerts are reported separately.

The far-from-attack descriptive clean-row alert rates are: S1 7/765 (0.915%),
S2 5/745 (0.671%), S3 1/768 (0.130%), S4 3/448 (0.670%), and S5/S6 zero
over 324/408 such within-run clean rows. These are **not independent field
false-alarm rates**, confidence bounds, or proof that the system can safely
operate with zero alerts on a new network.

## What this establishes and does not

There is measurable temporal adjacency: much of the remaining benign-alert
burden is close to attack annotations. Causal event persistence, recovery
windows, and data freshness deserve prospective audit. However, temporal
proximity does **not** reveal the cause of each false positive. Some may be
label boundary effects; others may be independently faulty measurements or
algorithmic false alarms.

**No alarm suppression was implemented**: choosing not to count alerts merely
because we know where attacks occurred would be evaluation leakage and an
invalid deployment strategy. The exact Phase 36 macro F1 stays **0.98943**;
the real false-positive counts and rates are unchanged.

The React Research Evidence page displays this table alongside the four-lane
scores and ablation, all explicitly marked exploratory. No raw third-party
captures are included in the release. The API remains research-only and the
deployed inference path remains the frozen meter self-consistency head.

## Reproducibility

Install `numpy`, `pandas`, `scikit-learn` and `dpkt`, place the original dataset
ZIP beside the scripts, and run:

```bash
python -m unittest -v test_data4cyber_temporal_false_alerts
python data4cyber_four_lane_fusion.py --output timing.json
```

The produced JSON includes per-scenario `false_alert_temporal_attribution`
with full, disjoint row accounting and denominators.

## Blockers to 90%+ overall readiness

Field data from independent topologies/operators, authenticated Modbus and
MQTT principals, sufficiently long benign monitoring, secure maintenance
provenance and target-machine Docker/Postgres restoration remain unverified.
This additional scientific diagnosis does not change the qualitative overall
project estimate of **~82/100**.
