# Phase 55 — Normalized MAC novelty, benign-only calibration

## Experiment

The Phase 54 alert threshold was a retrospectively selected absolute packet count (>3). This phase examines a more defensible exposure-normalized threshold: unseen Ethernet-source-MAC packet count divided by **all captured frames**. Existing vantage-matched inventories remain fixed from the normal captures `001` (central switch) and `069` (PLC port). No policy updates are made during the test.

Each viewpoint has one **calibration** normal capture (`002` / `070`) and one *later held-out* normal capture (`003` / `071`). A one-sided Poisson 95% upper-bound rate is computed using only the earlier benign capture; it is frozen before scoring the later normal and all publisher-labeled attack-scenario captures. Packet independence is an unrealistic assumption, so this is a heuristic rate bound, not a warranted 95% live-site guarantee. The source feature and dataset were chosen post hoc in earlier phases.

| Viewpoint | Benign calibration | Unknown MAC frames / total | Conservative cutoff per 100k frames | Later normal rate per 100k |
|---|---|---|---:|---:|
| Central switch | 002 | 2/84,477 | 7.4527 | 2.3717 (003) |
| PLC port | 070 | 0/8,116 | 36.9114 | 0 (071) |

On the **83 publisher-labeled attack scenario files**, this benign-only rate threshold flagged **83/83**. It also flagged **0/2** later benign files. Minimum attack rate was **66.2557 per 100,000 frames**, greater than either matched cutoff. The Phase 54 absolute-count comparison flags the same attacks but its threshold was chosen with knowledge of both held-out benign captures and attack results.

## Interpretation and boundaries

This is meaningful progress in resisting capture-duration confounding and in separating benign calibration from subsequent scoring. It is **not independent-site, prospective, packet-level, or event-level validation**. There are only two later benign files, each a related capture from one laboratory testbed. Scan recordings share attacker infrastructure and may be highly correlated. The false-alert burden during real maintenance, equipment replacement, IP/MAC spoofing, legitimate topology changes, or other sites remains unknown.

Crucially, the scored Ethernet-MAC lane is a research-only audit; the deployed frozen meter-integrity model and the earlier four-lane Data4Cyber benchmark are not changed or re-evaluated here. Until authenticated vantage metadata and truly prospective independent captures exist, the project readiness estimate remains **88/100**.

Reproduce the experiment on the packaged Phase 54 JSON with `python cyber4ot_benign_calibrated_rate.py reports/SmartGrid_Phase54_Full_Cyber4OT_Audit_2026-10-27.json`. Full per-capture scores and input SHA-256 are in `SmartGrid_Phase55_Benign_Only_Rate_Calibration_2026-10-27.json`.
