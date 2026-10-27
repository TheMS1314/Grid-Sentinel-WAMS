# Phase 50: Two-Source, Leave-One-Domain-Out MITM Detection

Date: 27 October 2026 (India). Underlying published dataset: Elrawy et al., [Zenodo 8375657](https://zenodo.org/records/8375657), original ZIP checksum MD5 `8ceb392f6a69086635159ff5bd0fff17`.

## Goal and protocol

Can pooled training from **two** engineered-feature domains improve binary attack detection on a **third completely held-out** domain? The three domains are real Modbus (A–H), simulated Modbus (D5–D8) and simulated MMS (D1–D4). All rows in the held-out domain are excluded from model fitting, preprocessing, source weighting, and threshold selection. Within this single dataset publication, this is a stronger domain-exclusion test than Phase 48 leave-one-workbook-out, but still NOT multi-utility independent validation.

Binary label 1 is normal; all other published labels, including 50, are treated as attack. Features are IRTT/TTOC/MITR/MATR/NROC, optionally the published ARP poisoning indicator. The ARP indicator's passive availability and causal independence are **unverified**. Flow-only should be considered the more conservative feature set. Real/simulated groups have distinct acquisition regimes.

We predeclared four candidates before running the comparison, with no test-domain tuning: RF pooled with 300 trees/min leaf 5/balanced classes/seed 42; RF with equal source-domain total training weight; robust-scaled class-balanced logistic regression; histogram gradient boosting (100 iterations, learning rate .05 and L2=1). All missing-value imputers and scales are fit on sources only.

## Results: third domain held out (pooled flow + ARP)

| Target | RF pooled F1 | Domain-balanced RF F1 | Robust logistic F1 | Hist. boosting F1 |
|---|---:|---:|---:|---:|
| Real Modbus | .896653 | .896653 | .556565 | .900799 |
| Simulated Modbus | .915302 | .907724 | **.934927** | .921497 |
| Simulated MMS | **.947214** | .933135 | .945055 | .947137 |

With flow-only RF pooled, F1 is .895903 on real Modbus, .878667 on simulated Modbus and .894696 on simulated MMS. The difference when incorporating ARP, particularly in simulation, must be interpreted against feature-observability uncertainty.

### Real Modbus alert burden

When trained on both simulated domains, RF pooled flow+ARP yields TP 2143, FN 2, FP **492**, TN 2946 among 5,583 real-Modbus rows. Therefore precision is only .813283 although recall reaches .999068. Histogram boosting with ARP has FP 470, only a modest improvement. The logistic-with-ARP candidate produces **3,418 false positives**, almost every normal row, showing that candidate performance is unstable across domains. These are per-feature-row counts, not alarms/day.

### Simulated Modbus

Logistic-with-ARP gives TP 704, FN 8, FP 90, F1 .934927. The RF pooled candidate has TP 643, FN 69, FP 50, F1 .915302. Neither universally dominates: logistic improves attack recall but raises false alerts.

### Simulated MMS

RF pooled with ARP gives TP 646, FN 67, FP 5, F1 .947214. This promising score is not a validated frozen-system result and includes an indicator whose deployment provenance is not established.

## Integrity and interpretation

- The source/target evaluation excludes all target training rows and target statistics. There is **no leakage by target-domain normalization** in this script.
- We examined multiple model candidates on the same three held-out domains. The strongest model per target is a **post-hoc observation**, not an unbiased prospective selection. Do **not** promote it directly to production or represent its F1 as a site-wide estimate.
- Workbook experiments may share methods, simulator settings, network infrastructure, feature extraction and class-conditional artifacts. Neither the former 98.94% Data4Cyber post-hoc number nor this benchmark demonstrates real utility deployment generalization.
- No temporal/event-level label alignment, detection delay, calibration, real false-alert/day, access to a live grid, or utility-authorized tariff signing has been shown.

## Architecture implications

1. Keep **protocol-aware** lane routing. Treat source-domain/sensor provenance and feature health as explicit required context.
2. Carry **unscored/unsupported** separately from normal/attack when the domain is unvalidated. The Phase 49 source-only quantile gate rejected all real-versus-simulation transfers; a safe fall-back requires a collection/calibration plan rather than pretending these abstentions are detections.
3. Compare a model trained on multiple compatible environments against simple site-specific models using a prospective untouched target stream. Choose acceptable benign false-alert burden *before* scoring, not from the target labels.
4. Do not blend the external flow-feature classifier into the existing deployed four-lane replay until input semantics, timing and packet observability are verified.

## Reproduce

Install `numpy`, `pandas`, `openpyxl`, `scikit-learn`, then run:

`python external_mitm_leave_domain_out.py '/path/to/MITM Attack Datasets_V1.zip' --output reports/SmartGrid_Phase50_Leave_Domain_Out_2026-10-27.json`

`python -m unittest -q test_external_mitm_leave_domain_out`

The complete 24 comparisons and TP/FP/FN/TN counts are stored in the accompanying JSON. The third-party raw dataset is excluded from the distribution. No research paper was drafted. Physical-host Docker acceptance and independent-site testing remain open prerequisites for 90–100% completion claims.
