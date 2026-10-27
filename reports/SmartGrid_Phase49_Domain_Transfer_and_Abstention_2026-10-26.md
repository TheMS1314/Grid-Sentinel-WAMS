# Phase 49: Out-of-Domain MITM Transfer and Conservative Abstention

Date: 26 October 2026. External source: Mohamed Faisal Elrawy et al. (2023), [published MITM smart-grid flow-feature dataset](https://zenodo.org/records/8375657). Original archive MD5: `8ceb392f6a69086635159ff5bd0fff17`. Raw source files are deliberately excluded from this project release.

## Key result

The high Phase 48 leave-one-workbook-out results are **not stable under train-on-one-environment/test-on-another evaluation**. We froze the same Random Forest architecture and features as Phase 48, trained separately on the entire named source experiment group, made *no* use of target labels or target statistics in training/imputation, and tested on the entire different target group.

| Source → target | Flow-only F1 | Flow+ARP F1 | Flow-only recall | Flow-only false positives |
|---|---:|---:|---:|---:|
| Real Modbus → simulated Modbus | .591716 | .593688 | .421348 | 2 |
| Real Modbus → simulated MMS | .771478 | .768966 | .629734 | 2 |
| Simulated Modbus → real Modbus | .894781 | .897216 | .999068 | 502 |
| Simulated Modbus → simulated MMS | .868400 | .879001 | .772791 | 5 |
| Simulated MMS → real Modbus | **.555124** | .555124 | 1.000000 | **3438 (every normal row)** |
| Simulated MMS → simulated Modbus | .887324 | .893617 | .973315 | 157 |

These are binary class results on differently engineered flow-feature workbooks. They do **not** measure frozen Data4Cyber four-lane model performance; nor do source/target groups constitute distinct physical utilities. The wide transfer gap is nevertheless a direct falsification of the idea that the Phase 48 >95% within-domain scores imply universal smart-grid attack detection.

## Sensor loss

For each transfer we replaced one input sensor column at a time with missing values, using the **source-fitted** training median imputer. Several combinations fall to F1 = 0 (including dropping MITR in real-Modbus → simulated targets and dropping TTOC in simulated-Modbus → real Modbus). This is a single-feature-loss stress test, not an adversarial-optimal attack evaluation. Every combination and confusion count appears in the machine-readable JSON.

## Source-support abstention diagnostic

We separately evaluated an intentionally simple gate: accept a complete, finite feature row only if **every feature** lies within the 0.5th–99.5th percentile of that feature's *source training* distribution. No target percentile fitting, target threshold tuning, or target label access occurs. Predictions outside the range are **abstained**, not marked normal or counted as correct.

This is an **experimental coverage diagnostic**, not a validated operational out-of-distribution detector:

| Training → test (flow-only) | Accepted row coverage | Accepted attack coverage | End-to-end attack recall (abstentions count as missed) |
|---|---:|---:|---:|
| Real Modbus → simulated Modbus | 0.00% | 0.00% | 0.00% |
| Real Modbus → simulated MMS | 0.00% | 0.00% | 0.00% |
| Simulated Modbus → real Modbus | 0.00% | 0.00% | 0.00% |
| Simulated Modbus → simulated MMS | 29.89% | 77.98% | 55.26% |
| Simulated MMS → real Modbus | 0.00% | 0.00% | 0.00% |
| Simulated MMS → simulated Modbus | 95.93% | 94.66% | 92.28% |

The gate is extremely conservative and rejects *all* rows in every real-versus-simulation direction. This avoids offering a misleading model decision but is operationally **unusable without a site-specific acceptance and calibration process**. Do not interpret zero accepted-row false positives as a high-performing detector.

## Deployment implication

- Treat external domain, source feature semantics, protocol type, packet/sensor completeness and version as explicit prerequisites. A mismatch should lead to **unscored / needs calibration**, not a trustworthy benign label.
- Do not combine meters, Modbus, MMS and tariff measurements into a single generic input solely because they all concern smart grids.
- For a *real* production objective, collect time-aligned passive packet streams and meter measurements at a consented isolated site; precommit calibration and evaluation. Estimate false alerts per day, attack-family and malicious-event recall, rejection/abstention rate and calibration drift, with an untouched run.
- The front-end and Docker files are engineering artifacts; no private-host smoke test, trusted utility signer, or independent production test is proven here.

## Reproduce

Install `pandas`, `numpy`, `openpyxl`, `scikit-learn`; run:

`python external_mitm_domain_transfer.py '/path/to/MITM Attack Datasets_V1.zip' --output reports/SmartGrid_Phase49_External_Domain_Transfer_2026-10-26.json`

`python -m unittest -q test_external_mitm_domain_transfer`

All reported results derive from verified original workbooks; no paper has been written. **Research/deployment readiness must not be inflated to 90–100% on these exploratory results.**
