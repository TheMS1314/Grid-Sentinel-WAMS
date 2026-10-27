# Phase 45 — split price context from unverified security review

## Outcome

Using already-frozen Phase 36 lane-ablation records, Phase 45 compares two **post-hoc research reporting policies**. No threshold or model is optimized and no new attack dataset is claimed:

1. **Four-lane OR research alert**: frozen physics, Modbus unexpected writer, ARP claim mismatch, or price-regime novelty.
2. **Security-review-only**: frozen physics, Modbus, or ARP. Price-regime novelty is *still displayed* as separate contextual information and **not treated as verified MQTT compromise**.

| Metric on previously examined S1–S6 | Four-lane OR | Security-only |
|---|---:|---:|
| Macro row F1 | 0.98943 | 0.83355 |
| S1–S5 F1 | Unchanged | Unchanged |
| S6 row F1 | 0.99558 | 0.06034 |
| S6 true-positive attack rows | 1,350 | 42 |
| S6 benign false-positive rows | 12 | 0 |

The price lane uniquely explains **1,308 S6 attack-labeled review rows** and **12 S6 benign false-positive rows**; removing it from the security stream removes both. Reducing nuisance alarms by suppressing or hiding this lane would silently destroy almost all S6 coverage. It is therefore scientifically inappropriate to claim that a price-disabled security detector retains 98.94% performance.

## Decision

**Maintain two visibly distinct research categories:**

- Security review: nonprice meter/protocol anomalies, still unauthenticated review evidence (not proof of hostile intent).
- Price-regime context: unusual observed price, not an authenticated intrusion alarm; needs independent publisher/tariff provenance and ideally a new trusted MQTT integrity signal.

The deployed FastAPI meter-only detector remains unchanged. The four-lane comparator and new category language are historical evidence only. The private dashboard now includes a Price Context tradeoff panel backed by `/api/price-context-research`, and explicitly lists the benign S0 synthetic tariff offsets from Phase 44. The backend JSON is frozen in `smartgrid_platform/backend/model/phase45_price_context_tradeoff.json` for offline Docker availability.

## Limitations and next experiment

This is **not an unbiased comparison**, because all scenarios and the original threshold/persistence choices have already been examined. The Phase 44 additive offsets are synthetic; no complete four-lane packet replay was conducted under those modified prices. A future independent-site collection should include benign tariff schedule changes, signed/authenticated price provenance, S6-like malicious publisher alterations, trusted attack windows, and complete coverage records. Commit policy and sensor inventory before obtaining labels, then run the Phase 42 sealed workflow. Requiring trusted MQTT origins is a new input/sensor capability, not just a classifier threshold adjustment.

## Reproduce and checks

```bash
python data4cyber_price_context_policy.py
python -m unittest -v test_data4cyber_price_context_policy
```

Inputs are the bundled Phase 36 four-lane JSON and Phase 44 stress JSON; output is a recomputed aggregate and scenario tradeoff. Existing backend API and React production-build tests also cover the evidence presentation. No paper was produced.
