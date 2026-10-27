# Grid Sentinel Phase 44 — price-regime robustness negative control

## Result from actual held-out S0 benign observations

We used the official `Data4Cyber_v3_2026.zip` S0 benign CSV, kept the previously frozen price calibration procedure (first 60% training, next 20% threshold selection), and evaluated the final **360 attack-free, previously examined** seconds under predefined additive synthetic tariff shifts. Only the price column was altered: this is a counterfactual simulation, not new observed grid traffic or a real-world attack campaign.

Frozen calibration: median center €0.0086/kWh, scale €0.0362/kWh, threshold 1.801105 normalized deviations.

| Synthetic additive price shift | Benign review seconds / 360 | False-review fraction |
|---|---:|---:|
| −€0.10/kWh | 360 | 100.00% |
| −€0.05/kWh | 360 | 100.00% |
| −€0.02/kWh | 340 | 94.44% |
| −€0.01/kWh | 340 | 94.44% |
| €0.00/kWh | 0 | 0.00% |
| +€0.01/kWh | 0 | 0.00% |
| +€0.02/kWh | 0 | 0.00% |
| +€0.05/kWh | 0 | 0.00% |
| +€0.10/kWh | 0 | 0.00% |

This notable **asymmetry** comes from the distribution of the measured S0 held-out prices and the frozen center; it does **not** imply that higher tariffs are generally safe. These are synthetic offsets chosen to test failure modes. Shifts were not a new attack-label test, and the scenarios were already inspected by project researchers.

## Consequences for architecture and research claims

- A tariff novelty detector is a **regime-change sensor**, not authenticated proof that an MQTT publisher was compromised. It may react to legitimate pricing changes.
- The post-hoc four-lane research fusion uses a logical OR: one price-lane alert suffices to create a fusion review. Consequently, any clean tariff shift that triggers the price lane also triggers the fusion, even if all other lanes are quiet. This is a design-level implication; the phase ran the price-only stress, **not** an entire four-lane packet replay under changed tariffs.
- **Do not** improve apparent macro F1 by tuning a new price threshold or shift sign on these same previously seen rows. That would further compromise validity.
- Recommended next architecture gate: validate a frozen, independently attested tariff schedule/publisher identity and separate `PRICE_REGIME_CONTEXT_REVIEW` from confirmed malicious claims. Explicitly measure the alert burden during benign pricing maintenance on **new** collection days/sites.
- The existing exploratory four-lane S1–S6 macro F1 of 0.98943 remains unchanged, is not a field result, and must be interpreted alongside this sensitivity.

## Reproduce

Obtain official v3 raw research ZIP independently and place it adjacent to the script; it is excluded from source releases. With `numpy`, `pandas` and `dpkt` installed:

```bash
python -m unittest -v test_data4cyber_price_shift_stress
python data4cyber_price_shift_stress.py --archive Data4Cyber_v3_2026.zip
```

Full measured table is in `SmartGrid_Phase44_Price_Shift_Stress_2026-10-26.json`. These results reveal a limitation rather than a higher performance score. Real site readiness is **not** upgraded based on this result.
