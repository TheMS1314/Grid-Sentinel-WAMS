# Grid Sentinel Phase 28 — uncertainty of the zero-alert negative control

Date: 2026-10-26. **Results are historical and within one research topology. No field-performance certification, model retraining, or research paper.**

## Why this audit matters

Phase 27 found zero ARP claim mismatches across 28,449 observed ARP packets in S0, S1, S1-alt, S2, and S6, and zero alerts across 3,442 labeled-clean seconds. A zero observed count does not imply the real-world rate is zero, especially when time samples are correlated and the inventory and rules were chosen using the same dataset family.

## Exact one-sided 95% *conditional* upper bounds

For zero events in `n` **independent and representative** Bernoulli trials, the one-sided exact upper probability is

`p_upper = 1 - (1 - 0.95) ** (1 / n)`.

| Hypothetical trial unit | Observations | Observed events | Formal 95% upper probability if assumptions held |
|---|---:|---:|---:|
| One labeled-clean second | 3,442 | 0 | 0.086997% per second |
| One observed ARP packet | 28,449 | 0 | 0.01053% per packet |
| One entire scenario capture | 5 | 0 | 45.071973% chance of any scenario failure |

**None of these is an independently validated operational confidence interval.** Consecutive seconds and packets are strongly dependent. All five scenarios use a shared research topology, inventory, and capture-generation process. Even scenario-level independence is hypothetical. The rule was developed after the dataset campaigns were examined, which adds selection bias. The radically different numerical bounds demonstrate sensitivity to the chosen experimental unit; they do **not** imply an actual risk of 45% or an actual false-positive rate of 0.087%.

## Scientific interpretation

1. Keep the Phase 27 empirical observation: the ARP lane raised no alerts in these five non-ARP captures.
2. Do not turn that observation into a zero-FPR claim or promote the two-second persistence candidate to deployment. S5 still showed a 2.397% benign-row alert rate with two-second persistence in the exposed MITM capture.
3. To support a deployment-level specificity estimate, pre-register an event-level false-alarm budget, gather independent benign days across sites and network maintenance conditions, freeze the inventory and thresholds, then score incident-level alert rates with uncertainty clustered by independent site/day.
4. The method remains a spoofable network identity-claim consistency check, not authenticated attribution, and cannot authorize automated grid intervention.

## Reproduce from the packaged derived results

```bash
python -m unittest -v test_data4cyber_arp_uncertainty
python data4cyber_arp_uncertainty.py --output reports/SmartGrid_Phase28_ARP_ZeroAlert_Uncertainty_2026-10-26.json
```

No Data4Cyber raw dataset is needed for this particular audit: it operates on the previously verified Phase 27 JSONL outputs. The source ZIP retains reproducibility code and the complete historical evidence chain. Scientific acceptance remains incomplete until independent captures and the other published gates pass.
