# Grid Sentinel — independent reviewer-style research readiness audit

Date: 2026-10-27. **Results assessment only: no manuscript, submission, or new tuned model.**

## Decision

- Current conference-paper research quality estimate: **6.5/10** for a suitably scoped applied/security-for-power conference; high-competition flagship expectations may be tougher.
- Current journal-paper research quality estimate: **4.5/10** for a reputable technical journal; strong novelty/field-validation journals would require more.
- Scores are **subjective readiness judgments**, not acceptance probabilities or impact-factor rankings. Do not equate application deployment completion with scientific publication readiness.

## Recomputed historical Data4Cyber S1–S6 evidence

Using `research_evidence_audit.py` to derive metrics from bundled publisher-based confusion matrices, excluding the S0 clean holdout and the supplemental S1-alt:

| Metric | Recomputed |
|---|---:|
| Macro F1 | 0.989425 (98.9425%) |
| Pooled micro F1 | 0.990043 (99.0043%) |
| TP / FN | 6,612 / 64 |
| FP / TN | 69 / 4,019 |
| Benign rows | 4,088 |
| Benign-row alert fraction | 69/4088 = **1.6879%** |
| Benign false alert episodes | 17 |
| S0 clean holdout | 4/360 alerted rows, 2 episodes |

Important: The 17 episodes span attacked campaigns' internal benign periods, not 17 authenticated independent false incidents. The one-hour or 24-hour site alert burden is **not measured** by the above fractions. Scenario F1 is derived from correlated per-second labels and model choices made after these campaigns were inspected.

The Phase 37 ablation independently records removal of physics yielding slightly *higher* macro F1 (0.98945), while losing 35 exclusive positive rows and suppressing 28 exclusive benign alerts. This undermines any blanket assertion that physics strictly improves precision/F1 in every case. The model nonetheless provides a separate physical mechanism.

The Phase 50 real-Modbus external transfer RF experiment has 492 false-positive **rows**, despite its high attack-row recall. Domain transfer and false-alarm burdens must be reported together.

## Publication strengths

1. Multi-domain evaluation rather than a single train/test split.
2. Physics + Modbus writer-role + ARP identity + price novelty, with interpretable mechanisms.
3. Strong reproducibility: publisher checksums, complete source, frozen interfaces, negative controls, ablations, automated CI, and private application.
4. Explicit failures: S1/S2 meter-only weakness, ping-scan misses, MAC novelty instability, GOOSE out-of-scope and short benign controls.
5. Working private React/FastAPI/PostgreSQL/Docker system and persistence recovery.

## Critical review risks (highest first)

1. **Label-informed architecture selection:** Four-lane OR combination and 5s/2s holds were selected after examining the same scenarios. Do not market the 98.94% as unbiased held-out attack detection.
2. **Limited independent labels:** New TU Delft scanning data lack event-level truth; KIOS GOOSE attacks are protocol-out-of-scope. Neither repairs the four-lane selection bias.
3. **Originality needs a single falsifiable contribution:** Current work combines several known rules and a platform; merely increasing F1 by post-hoc OR fusion is unlikely to satisfy demanding journals.
4. **Operational false alerts and attribution:** Unauthenticated IP/MAC/price sources cannot reliably prove attackers. Real benign maintenance and novel tariffs can trigger false alerts.
5. **No prospective field evidence:** No independent utility/long benign site-days, authenticated event onset, or transfer of the entire four-lane system as frozen live inference.

## Feasible priority sequence

1. **Complete now:** Independent arithmetic and source-integrity audit; freeze published numerical definitions and exclusion list.
2. **Complete now:** Mechanism-wise attack-family support matrix, including explicit abstain vs detect; explain weak S1/S2 physics-only cases.
3. **Complete now:** Package one coherent conference *claim* around honest cross-domain selective review, negative controls and failure disclosure; no paper until separately requested.
4. **Complete now:** Add strict CI checks to prevent claim drift; finalize private demo and ZIP.
5. **External prerequisite:** Publisher-authorized independent time-stamped attack+benign data, ideally 24+ hours benign with local sensor provenance, and fully blind rerun without thresholds changed.
6. **After new data:** Evaluate event onset latency, true/false alert episodes per observed site-day, calibration, confidence intervals and class-specific abstentions; journal then reassessed.

## Positioning

Suggested conference contribution (not a paper title): **Auditable, protocol-scoped cyber-physical review across heterogeneous power-network datasets, with explicit abstention and false-alarm limitations**. Avoid claiming universal attack attribution or 98.94% prospective detection.

No user credentials accessed, no control commands sent, no paper written.
