# Phase 37 — Four-Lane Contribution and False-Alert Ablation

Date: 2026-10-26. **Offline research result only; not deployed or blind tested.**

## Outcome

Reproduced Phase 36's four-lane post-hoc macro F1 **0.98943** on Data4Cyber
S1–S6, then switched off one evidence lane at a time. The public original
`data4cyber_dataset.zip` was independently downloaded again, verified at
164,148,991 bytes and publisher MD5
`20d81c975e5c37f453103cdadb052c9e` before running the audit.

| Lane disabled | Macro F1 with remaining lanes | Attack rows only the omitted lane detected | Benign alert rows solely caused by the omitted lane |
|---|---:|---:|---:|
| Meter consistency / physics | 0.98945 | 35 | 28 |
| Unauthenticated Modbus source role (5s) | 0.66770 | 1,772 | 21 |
| Passive ARP identity claims (2s) | 0.88202 | 1,024 | 8 |
| MQTT price-domain novelty | 0.83355 | 1,308 | 12 |

The last two columns count *mutually exclusive per-second labels*, relative to
the other three lanes, summed across S1–S6. They are **not** independent
attack incidents or authenticated source identifications. They cannot be added
to obtain the full detection total because many positive rows have alarms
from more than one lane.

### Important interpretive result

Removing meter-consistency slightly **raises** the arithmetic macro F1,
because the remaining network signals cover almost all of the same campaign
rows. The physics lane nevertheless detects 13 otherwise missed S4 rows and
22 otherwise missed S5 rows. It also creates 4 alerts on the separate S0
clean holdout and 28 false-alert rows across S1–S6 that other lanes would
not have created. These are legitimate false-alarm tradeoffs.

**Do not remove the physics lane based on this post-hoc result.** The network
signals are unauthenticated; independent benign maintenance, topology change,
real tariff schedules, and attacker adaptations could reverse the ordering.
The additional physics evidence supplies a different causal measurement
mechanism, not an automatically redundant sensor.

### Practical design consequence

- Keep the four signals **separately reported**, with source provenance and
  observability/abstention status, before field integration.
- Evaluate alert prioritization and event de-duplication against a prospective
  clean site-days dataset. Never suppress a signal based on published attack
  scenario IDs or label-informed grouping.
- Require independently verified inventory-change provenance for ARP,
  authenticated Modbus write sources, and trusted signed or cross-verified
  electricity-price publications before declaring an attacker.
- Preserve the present narrow live meter-detector implementation. The backend
  and React research screen contain only a **historical** ablation table.

## Reproduce

Obtain Data4Cyber v3 separately, install optional research dependencies
`numpy`, `pandas`, `scikit-learn`, and `dpkt`, then run:

```bash
python -m unittest -v test_data4cyber_four_lane_fusion
python data4cyber_four_lane_fusion.py --archive Data4Cyber_v3_2026.zip --output ablation.json
```

The ablation report in this package includes every per-scenario
`leave_one_lane_out` confusion matrix, unique positive counts and unique false
alert counts, plus macro summaries. The source ZIP does not redistribute
publisher packet captures.

## Outstanding external conditions

This analysis **does not increase independent scientific validation**: all
choices still use previously examined scenarios from one publisher topology.
There is no authenticated OT source provenance, prospective field-capture
evaluation, live Docker/Postgres run, or safe backup restore rehearsal.
Overall project completion remains a **qualitative ~82/100 estimate**, not
the 98.94% experimental row-F1 or a claim of 90% field readiness.
