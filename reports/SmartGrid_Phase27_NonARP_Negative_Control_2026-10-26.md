# Grid Sentinel Phase 27 — non-ARP negative controls

Date: 2026-10-26. **Within-dataset stress test; not a blind external validation or a production approval.**

## Objective

The passive ARP IP/MAC consistency lane improved detection of Data4Cyber S3 and S5 MITM activity in the earlier phases. Phase 27 asks whether the same ARP lane spuriously activates during *other* attack families. We replayed the published packet captures for S0, S1, S1-alt, S2 and S6, retaining the S0 device inventory and the unchanged detection rule. We tested hold durations 0, 2 and 5 seconds; all yielded identical zero-alert counts on these non-ARP controls. This is a negative-control analysis, not a retraining run.

## Results (2-second candidate shown)

| Scenario | Observed ARP packets | Known-IP/MAC mismatches | Clean seconds | Attack-activity seconds | ARP alert seconds |
|---|---:|---:|---:|---:|---:|
| S0 benign, reserved final 20% | 872 | 0 | 360 | 0 | 0 |
| S1 Industroyer PV | 11,723 | 0 | 885 | 913 | 0 |
| S1-alt, reserved variant | 2,291 | 0 | 882 | 910 | 0 |
| S2 Industroyer BSS | 1,769 | 0 | 865 | 903 | 0 |
| S6 MQTT supply-chain | 11,794 | 0 | 450 | 1,350 | 0 |
| **Total** | **28,449** | **0** | **3,442** | **4,076** | **0** |

No known-IP/MAC mismatch packets were observed in these five captures, hence there were zero alert seconds at all tested persistence durations. The 4,076 seconds of non-ARP *attack activity* are not positive examples of ARP spoofing, and we intentionally do not credit or penalize the ARP detector's activity recall against these unrelated labels. The clean windows total 3,442 seconds, but they share the same dataset infrastructure and do not constitute five independent deployment sites.

## Interpretation and limitations

This reinforces a narrow and useful claim: within the sampled Data4Cyber topology, the fixed S0 ARP identity-claim rule did not alert on the other observed attack campaigns. It does **not** demonstrate that the real-world ARP false-positive rate is zero. The inventory can become stale through DHCP reassignment, MAC rotation, NIC replacement, virtual interfaces, or failover; capture vantage points can omit relevant ARP frames. ARP packets also have unauthenticated sender claims, so even a mismatch cannot establish who transmitted it. Attacker behavior or legitimate maintenance in the same topology could change the observed burden.

The prior Phase 26 S5 two-second candidate still has a 2.397% benign-row alert rate **inside the S5 attack capture**, compared with 3.050% for five seconds. The present negative controls do not supersede that figure. A deployable threshold must be set using independent representative clean networks with frozen inventory-management rules, prospective attack streams and a predeclared false-alarm budget.

## Reproduction

```bash
python -m unittest -v test_data4cyber_arp_negative_control
python data4cyber_arp_negative_control.py --output SmartGrid_Phase27_NonARP_Negative_Control_2026-10-26.jsonl
```

Requires the public `Data4Cyber_v3_2026.zip`, the prior ARP audit scripts and Python dependencies `dpkt`, `numpy`, `pandas`. The source-release ZIP includes analysis code, tests and derived JSONL output, not third-party raw datasets. A new read-only `negative_controls` array is exposed in `/api/arp-research` and on the React Research Evidence page. **The operational model and threshold remain unchanged.** No research paper was written.
