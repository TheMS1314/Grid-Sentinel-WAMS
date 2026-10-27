# Phase 36 — Four-Lane Data4Cyber Research Fusion

Date: 2026-10-26. **Research evaluation, not a deployed model or a research paper.**

## Major result

A four-signal *post-hoc* OR fusion achieved **macro F1 0.98943** across the six
published S1–S6 Data4Cyber scenarios. Each scenario F1 exceeds 0.978, but
this is **not independent model validation**: the family-specific lanes and
2s/5s alert persistence were chosen after studying the same campaigns. Do
not characterize this as production 98.94% accuracy, or as proof that it will
generalize to a new network.

The archive was downloaded directly from the publisher's [Zenodo v3 record](https://zenodo.org/records/22953576):
`data4cyber_dataset.zip`, 164,148,991 bytes, checked MD5
`20d81c975e5c37f453103cdadb052c9e` (matches published file checksum).
Third-party raw data are excluded from the redistributable code ZIP.

## Per-campaign result

| Evaluation scenario | Four-lane F1 | Benign sample alert rate | Benign false-alert episodes |
|---|---:|---:|---:|
| S0 clean chronological last 20% (360 rows) | N/A | 1.111% (4/360) | 2 |
| S1 PV Modbus manipulation | 0.97812 | 2.373% (21/885) | 5 |
| S2 BSS Modbus manipulation | 0.98675 | 1.734% (15/865) | 4 |
| S3 battery MITM | 0.99341 | 0.450% (4/888) | 3 |
| S4 loads/PV MITM | 0.99202 | 1.109% (6/541) | 2 |
| S5 multi-meter MITM | 0.99067 | 2.397% (11/459) | 2 |
| S6 price/MQTT compromise | 0.99558 | 2.667% (12/450) | 1 |
| S1-alt additional PV Modbus reference | 0.97753 | 2.608% (23/882) | 6 |

The mean F1 excludes the S0 clean run and extra S1-alt run. Each attack row
receives the publisher's `attack_active` label, which can include preparatory
periods; a row score is not authenticated attack-source attribution. Per-run
benign observations can be adjacent to attacker activity and are not independent
deployment-wide normal operation.

## Architecture and evidence levels

1. **Meter consistency:** unchanged, frozen 15-feature detector. Especially
   effective on the narrow S4 total-vs-phase mismatch.
2. **Modbus writer role:** S0 management-system IP allowlist; 5s causal hold
   selected after inspecting S1/S2. Detects unauthorized-looking write-source
   claims, **not cryptographically authenticated initiators**.
3. **ARP identity claim mismatch:** S0 known IP/MAC mapping; 2s causal hold
   selected after inspecting S3/S5. An authorized NIC replacement can look
   exactly like spoofing, as Phase 32's counterexample demonstrated.
4. **Price-domain novelty:** price center/scale trained on chronological S0
   first 60%, fixed 99th-percentile threshold on next 20%. No attack labels
   used to fit this scalar threshold. It triggers on S6's 2.1–2.3 price
   regime versus S0's roughly -0.057–0.009 observed values. On S6, 12
   benign normal-price rows **after** attack were flagged; none was proven
   to be a pre-attack alert. The price lane did not fire in S1–S5 or S1-alt
   within this same dataset. Still, a legitimate new tariff or other site
   pricing regime might trigger it, and without signed publisher provenance
   it cannot authenticate an MQTT compromise.

### Negative-control result

The exploratory S0-observed Modbus register-address policy found **zero**
additional alerts relative to the established write-source policy, despite
matching the benign S0 observation window and processing the same packet
captures. This candidate was **not retained** as an extra deployed detector.

An S0-calibrated IsolationForest with contextual tariff/SOC inputs yielded
S6 F1 0.0660 and benign FPR 6.22%, versus a physical-only IsolationForest S6
F1 0.1492 and benign FPR 14.22%. Both perform poorly and are not credible
replacements for the mechanism-specific price novelty probe.

## Essential limitations

- **Selection bias:** all these scenario attack types were known during lane
  selection. OR fusion makes row F1 larger, but the resulting estimate is
  optimistic; the high macro number does **not** upgrade independent-science
  readiness gates.
- **No verified principals:** source IPs and ARP claims can be spoofed. The
  tariff scalar is not cryptographically signed or matched to a trusted order.
- **Correlated observations:** scenarios share a publisher testbed; row-F1
  and per-sample false-alert fractions are not site-level CIs or prospective
  rates.
- **False alarms remain material:** 1–2.7% benign-row alert rates in several
  campaigns would be unacceptable for unattended operations unless validated,
  triaged and substantially reduced.
- **No new real-world dataset:** this study reproduces and extends the same
  Data4Cyber release. Sherlock's IEC 60870-5-104 channels need a separate
  model family; mismatched schema transfer would be invalid.
- **Not deployed:** the private FastAPI app still serves the narrow frozen
  meter-integrity assessment. Its Research Evidence page displays a clearly
  marked snapshot of these results. No automatic grid control or attack
  traffic generation was added.

## Reproduce

Install optional research modules `numpy`, `pandas`, `scikit-learn`, `dpkt`;
obtain publisher's v3 dataset ZIP and rename it `Data4Cyber_v3_2026.zip`
alongside the scripts. Then run:

```bash
python -m unittest -v test_data4cyber_four_lane_fusion test_data4cyber_s6_price_shift_audit test_data4cyber_modbus_register_audit
python data4cyber_modbus_register_audit.py --output register.jsonl
python data4cyber_s6_price_shift_audit.py --output price.json
python data4cyber_four_lane_fusion.py --output fusion.json
```

Source-level and report artifacts accompany this release. The frontend and
backend show only compact historic metrics, never third-party raw packet
captures.

## Next release gates

1. Pre-register a frozen, fully specified four-lane architecture against
   independent acquisition from a **different** network/operator.
2. Verify endpoint identity/inventory changes and signed tariff publication;
   abstain when trusted provenance is absent.
3. Quantify site-days of benign monitoring, alert episodes/day, alert latency,
   class-specific misses and label adjudication in a prospective blind test.
4. Deploy privately and rehearse PostgreSQL backup restoration on owner's
   machine, without exposing unprotected endpoints to the internet.

**Status:** major *within-dataset research* improvement, not proof of a
greater-than-90% completed field deployment. The prior qualitative project
readiness number remains unverified and must not be mistaken for F1.
