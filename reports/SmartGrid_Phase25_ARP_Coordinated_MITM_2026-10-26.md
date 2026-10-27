# Grid Sentinel Phase 25 — Passive ARP Identity Evidence for Coordinated MITM

26 October 2026 — research-only, **no paper**, no packet transmission or grid control.

## Outcome

Added a third, strictly passive **ARP IP/MAC claim-consistency audit** to complement the frozen physics-integrity and newly explored Modbus write-source research heads. The expected IP/MAC pairs come only from the publisher's S0 benign inventory (seven populated records). The audit examines released pcapng, identifies claims inconsistent with that inventory, aligns observed packet timestamps with the publisher's 1-Hz activity labels, and reports stand-alone and simple OR behavior. It does **not** authenticate MAC/IP identity, prove an attack, or replace a protected anchor. Source addresses and ARP packets can be forged.

### Main previously missed problem: S5 MITM phase 2

| Detection evidence | Review rows / 582 labeled phase-2 rows | Row coverage |
|---|---:|---:|
| Frozen local meter identities | 98 | **16.84%** |
| Raw ARP IP/MAC discrepancy | 287 | **49.31%** |
| **Physics OR raw ARP** | **340** | **58.42%** |
| Physics OR five-second held ARP event (exploratory posthoc) | 582 | 100% |

The phase-2 result establishes that an independent network-layer observable can help where coordinated measurements no longer violate local arithmetic constraints. The last row **does not** mean perfect attack attribution: persistence extends a small number of ARP claims into neighboring 1-Hz rows and may manufacture deceptively strong sample-level recall. It is a sensitivity case only, **not** the default policy or a blind model improvement.

## Stand-alone and fusion replay results: instantaneous ARP claims

| Scenario | Frozen physics F1 | ARP evidence F1 | Simple OR F1 | Clean FPR of OR |
|---|---:|---:|---:|---:|
| S0 final 360 clean rows | N/A | N/A | N/A | **4/360 = 1.11%** (physics only) |
| **S3 Battery MITM** | **0.56875** | 0.66276 | **0.81883** | 4/888 = 0.45% |
| S4 Loads/PV MITM | **0.99202** | 0.65633 | **0.99202** | 6/541 = 1.11% |
| **S5 Multi-meter MITM** | **0.77092** | 0.65298 | **0.89190** | **7/459 = 1.53%**, versus 3/459 = 0.65% physics-only |

The S0 capture produced **872 ARP packets and no known-IP/MAC contradictions**. The attack scenario captures contain 904 (S3), 2,429 (S4), and 2,068 (S5) contradictory ARP packet claims. Many assert that legitimate metering/management IPs have MAC `98:e7:43:a2:c7:b1`, which matches the attacker-node MAC in the corresponding scenario's publisher metadata. These are *recorded protocol claims*, not independently authenticated origins. Unknown ARP sender IPs were excluded from the rule, limiting recall.

On S5, ARP mismatch observations also caused **four benign-labeled alert rows**. Combined with three physics false positives, the simple OR worsens clean false alarms. This is a serious deployment blocker, not a minor tradeoff.

## Five-second persistence stress test (posthoc)

| Scenario | Five-second ARP-only F1 | Five-second physics OR ARP F1 | Clean FPR of five-second OR |
|---|---:|---:|---:|
| S3 | 0.99725 | **0.99506** | 0.45% |
| S4 | 0.98997 | 0.99202 | 1.11% |
| **S5** | 0.98346 | **0.98956** | **3.05%** |

These attack campaigns were already inspected before evaluating the persistence duration. Very high apparent performance under posthoc hold policies does **not** imply unseen-grid generalization or sustainable alarms per operating day. The five-second policy is displayed as historical sensitivity evidence only; the shipped FastAPI `/api/analyses` model is unchanged.

## Engineering implementation and tests

- `data4cyber_passive_arp_audit.py`: S0 role mapping, ARP sender claim extraction and timestamp-aligned offline reports.
- `data4cyber_arp_two_lane_benchmark.py`: physics vs ARP vs OR comparisons, including explicit attack-phase overlap.
- `test_data4cyber_arp_lane.py`: two synthetic pcapng test cases for legitimate and mismatched ARP claims, **2/2 passed**.
- Results JSONL for instantaneous and five-second posthoc sensitivity included in the source release.
- FastAPI `GET /api/arp-research` serves **frozen historical evidence only**, not live packet ingest. React Research evidence page now compares S0/S3/S4/S5 and notes spoofability and false alarms.
- Updated React production build: **passed**. FastAPI API suite: **9/9 passed**. Other offline unit suites: **8/8 passed**, for a total of **10** offline unit tests including the new ARP fixtures.
- Existing six reproducibility commands remain passing. Scientific readiness remains **3/10** based on the earlier stringent independent evidence requirements; this is not an engineering completion percentage.

## Honest limits and the next 10/10 gate

1. **No cryptographic provenance.** MAC/IP mapping is a useful observation from this one testbed, not a trusted sender. A privileged attacker can spoof both. An independent mirrored switch port, protected tap, signed device identity or corroborating anchor would strengthen attribution.
2. **No blind test campaign.** This mechanism was designed after knowing the S3–S5 attack families and seeing the same dataset. Obtain a sealed independent ARP/MITM test session and long diverse clean/maintenance traffic *before* choosing persistence thresholds and fusion weights.
3. **False positives.** S5 simple OR and five-second OR raise benign-row FPR to 1.53% and 3.05%, which is unacceptable without much longer benign validation and episode-based triage. The alert counts are also serially dependent.
4. **S6 remains unaddressed.** No MQTT broker traffic on conventional 1883/8883 was visible in the S0/S6 tapped recordings; authentic publisher feeds and broker audit logs must come from another validated vantage point.
5. **Physically coherent FDI remains possible.** ARP evidence helps only where spoofed ARP claims are visible. Coherent manipulation without those claims still needs trusted electrical anchors and verified AC network models.
6. **Live deployment not verified.** No Docker daemon was available for PostgreSQL/Compose integration or production networking/identity tests. No SCADA, PLC or control access is wired into the software.

## Reproduce

With the independently downloaded publisher `Data4Cyber_v3_2026.zip` and Python packages `dpkt`, `numpy`, `pandas`, `scikit-learn`:

```bash
python -m unittest -v test_data4cyber_arp_lane
python data4cyber_passive_arp_audit.py
python data4cyber_arp_two_lane_benchmark.py
python data4cyber_arp_two_lane_benchmark.py --hold-seconds 5
```

All experimental scripts read captured traffic; none send packets or operate grid equipment. Raw third-party captures are not redistributed in the project ZIP. **No research paper has been written.**
