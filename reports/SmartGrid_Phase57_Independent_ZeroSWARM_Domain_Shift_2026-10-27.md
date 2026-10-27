# Phase 57 — Independent Zero-SWARM industrial PCAPs: success and failure

Source: [Zero-SWARM normal and malicious packet captures](https://zenodo.org/records/15082260), published by Lazaridis and Mpatziakas through Zenodo. This is a **different industrial factory/testbed**, not a smart-grid deployment. All four files were downloaded independently and publisher MD5 checked. Raw PCAPs are **not redistributed** in the source ZIP.

## Protocol

- Source-MAC inventory enrolled on first 600 seconds of `ZeroSWARM Normal data_v2b.pcap` (59,663 Ethernet frames; two MACs).
- The next 300 seconds of the same normal capture (29,713 frames) calibrated a one-sided zero-count Poisson upper novelty rate; the remaining 105,986 frames (19 minute-buckets) were held out.
- The frozen rule was then scored on separate publisher attack-scenario captures `Nmap_v1` and `Flooding Attack_v1` using 60-second buckets. The feature itself was designed after prior Cyber4OT exploration; no packet-level or onset ground truth is available.
- Finally, the distinct, much longer `ZeroSWARM Normal data_v2.pcap` (2,840,579 frames / ~7.64 hours / 458 minute-buckets) was evaluated as an external benign-session negative control, without changing the inventory.

## Results — first enrollment

| Scenario | Novel source-MAC packets | Flagged one-minute buckets |
|---|---:|---:|
| Short normal, later portion | 0 | 0/19 |
| Nmap attack capture | 30,874 | 11/11 |
| Flooding attack capture | 29,513 | 10/10 |
| **Long normal, independent session** | **1,183,570** | **458/458 false reviews** |

The longer benign recording contains source MACs `08:00:27:fc:8d:d7` and `0a:00:27:00:00:32`; the enrolled short-normal recording instead contains `08:00:27:fc:8d:d7` and `f8:75:a4:8b:8c:13`. Both attack recordings contain the **same two MACs as the longer benign capture**.

## Reverse enrollment reveals a shortcut

If the **long-normal MAC inventory** were enrolled instead, the Nmap and flooding recordings each contain **zero novel source-MAC packets**: the MAC-only rule would provide no attack signal. Under that long-normal inventory, the short-normal held-out portion instead has **44,161 novel-MAC frames despite benign labeling**. This second direction is a count-only counterexample, not an alternative calibrated classifier result.

The striking earlier short-recording separation is thus unstable under which normal session is selected. It is unsafe to claim external deployment robustness for the MAC lane. Treat MAC novelty as a context/review cue, require authenticated sensor vantage and separately approved inventory transitions, and evaluate independent benign topology changes. IP/MAC identifiers alone are not authenticated device identity.

This research audit does **not** evaluate or modify the deployed frozen meter model or the full four-lane Data4Cyber detector. No packet-level F1 or event delay estimate is justified. See `SmartGrid_Phase57_ZeroSWARM_External_PCAP_2026-10-27.json` for per-minute counts, SHA-verifiable publisher source checks, and reverse-enrollment tables.
