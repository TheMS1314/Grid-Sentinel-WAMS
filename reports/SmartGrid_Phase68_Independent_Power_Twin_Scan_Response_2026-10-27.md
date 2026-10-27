# Phase 68 — Independent power-system digital-twin scan-response audit

Date: 2026-10-27 (Asia/Kolkata). **Executed once with frozen Phase 58/59 TCP rule. No new threshold fitting.**

## Independent deposited evidence

Source: M. M. Thwe and A. Stefanov, [Mininet Network Traffic Dataset for Intrusion Detection in a Cyber-Physical Power-System Digital Twin](https://doi.org/10.5281/zenodo.23055644), Zenodo version 1, 2026-09-30, TU Delft. Its companion documentation identifies Mininet communication for a PowerFactory-connected cyber-physical digital twin, with fast/stealth network scans. The documentation **does not claim exact scenario timing, target/attacker roles, or packet-level labels**. This is therefore a **scenario-containing capture**, not a time-localized ground-truth attack benchmark.

Publisher file: `scanningattack_packets.pcapng` (1,011,252 bytes).
- Official MD5: `5c9e8e5f51813831084c0e11cbe0d50b` — independently matched.
- SHA-256 recorded before scoring: `66d6c877c74e82b97d123b6d3344815e04237aff8d9bcc5684e4c940ad73a99c`.
- Source capture not redistributed in repository.

## Pre-existing frozen detector policy

Applied unchanged: nonempty capture-relative 60-second buckets, review when **more than two distinct TCP destination ports** AND **at least one SYN without ACK** within the bucket. IPv4/TCP is included; non-TCP frames count toward frame totals, not the TCP ports. Zero-frame time buckets do not count as observations. The policy does not identify individual packets as attacks. No model training, feature selection or tuning used this dataset.

## Executed result

| Metric | Observed |
|---|---:|
| All packets/frames | 11,372 |
| IPv4/TCP frames | 11,254 |
| Parser errors counted | 0 |
| Capture duration | 970.751 s |
| Nonempty 60-s buckets | 15 |
| Buckets flagged for review | **10 / 15** |
| Contiguous flagged bucket groups | **2** |

Review minute indices: **0, 1, 8, 9, 10, 11, 12, 13, 14, 15**.

Minute 0 included 1,002 distinct TCP destination ports and one SYN without ACK; minute 1 included 1,004 destination ports and 1,002 SYN-without-ACK frames. Later high-diversity scan-like windows were also flagged. The result demonstrates sensitivity to network-scanning patterns in this independent power-system simulation.

### Limitations that must accompany any presentation

- The authors provide no time-localized truth. **No 10/10 recall, F1, precision, specificity, false-positive rate, onset-delay or per-packet accuracy can be calculated.** The ten reviewed buckets might overlap benign phases; all observations remain review signals.
- There is no separately labeled benign reference capture in this Zenodo deposit. The preregistered 24-hour false-episode target is **unassessed**.
- The 15 nonempty 60-s buckets span approximately 16.2 minutes, with gaps; observed capture duration is not continuous verified benign exposure.
- This is one simulated power-system digital twin, not an independent live grid site; one attack-containing capture cannot establish generalization to all S1–S4 cases.
- The TCP lane is offline research; the deployed FastAPI meter-consistency engine is separate.
- DataSense/CIC IIoT 2025 remains a planned further preregistered challenge, pending authorized dataset access.

## Reproduction

Install the research dependency `dpkt==1.9.8`, obtain the above PCAPNG from its publisher, then from the repository root:

```bash
python zenodo_power_twin_frozen_tcp.py /path/to/scanningattack_packets.pcapng
python -m unittest -v test_zenodo_power_twin_frozen_tcp
```

The script refuses any file whose MD5 differs from the publisher’s. It reports window details alongside counts, not implied accuracy metrics. No research paper prepared.
