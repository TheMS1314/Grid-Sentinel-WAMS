# Grid Sentinel Phase 32 — ARP identity claims versus legitimate maintenance

Date: 2026-10-26. **Synthetic identifiability counterexample, not a new external dataset, model-F1 improvement or deployment policy.** No research paper.

## Research question

Can passive ARP IP/MAC mismatch claims by themselves distinguish a malicious ARP spoof from authorized network interface replacement? No. If the captured observations are identical under both physical explanations, any deterministic rule receiving only those observations must return identical outputs. A better persistence threshold cannot resolve this lack of independent provenance.

## Controlled illustrative scenario

We created a deterministic 1,200-second *synthetic* timeline. From second 600 until just before 660, a known IP advertises a changed MAC in 11 ARP observations, one every five seconds (605 through 655). The recorded ARP claims are identical in both stories:

- **Maintenance:** an operator changed the NIC or its configuration; no attack occurred.
- **Impersonation:** an attacker made the same observed claims; the 60-second event is malicious.

The causal alert rule holds each mismatched claim for 0, 2, or 5 seconds after the observation. No classification model was retrained and no independent network packets were obtained.

| ARP hold | Benign-maintenance false-alert seconds | Spoofing-labeled seconds detected | Interpretation |
|---|---:|---:|---|
| 0 s | 11 | 11/60 | Narrow temporal footprint, still ambiguous |
| 2 s | 33 | 33/60 | More apparent attack coverage **and** benign alerts |
| 5 s | 56 | 55/60 | Nearly continuous maintenance alerts; 1 alert spills past attack window |

These numeric values are for a **constructed thought experiment** and must not be combined with S3/S4/S5 dataset F1 or interpreted as empirical estimates of maintenance frequency. The stronger conclusion is qualitative and exact: two physically distinct realities can produce the same ARP observations, so the ARP lane cannot authenticate intent.

## Engineering decision

1. Preserve the existing read-only ARP lane as **unverified network-identity evidence**; never label a source as an authenticated attacker based solely on a mismatch.
2. Do **not** automatically add newly observed MAC claims to a trusted inventory. That would let attackers train the baseline during an incident.
3. Before operational deployment, obtain an independently authenticated inventory/change record—for example an approved change ticket tied to trusted port/NAC/802.1X identity logs—and verify time, device, approved MAC, and operator identity. Build a separate human-reviewed inventory update procedure with audit history; do not silently suppress all events during maintenance windows.
4. Evaluate nuisance alerts on genuine maintenance days, independent benign topologies and prospective attacks. The Phase 27 non-ARP controls were same-topology captures and did not exercise authorized NIC changes.

## Reproducibility

```bash
python -m unittest -v test_arp_identity_ambiguity
python arp_identity_ambiguity.py --output reports/SmartGrid_Phase32_ARP_Identity_Ambiguity_2026-10-26.json
```

Requires only the standard Python library, not raw third-party data. The React Research evidence page and `GET /api/arp-research` expose the test separately with **synthetic-only** warnings. The deployed model and ARP policy remain unchanged. Scientific readiness remains incomplete pending authenticated provenance and independent site validation.
