# Phase 56 — Legitimate MAC change counterexample

The previous Cyber4OT normal and attack scenario results do not include genuine maintenance windows or a device-replacement corpus. This phase therefore performs a clearly marked **synthetic counterfactual**: it starts with the two *observed benign* evaluation captures (`003` central switch, `071` PLC port), appends a specified number of hypothetical frames from a legitimate new source MAC, and reevaluates the *already frozen* Phase 55 benign-calibrated rate decision. Both the anomaly numerator and total frame denominator increase.

## Results

| Hypothetical additional benign source-MAC frames per capture | Central-switch `003` | PLC-port `071` | False-flagged / 2 |
|---:|---|---|---:|
| 0 | normal | normal | 0 |
| 1 | normal | normal | 0 |
| 5 | normal | alert | 1 |
| 10 | alert | alert | 2 |
| 50 | alert | alert | 2 |
| 100 | alert | alert | 2 |
| 1,000 | alert | alert | 2 |

This is **not a measurement of real maintenance false-positive frequency**: no real packet replacement, new PCAP label, or genuine maintenance event was observed. The counterfactual highlights a fundamental non-identifiability: the very same source-MAC-novelty evidence can be created by authorized hardware changes or by malicious activity. Conversely, an attacker can use a MAC already allowed in the sensor's inventory and avoid this one novelty trigger. Other research lanes may still detect aspects of such activity, but no universal evasion or success result is inferred.

## Required behavior before operational approval

1. Report a triggered MAC novelty policy as a **review finding**, not a verified cyberattack attribution.
2. Bind inventory and every observation to an authenticated sensor identity and vantage. Unverified viewpoint must **abstain** from a benign/attack claim.
3. Handle device replacement using separately authenticated asset-inventory and change-control records; **do not auto-learn from suspicious traffic** or permit an unauthenticated maintenance flag to suppress detection.
4. Collect and prospectively test untouched benign maintenance windows, device replacement, MAC/IP changes, topology shifts, and realistic attack scenarios at each vantage; measure event F1, false reviews/day, and abstention coverage.
5. Maintain independent protection from Ethernet MAC spoofing and host-ID ambiguity; no single network feature can authenticate physical device identity.

The Phase 55 evidence remains a useful retrospective lab capture-level result (83/83 attack scenario captures flagged, 0/2 later benign captures), **but it is insufficient for field reliability**. The deployed meter-integrity model is unchanged. Project readiness stays at **88/100** because prospective maintenance/independent-site and real-host deployment gates remain unmet. No paper was written.
