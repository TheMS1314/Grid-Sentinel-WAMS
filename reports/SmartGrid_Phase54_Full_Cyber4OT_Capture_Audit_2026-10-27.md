# Phase 54 — Full comparable-view Cyber4OT packet-capture audit

## Why this phase matters

The previous eight hijacking/MAC-spoofing files did not characterize reconnaissance and ordinary network scans. This phase exhaustively scores the remaining publisher-described **comparable-sensor** attack captures from the same dataset, keeping observation points separate. The publisher archive was verified using MD5 `55510cbb43d8af72a69dfbcd6940daa5`.

## Protocol

- Central-switch reference: normal capture `001`; test benign `002–003`, scenario attacks `004–068`.
- PLC-port reference: normal capture `069`; test benign `070–071`, scenario attacks `072–082`, `084`, `086`, `088`, `090`, `092`, `094`, `095`.
- Attacker-endpoint captures are excluded, because they would confound viewpoint and attack effects. No packet-level labels are available.
- Alert on **more than 3 Ethernet-source-MAC novelty packets** in a complete capture, with observation point bound to its own reference. The threshold is *retrospective*, chosen after inspecting benign controls and prior attacks—not prospectively tuned or deployment-approved.

## Results

| Group | Captures flagged | Total | Caveat |
|---|---:|---:|---|
| Central-switch host scans | 60 | 60 | Same testbed, correlated targets/modes |
| Central-switch ping scans | 5 | 5 | Scenario-level labels |
| PLC-port ping scans | 5 | 5 | Scenario-level labels |
| PLC-port scans | 5 | 5 | Scenario-level labels |
| PLC-port MAC spoofing/hijack | 8 | 8 | Partial/mixed 095 lacks onset annotation |
| Benign central-switch false alerts | 0 | 2 | Only two test normal files |
| Benign PLC-port false alerts | 0 | 2 | Only two test normal files |

In total: **83/83 attack-scenario files alert, 0/4 benign files alert** at cutoff >3. The observed novelty range separates these specific captures: minimum attack `47` vs maximum benign `3`. At cutoff >0 the same 83 attack files alert but both benign central-switch captures falsely alert; at cutoff >100, only 71/83 attack files alert. This illustrates the sensitivity to the cutoff and argues against claiming that any exact threshold universally generalizes.

The IP-to-MAC Modbus peer binding conflict lane was zero throughout this audit; source-MAC novelty is a *different and broader Ethernet feature*, which can respond to ARP/reconnaissance traffic or changes unrelated to a cyberattack. The results cannot be attributed to the four-lane Data4Cyber production detector without a compatible feature integration and fresh evaluation.

## Scientific limitations and readiness

1. **Post-hoc threshold and feature selection:** Not a blind, out-of-sample proof. Files are correlated recordings of one publisher testbed, so 83/83 is not 83 independent deployments.
2. **Capture labels, not time-resolved ground truth:** No event sensitivity, detection delay, precision, or realistic alerts/day can be inferred.
3. **Sensor identity and maintenance:** A port change or replacement legitimately changes source MACs. Capture-point labels are publisher provenance, not runtime cryptographically authenticated sensor provenance.
4. **Site mismatch:** The prior Phase 53 benign negative control found 2/2 false alerts across unmatched sensor vantage; require fail-closed abstention on mismatches, not a low-risk prediction.
5. **No real-host validation:** Docker/PostgreSQL startup, operational recovery, and signed utility context still require the user's actual private host and authentic data.

## Next acceptance experiment

Pre-register features, fixed cutoff and outcomes, capture source verification, new site and maintenance windows. Collect untouched benign and attack traces for a prospective test. Retain an explicit `abstain` outcome on untrusted provenance or insufficient observations; measure event-level recall, benign alerts/day and coverage. The **project remains 88/100** until these externally-dependent gates are satisfied; no research paper has been written.

See `SmartGrid_Phase54_Full_Cyber4OT_Audit_2026-10-27.json` for the full capture-level evidence table and cutoff sensitivity.
