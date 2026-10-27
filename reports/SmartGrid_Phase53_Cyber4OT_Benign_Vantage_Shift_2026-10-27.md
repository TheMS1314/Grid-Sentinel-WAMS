# Phase 53: Benign Observation-Point Negative Control

Date: 27 October 2026 (India). Data: *Cyber4OT*, Warsaw University of Technology, https://zenodo.org/records/15005190. Archive checksum verified against publisher MD5 `55510cbb43d8af72a69dfbcd6940daa5`. Same original raw dataset as Phase 52, but evaluates **additional independently described benign central-switch captures**; this is an internal testbed sensor-shift stress test, not a new independent utility.

## Why test the detector against more normal traffic?

Phase 52's exploratory MAC novelty lane flagged all 8 examined attack-containing PLC-port captures and neither of two held-out normal PLC-port captures. That was conditional on a frozen inventory learned at the PLC port and was not a prospective performance estimate. A new switch or monitor port can expose more legitimate endpoint MAC addresses. We therefore applied frozen policies to multiple **normal-only** captures from the publisher's README, with no relabeling or attack fitting.

## Capture-level results

| Inventory source | Benign target capture sensor | Target IDs | Benign captures flagged on any unknown source MAC | Unfamiliar-MAC packet counts |
|---|---|---|---:|---|
| Normal PLC port, trace 069 (5 min) | PLC port | 070, 071 | 0/2 | 0, 0 |
| Normal PLC port, trace 069 (5 min) | Central switch | 002, 003 | **2/2** | **76,025; 113,940** |
| Normal central switch, trace 001 (5 min) | Central switch | 002, 003 | **2/2** | 2; 3 |
| Normal central switch, trace 001 (5 min) | PLC port | 070, 071 | 0/2 | 0, 0 |

The source and target roles are derived from the publisher's documented capture vantage; PCAPNG does **not** cryptographically attest to the physical switch port. The baseline inventory contained 5 source MACs at the PLC port and 9 at the central switch. The frozen Modbus client-IP allowlist generated **no** new-client alerts in these benign controls.

## Consequences

1. **Any single unseen Ethernet source MAC is too brittle even within the same observation point.** The normal central-switch captures show 2–3 such packets; a one-packet detector triggers.
2. Applying the PLC-port inventory to a central-switch capture makes 90% or more packets appear to have unfamiliar source MACs. This is **monitor placement/domain mismatch**, not evidence of widespread attacks.
3. A simple retrospective threshold sensitivity grid (`>0`, `>10`, `>100`, `>500`, `>1000` novelty packets per complete capture) was inspected. All tested PLC-port attack-containing captures are flagged through `>500`; however both central-switch normal captures **still flag** under the PLC-port baseline at every threshold in that grid. At `>1000`, only 5/8 attack-containing PLC-port captures flag. **Thresholds were examined after results were known** and cannot be reported as independently tuned prospective accuracy.
4. MAC flooding and a benign new sensor/device must be separated with authenticated inventory changes, sensor identity, maintenance events, rate/window normalization and prospective benign testing. Absolute count thresholds on traces of different length are not directly comparable.
5. A prototype `vantage_bound_decision` returns **`abstain`**, not `normal` or `attack`, whenever declared observation point is absent or differs from the frozen policy's point. This is evaluated as a software contract only. It does not itself authenticate the declared vantage; a trusted acquisition pipeline must provide that.

## Architecture change and limitations

The recommended external MAC-lane policy artifact must bind: policy/model hash, source sensor ID/physical port, timestamp and capture coverage, authorized MAC inventory snapshot, maintenance-change log and declared response when observation point or inventory provenance is missing. If this cannot be established, the correct result is **unscored/untrusted**, never a healthy benign row.

This phase does not show a new four-lane detector, real utility F1, alert burden/day, verified physical sensor identity or an operational Docker deployment. The testbed's benign files are not grounds for a 100% generalization claim. No research paper has been written.

## Reproduction

`python cyber4ot_vantage_shift_negative_control.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase53_Vantage_Shift_Negative_Control_2026-10-27.json`

`python -m unittest -q test_cyber4ot_vantage_shift_negative_control`

Raw published PCAPNG files are intentionally excluded from the source release. Complete per-capture and retrospective threshold counts are in the JSON output.
