# Phase 51: Independent-Site Acceptance Contract with Abstentions

Date: 27 October 2026 (India). This is an **offline evaluator and contract**, not evidence of measured accuracy. No real-site observations or PC/server deployment were supplied.

## Why Phase 51 exists

Phase 49 demonstrated severe source-domain failures (including every benign real-Modbus row falsely flagged by a simulated-MMS-trained flow classifier); Phase 50 showed that pooling domains helps some experiments but still gives hundreds of benign false positives. Those observations should lead to a prospective test on a new site, where the evaluator *must* distinguish **unobserved/unsupported**, **normal**, and **attack**. The former Phase 33 version 1 prospective evaluator could score only binary predictions.

`prospective_site_validation_v2.py` extends, rather than overwrites, that evaluator. It takes a SHA-256-frozen model artifact, a manifest declaring training site IDs and test run IDs, and independently labeled, timestamped held-out CSV traces. Paths are confined to the evaluation directory and CSV/model checksums are verified before scoring. No network collection, fitting, adaptive threshold selection, or secret operations occur.

## Required record fields

| CSV column | Permitted content |
|---|---|
| `timestamp_utc` | Strictly ascending ISO-8601 UTC instant ending in `Z`, nominal fixed sampling cadence |
| `attack_active` | Exactly `0` or `1` |
| `decision` | `normal`, `attack`, `abstain` |
| `event_id` | Nonempty stable ID only on attack rows; blank on benign rows |
| `attack_family` | Nonempty stable family ID only on attack rows |
| `observation_health` | `healthy`, `missing_sensor`, `unsupported_domain`, `invalid_schema`, `untrusted_source` |

If observation health is not `healthy`, **the sole legal model decision is `abstain`**; do not convert an unsupported or untrusted observation into an apparent benign label. Healthy rows may still abstain for model uncertainty. The evaluator verifies a field claim, not the provenance of that claim—sensor health must be produced by independent trusted collection controls and reviewed separately.

## Evaluation rules and anti-inflation protections

- Three source-free acceptance criteria must be declared **before opening held-out results** in `acceptance_criteria`: `min_scored_coverage` in [0,1], `min_attack_event_detection` in [0,1], and `max_false_alert_episodes_per_clean_day` finite and nonnegative. The manifest itself is hashed in the report; preserve its externally precommitted hash separately to prove it was not modified after testing.
- Attack events are detected only if at least one attack row has an `attack` decision. Abstained attack rows are **not** a detection, and are included in the denominator of end-to-end recall.
- Coverage equals scored rows divided by all rows, separately reporting abstained benign and attack counts. Per-scored-row confusion metrics exclude abstentions from all four cells, but end-to-end attack recall uses **all attack rows**.
- Benign false-alert episodes are consecutive benign `attack` decisions; their rate uses **all observed benign time** as denominator, not scored-only benign time. These are alert episodes per nominal clean day, not a measured live daily burden unless the underlying stream really is time-accurate and representative.
- Every attack requires a nonblank event and family, and a given event ID must not change family. The report gives per-family event-level detection, including entirely abstained families.
- The evaluator rejects training site overlap, malformed hashes and paths, missing data, abnormal time gaps, model mismatch, invalid decisions and healthy/unhealthy inconsistencies.
- Runs without any attack event fail the attack-event gate; runs without benign time fail the false-alert burden gate. Missing evidence is not a pass.
- Site labels, site independence, ground truth, signing authorities, sensor provenance and model behavior **cannot** be proven by a self-supplied CSV. Independent review remains mandatory.

## Minimal manifest shape

The file is JSON and lives beside the frozen model and one or more CSV files. The following illustrates the fields; replace values **before** data collection and calculate SHA-256 checksums from real files:

```json
{
  "protocol_version": 2,
  "frozen_model_path": "detector.bin",
  "frozen_model_sha256": "<64 hexadecimal characters>",
  "frozen_policy": {"model_version": "precommitted-release-tag"},
  "training_site_ids": ["train-site-A"],
  "acceptance_criteria": {
    "min_scored_coverage": 0.95,
    "min_attack_event_detection": 0.90,
    "max_false_alert_episodes_per_clean_day": 1.0
  },
  "evaluation_runs": [
    {
      "run_id": "independent-site-passive-capture-001",
      "site_id": "never-trained-site-B",
      "csv_path": "heldout_predictions.csv",
      "csv_sha256": "<64 hexadecimal characters>",
      "provenance_reference": "independent-capture-and-label-review-id",
      "sample_seconds": 1.0
    }
  ]
}
```

These thresholds are **illustrative**, not achieved performance or a recommended utility safety standard. For real acceptance, choose operationally meaningful limits with the site owner *before* accessing test labels.

## Run and interpret

`python prospective_site_validation_v2.py --manifest /path/to/site_manifest_v2.json --output /path/to/new_evaluation_result.json`

`python -m unittest -q test_prospective_site_validation_v2`

Version 1 evaluator and its interface remain intact. The new six synthetic unit tests verify abstention accounting, invalid sensor decisions, changed hashes, training site overlap, fully unscored runs and invalid sampling cadence. Passing fixtures demonstrate software behavior only. **No independent-site validation or live Docker deployment has been completed, and the project must not be marked 100%.** No paper was drafted.
