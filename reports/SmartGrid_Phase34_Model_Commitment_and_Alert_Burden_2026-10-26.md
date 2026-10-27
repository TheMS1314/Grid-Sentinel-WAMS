# Phase 34 — Stronger prospective evaluation integrity

## Changes

The Phase 33 offline evaluator now verifies the **actual frozen model bytes**
against `frozen_model_sha256`. Specify `frozen_model_path`, relative to the
manifest's directory. It refuses to score when the hash fails or the path
escapes the evaluation directory. This closes a provenance error in Phase 33,
where a hash was recorded but not checked against actual model bytes.

The timestamp reader now parses UTC ISO8601 datetimes, enforces increasing
instants, and refuses a gap exceeding `1.5 * sample_seconds`. Such gaps are
not quietly counted as known benign exposure. `sample_seconds` means expected
regular sample interval: prepare distinct runs for differing rates, and do not
relabel missing observations as clean. A gap smaller than tolerance can still
have jitter, so human inspection remains essential.

Two new per-run metrics measure the operational burden and time to action:

- `false_alert_episodes`: starts of consecutive false-alerted benign samples.
- `false_alert_episodes_per_clean_hour`: episode count divided by observed
  benign sample exposure hours.
- `first_detection_latency_seconds`: sorted elapsed seconds from each detected
  attack event's first observation to its first alert. Events never detected
  are accounted separately in `attack_events` and `detected_events`, rather
  than omitted from overall recall.

These metrics are descriptive only. Rows near an attack boundary may form
multiple benign false-alert episodes, and true operational incident counts
may require a predeclared alarm de-duplication policy. The evaluator never
changes the deployed detector or adjusts a threshold after looking at labels.

## Manifest amendment

Add to Phase 33's manifest:

```json
"frozen_model_path": "frozen-model.json"
```

The file must exist beside the manifest or inside one of its subdirectories,
and its exact SHA256 must match `frozen_model_sha256`. Copy the released
`smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json` under
this path if the frozen model is the current meter-integrity detector; never
substitute an unrelated model solely to satisfy the checksum check.

## Verification and limits

Nine targeted evaluator unit tests passed, including checks for tampered
model files, missing time intervals, invalid timestamps, tampered prediction
files, training-site overlap, bad labels, missing provenance, and path escape.
These are **synthetic tests of the reporting software**, not attack detection
benchmarks. All historical Data4Cyber and COCOON model outcomes remain unchanged.

No actual independently certified site capture, incident ground truth, live
Docker/Postgres deployment, or restore exercise is included. Overall readiness
is still qualitatively ~78/100, not a measured greater-than-90% achievement.
