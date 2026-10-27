# Phase 33 — Blind-site research evaluation readiness

## Outcome

Implemented `prospective_site_validation.py`: a self-contained, standard-library,
read-only evaluator for **already frozen** model/policy predictions on held-out
sites. It checks a SHA-256 commitment for each observation CSV, blocks overlap
with declared training site IDs, requires a provenance reference for each run,
and reports per-run precision, recall, F1, missed attack events, detected
attack events, and benign false-alarm burden. One synthetic unit-test fixture
illustrates computation only; **no new empirical accuracy figure is claimed**.

## Required manifest and CSV

Save a `manifest.json` and its referenced CSV files together. Manifest:

```json
{
  "protocol_version": 1,
  "frozen_model_sha256": "<64 lowercase SHA256 hexadecimal characters>",
  "frozen_policy": {"detector": "frozen-version", "threshold": 0.5},
  "training_site_ids": ["lab-site-1"],
  "evaluation_runs": [
    {"run_id": "field-site-2-day-1", "site_id": "field-site-2",
     "csv_path": "field-site-2-day-1.csv", "csv_sha256": "<64 hexadecimal characters>",
     "sample_seconds": 1, "provenance_reference": "operator-approved-trial-record-id"}
  ]
}
```

CSV columns: `timestamp_utc,attack_active,alert,event_id`. UTC timestamps must
be in increasing ISO-like string order and end in `Z`; labels and predictions
are strictly `0` or `1`; `event_id` is a stable nonempty incident identifier
for attack rows and empty for benign rows. `sample_seconds` is the exposure
represented by a sample. Predictions must be exported from the frozen system
without test-label access or retroactive threshold changes.

```bash
python -m unittest -v test_prospective_site_validation
python prospective_site_validation.py --manifest /path/to/manifest.json
python prospective_site_validation.py --manifest /path/to/manifest.json --output /path/to/new-results.json
```

The CLI never overwrites an existing output file. Copy only privacy-reviewed,
consented, authorized monitoring data; remove IP/MAC or operator identifiers
if they are not needed for scientific adjudication. Never inject attacks into
an operating power system. Use an approved isolated lab for attacks.

## Scientific limitations and release gates

1. CSV integrity is checked relative to the manifest; a dishonest actor could
   rewrite both. Store a signed or third-party witnessed manifest, timestamps,
   immutable model checksum, and ground-truth records **before unblinding**.
2. `provenance_reference` is mandatory but **not cryptographically verified**;
   human review of source evidence remains essential.
3. Held-out site IDs are declared, not authenticated. Disjoint IDs do not
   alone establish independent instruments, operators, or topologies.
4. Rows are correlated in time; row-level F1 and false-alerted samples per
   clean hour are descriptive. They are **not** confidence intervals or a
   count of alert incidents. The event detection rate is event-level only.
5. Missing attack types, sparse labels, scenario shifts, the ARP identity
   ambiguity, and missing MQTT visibility persist unchanged.
6. To credibly claim >90% readiness, obtain externally corroborated benign
   and attack trials on more than one independent environment, pre-register
   acceptance thresholds, freeze model/policy hashes, examine site-level
   errors, and verify Docker/Postgres operation plus backup restoration on
   the actual deployment hardware. These gates are not met by this phase.

## Status

Phase 33 makes future evidence more auditable, but **does not improve the
underlying detection results**. Overall project status remains approximately
**78/100**, a qualitative engineering estimate; scientific acceptance remains
**3/10** previously established gates. Do not conflate these numbers.
