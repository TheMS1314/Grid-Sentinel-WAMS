# Phase 41 — selective independent-site validation interface

## Purpose

Phase 41 connects precommitted Phase 39 replay output to a separately provided set of independent truth labels, **without using labels to adjust the detector**. It is a scoring tool, not evidence that independent validation has occurred. No new field dataset was available in this phase.

## Two committed inputs

1. `unverified_replay.json` from `offline_four_lane_replay.py` including the frozen policy and observation SHA-256 commitments. Take its SHA-256 independently before unblinding.
2. `adjudicated_truth.json` with `schema_version: 1`, identical `site_id`, a nonblank independently verified `adjudication_reference`, and `records` containing exact `timestamp_utc` and boolean `attack_active` for **every** replay row, including abstentions. Its file SHA-256 must also be frozen.

```bash
python offline_selective_validation.py --replay unverified_replay.json \
  --replay-sha256 COMMITTED_REPLAY_SHA256 --truth adjudicated_truth.json \
  --truth-sha256 COMMITTED_TRUTH_SHA256 --output selective_results.json
```

Output refuses overwrite and contains all source hashes plus provenance reference. Synthetic software tests assert timestamp/site alignment, rejection of contradictory alert evidence, label type, row loss, and selective-denominator math.

## Why abstentions matter

If visibility is incomplete and no positive signal exists, the row is `ABSTAIN_INCOMPLETE_VISIBILITY`. This is **not a predicted benign row**. Alert statuses may still have unknown lanes but remain unverified positive reviews. The new result reports:

- `selective_coverage`: fraction of rows with a positive review or fully observed negative determination.
- TP/FP/TN/FN, selective precision/recall/F1 on only those decided rows.
- `abstained_attack_rows` and `abstained_benign_rows` separately.
- `all_attack_recall_lower_bound`: all abstained attacks assumed missed.
- `all_attack_recall_upper_bound`: all abstained attacks potentially detectable, an optimistic bound only.
- Benign alert fraction across all benign rows, including abstentions in the denominator, with abstention counts alongside it.

Selective F1 must **never** be compared in isolation with the earlier Data4Cyber 0.98943 post-hoc macro F1. The datasets, scoring populations and policies differ. Furthermore, hashes establish byte integrity but not trustworthy clock, attack adjudication, sensor authenticity, true site independence or legitimate precommitment timing; these need outside evidence.

## Remains incomplete

No independent-site labels, no real streaming capture decoder, no authenticated price publisher, no verified controller inventory, and no production four-lane model are present. The FastAPI backend still deploys the narrower frozen physics model. This phase contributes evaluation rigor, not a newly measured detection-performance improvement.
