# Grid Sentinel Phase 42 — sealed two-stage offline evaluation

## Outcome

The offline four-lane research pipeline can now separate prediction generation from attack-label inspection with `offline_blind_site_run.py`. The `prepare` command does not accept a truth-file path, and writes normalized observations, replay predictions, and a hash commitment in a new directory; `unblind` later verifies the frozen observations and replay and scores a separately hash-frozen truth file. The seal checksum must be recorded in an **independent tamper-evident notebook or repository** before anyone sees the labels.

This prevents accidental in-process label leakage, improves traceability, and makes silent edits detectable. It is not cryptographic proof that collection and annotation were independent, and offers no ground-truth labels or new performance figures.

## Usage

Freeze trusted inventory policy and an offline event JSONL file *before* labels are known. See Phase 39/40 documentation for strict schemas.

```bash
python offline_blind_site_run.py prepare \
  --policy frozen_policy.json --policy-sha256 KNOWN_POLICY_SHA256 \
  --events offline_events.jsonl --events-sha256 KNOWN_EVENT_SHA256 \
  --directory independent_site_001_frozen
```

This creates `observations.json`, `replay.json`, and `seal.json` inside a previously nonexistent directory. Independently calculate and record the SHA-256 checksum of `seal.json`, preferably with a separate timestamped commit and named operator before unblinding. Only after that should the independently annotated, one-row-per-second `truth.json` be made available:

```bash
python offline_blind_site_run.py unblind \
  --directory independent_site_001_frozen \
  --seal-sha256 INDEPENDENTLY_RECORDED_SEAL_SHA256 \
  --truth adjudicated_truth.json --truth-sha256 COMMITTED_TRUTH_SHA256 \
  --output independent_site_001_results.json
```

Every output is non-overwriting; tampered replay, seal, mismatched site IDs or misaligned labels halt evaluation. Generated scores include selective coverage, abstained attack/benign counts, F1 on decided samples, recall bounds across all attack samples, and hashes of all inputs.

## Scientific boundary and pending gates

No independently acquired site data or credible third-party labels were added in Phase 42. The earlier Data4Cyber macro F1 of `0.98943` is still a **post-hoc research number** on examined publisher scenarios, not a blind-site metric. Other essential gates: authenticated data sources (including MQTT tariff provenance), robust cross-site clocks, trained and frozen physics-score ingestion, verified field false-alarm burden, real-user Docker deployment, and tested PostgreSQL backup/restore. The release neither connects to real grid devices nor actuates equipment.

## Tests

Synthetic end-to-end tests cover a complete prepare/unblind flow, replay hash mismatch, seal hash mismatch, truth hash mismatch, site mismatch, wrong policy hash, refusal to reuse directories or overwrite scored results, and the guarantee that truth need not exist during preparation. These checks are software engineering tests, not model-performance evidence.
