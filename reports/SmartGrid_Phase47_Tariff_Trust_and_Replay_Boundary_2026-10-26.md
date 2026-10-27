# Phase 47 — signed tariff trust boundary, checkpoint replay and integrated tests

## Security negative control

An honest authorized publisher and a compromised publisher controlling the **same authorized Ed25519 private key** can produce the *identical signed price statement*. A verifier receiving the same signed bytes, site ID, publisher ID, key ID, timestamp, sequence and observed price must report the same signature verdict in both hidden realities. The included ephemeral-key test demonstrates this information-theoretic ambiguity. **Ed25519 authenticates statement/key consistency; it cannot attest owner intent or signer compromise.**

This is a synthetic identifiability counterexample, not a new real attack experiment or improved F1. The prior S1–S6 post-hoc macro F1 0.98943 is unchanged.

## Cross-run sequence continuity

The Phase 46 verifier could identify repeated sequence numbers only *within* the currently loaded file. Phase 47 optionally accepts a prior checkpoint: `schema_version`, `site_id`, `publisher_id`, `last_authenticated_sequence`, `last_authenticated_timestamp_utc`. This rejects backward time and catches a repeated sequence number when the next batch starts with a later timestamp but a stale sequence.

```bash
python offline_signed_tariff_verifier.py --policy approved_keys.json \
  --policy-sha256 PRECOMMITTED_POLICY_SHA256 \
  --messages next_batch.json --messages-sha256 PRECOMMITTED_BATCH_SHA256 \
  --prior-checkpoint externally_approved_prior_checkpoint.json \
  --prior-checkpoint-sha256 EXTERNALLY_RECORDED_CHECKPOINT_SHA256 \
  --output next_audit.json
```

If no prior checkpoint is passed, `replay_checkpoint_mode` explicitly equals `BATCH_ONLY_NO_RESTART_REPLAY_ASSURANCE`. On success, the audit includes `proposed_next_checkpoint`; **this is not automatically trusted**. An independent operator must verify, durably timestamp and attest that checkpoint before relying on it for later runs. A checksum alone establishes byte integrity but not authentic custody or rollback resistance. This remains offline; no mutable secret or trusted append-only store is deployed.

## Full synthetic pipeline test

New `test_offline_signed_tariff_integration.py` exercises, in memory, the exact observation transformation → original four-lane replay → authorized signed tariff verification → strict evidence joining:

- A valid signed *but novel* price stays a separate `SIGNED_BUT_NOVEL_CONTEXT` record; the original research replay status remains `REVIEW_UNVERIFIED`.
- A separately observed price that differs from the authorized signed price is reported as `PRICE_PATH_DIVERGENCE_REVIEW` without automatically claiming an attack.
- Time and site identities are signed and aligned from the start; test code does not rewrite verification reports after the fact.

Tests also cover prior checkpoint misuse, key rotation, malformed key material, timestamp conflict, invalid signatures, and price missingness. Synthetic fixtures produce no new empirical security detection metrics.

## Still missing

Independent authenticated utility key inventory/custody, revocation and secure rotation, trusted cross-run checkpoint persistence, synchronized clocks, actual signed MQTT publisher integration, independently measured benign tariff changes, real deployment and cross-site labelled campaigns. The served API remains a narrow meter-integrity detector and the signature lane is **offline research only**. No paper was created.
