# Phase 46 — cryptographically authenticated tariff context (offline)

## Added

`offline_signed_tariff_verifier.py` verifies detached **Ed25519** signatures on a strict canonical JSON tariff statement, bound to site ID, publisher ID, key ID, monotonically increasing sequence, timestamp, and signed EUR/kWh price. It requires a separately SHA-256-frozen, site-approved public-key policy with explicit validity intervals and provenance reference. Key rotation is possible only when sequence numbers remain increasing across keys; stale/replayed sequences are marked for review. Signature bytes and publisher assertions are never treated as proof of honest business intent.

`offline_tariff_context_bridge.py` joins this result with the Phase 39 four-lane replay by exact site and timestamps. Price observations and existing alert statuses are **not altered**. Instead it presents a contextual classification:

- `SIGNED_BUT_NOVEL_CONTEXT`: frozen price novelty fired, yet a recognized signer authenticated an identical statement. This is **still not proof of benign intent** or an uncompromised signing key.
- `SIGNED_EXPECTED_CONTEXT`: price was both signed/observed consistently and non-novel by the frozen research rule.
- `PRICE_PATH_DIVERGENCE_REVIEW`: authenticated message and independently observed price differ, suggestive of a feed integrity issue but not attributable to a specific attacker.
- `UNVERIFIED_SIGNATURE_FAILURE_REVIEW`, `SIGNED_SEQUENCE_ANOMALY_REVIEW`, and `TARIFF_PROVENANCE_ABSTAIN`: distinct uncertainty/error outcomes.

There are **no real utility signing keys** in the package. Unit tests create disposable Ed25519 key pairs only in memory, covering signing, tamper detection, key validity and rotation, sequence replay, missing prices, unknown publishers, and strict timeline join. No MQTT broker, live network, site operator certificate authority, PKI, key revocation service or persistent sequence store is accessed.

## Usage

Install optional offline dependency:

```bash
python -m pip install -r requirements-tariff.txt
python -m unittest -v test_offline_signed_tariff_verifier test_offline_tariff_context_bridge
```

Policy JSON schema:

```json
{
  "schema_version": 1,
  "mode": "research_only",
  "site_id": "INDEPENDENT_SITE_ID",
  "publisher_id": "APPROVED_PUBLISHER",
  "key_provenance_reference": "EXTERNAL_APPROVED_KEY_CUSTODY_RECORD",
  "trusted_keys": {
    "PUBLISHER_KEY_ID": {
      "public_key_b64": "BASE64_ED25519_32_BYTE_PUBLIC_KEY",
      "not_before_utc": "2026-10-25T00:00:00Z",
      "not_after_utc": "2026-11-25T00:00:00Z"
    }
  }
}
```

Input messages JSON has a `records` array. Each item has `signed`, `signature_b64`, and `observed_price_eur_per_kwh` (finite float or null). The `signed` object contains exactly `schema_version`, `site_id`, `publisher_id`, `key_id`, `sequence`, `timestamp_utc`, and `price_eur_per_kwh`. Signatures are over the sorted-key JSON encoded as UTF-8, with compact separators and ASCII escapes, produced by `canonical()` in the script. **Never upload a private signing key to this verifier.**

```bash
python offline_signed_tariff_verifier.py --policy approved_tariff_keys.json \
  --policy-sha256 PRECOMMITTED_POLICY_HASH \
  --messages frozen_tariff_messages.json \
  --messages-sha256 PRECOMMITTED_MESSAGES_HASH \
  --output tariff_audit.json

python offline_tariff_context_bridge.py \
  --replay frozen_four_lane_replay.json --replay-sha256 FROZEN_REPLAY_HASH \
  --tariff tariff_audit.json --tariff-sha256 FROZEN_TARIFF_AUDIT_HASH \
  --output two_track_context.json
```

Both outputs refuse overwriting existing files. Hashes protect byte integrity only, not truthful origins.

## Limitations / research acceptance

This is a **synthetic software demonstration only**. The long-term original macro-F1 figure 0.98943 is unchanged. Real-world acquisition of a trusted publisher key and independent price observation is an unfulfilled requirement; unsigned MQTT alone cannot supply cryptographic provenance. No cryptographic public key identifies a utility unless separately verified and no offline sequence rule prevents replay across process restarts without a persisted trusted checkpoint. Secure wall-clock, key revocation and compromised-publisher scenarios require independent operational design. The actual FastAPI backend remains the frozen meter detector; signed tariff verification is not deployed. No research paper was produced.
