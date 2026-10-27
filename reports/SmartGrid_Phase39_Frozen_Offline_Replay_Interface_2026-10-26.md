# Phase 39 — Reusable Frozen-Policy Offline Evidence Replay

26 October 2026. Defensive offline research tool; **not a deployed IDS** or a
paper. No raw packet captures, operational commands, or network access.

## Outcome

Implemented `offline_four_lane_replay.py`, a **standard-library** input adapter
that runs a user-supplied, hash-frozen four-signal review policy against
normalized observation rows. Unlike the publisher-specific Data4Cyber
benchmark script, it accepts a declared site inventory and independent
observation JSON without knowing scenario IDs or attack labels.

The four inputs are:

1. `physics_review`: `true`, `false`, or `null` from a *separately frozen*
   meter-consistency assessment. The adapter does **not** compute meter
   residuals from raw field readings and does not itself verify this flag.
2. `modbus_writes`: source-IP claims from a read-only packet decoder compared
   with a frozen, operator-verified allowlist. IP is not an authenticated
   principal; unidentified sources produce an **unverified review**.
3. `arp_claims`: claimed sender IP/MAC pairs compared with a frozen inventory.
   Unknown inventory entries yield **abstention**, not a clean result. A
   mismatch cannot distinguish an authorized NIC change from impersonation.
4. `price_eur_per_kwh`: current numeric input evaluated against a frozen
   center/scale/threshold. Novelty is not an authenticated publisher signature.

The exact example files shipped in `examples/` use documentation IP addresses
and synthetic policy values. They are fixtures, not real grid observations.

## Causal execution and fail-closed behavior

- Strict increasing UTC ISO timestamps; gaps greater than 1.5 seconds reset
  prior Modbus and ARP hold states, rather than fabricating observations.
- Incomplete visibility is explicit. If no lane fires and another is unknown,
  output `ABSTAIN_INCOMPLETE_VISIBILITY`; if any fires, output
  `REVIEW_UNVERIFIED` while retaining `unknown_lanes`.
- Coverage dropout clears the old hold state; no automatic network probing,
  inventory learning, mitigation or control commands.
- Existing results are never overwritten by the CLI. It requires an exact
  SHA-256 for **both** the frozen policy and observation file and records them
  in the resulting report. For truly blind validation, preserve those hashes
  independently **before labels are revealed**.
- Every output explicitly says passive claims are not authenticated attacks.

## Example

From the extracted release root:

```bash
python offline_four_lane_replay.py \
  --policy examples/offline_site_policy_example.json \
  --policy-sha256 2fbeb3dc478ebbd42f847db4e5fe484a220536b31d2cf2eddc06cbb9f3f515cd \
  --observations examples/offline_observations_example.json \
  --observations-sha256 8a20703a4d8ab5e1d53d91d0f14d43317b9c33affa0e619749de067a972e3c2c

python -m unittest -v test_offline_four_lane_replay
```

If you change either example file, calculate its new `sha256sum` and commit it
before the evaluation. Real-site policies must not reuse example IPs or the
synthetic price threshold. Obtain an authorized passive export from a trusted
capture workflow; ensure its normalization makes `observable=true` only when
coverage for that entire one-second interval is known.

## Scientific/deployment limitations

This is an **engineering harness**, not a newly measured detection result.
Synthetic tests establish strict state-machine behavior only. No independent
site telemetry, cryptographically signed tariff source, device identity,
prospective false-alarm statistics or live Docker/Postgres integration was
available. The Data4Cyber post-hoc `0.98943` macro-F1 is unchanged, and cannot
be assigned to this interface or a future network without validation.

For authentic attack attribution, the upstream evidence collector must verify
writer identity, device maintenance change records, tariff publisher signatures
and synchronized time sources. A hash of local JSON bytes protects integrity
relative to a previously trusted commitment; it does not prove the truth of
the content or that the collection equipment was uncompromised.

**Project readiness remains approximately 82/100** (qualitative engineering
estimate, not research accuracy). The target-machine restore drill and
multi-site blind trial remain the next external acceptance gates.
