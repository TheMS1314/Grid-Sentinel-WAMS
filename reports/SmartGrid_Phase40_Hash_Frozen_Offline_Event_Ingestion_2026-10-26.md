# Grid Sentinel Phase 40 — hash-frozen offline event ingestion

## What changed

Added `offline_observation_ingest.py`, bridging explicit JSONL offline events into the pre-existing Phase 39 four-lane replay JSON. This is a **read-only research adapter** with zero live grid access. A precommitted event-file SHA-256 and independently frozen policy SHA-256 are mandatory. The output reports its own SHA-256 for use with the replay CLI.

Input JSONL records are objects with UTC-second `timestamp_utc`, an identical `site_id`, and a `kind`:

| kind | required additional fields | meaning |
|---|---|---|
| `coverage` | `lane` (physics/modbus/arp/price), `observed` (boolean) | One per lane each observed second; false means no trustworthy visibility. |
| `physics_review` | `review` (boolean) | Precomputed frozen meter-model result; **not calculated by this adapter**. |
| `price` | `eur_per_kwh` (finite number) | Single tariff observation per covered second. |
| `modbus_write` | `source_ip` | Passive reported source IP; not authenticated. |
| `arp_claim` | `sender_ip`, `sender_mac` | Passive reported ARP claim; not authenticated. |

To treat a second as fully observed, submit four affirmative coverage records, one physics review record, and one price record. Modbus and ARP can have zero or multiple events with affirmative coverage. Uncovered missing seconds are automatically inserted with all lanes unknown. Each input line is size-bounded (16 KiB), input contains at most 500,000 events and spans at most 86,400 seconds. Duplicate JSON keys and contradictory observations are refused.

## Usage

First record the SHA-256 of the *unchanged* policy JSON and input JSONL independently **before** inspecting ground truth. Example:

```bash
python offline_observation_ingest.py --policy frozen_policy.json \
  --policy-sha256 YOUR_FROZEN_POLICY_SHA256 --events frozen_events.jsonl \
  --events-sha256 YOUR_FROZEN_EVENTS_SHA256 --output normalized_observations.json
```

The command prints `observations_sha256`. Then run:

```bash
python offline_four_lane_replay.py --policy frozen_policy.json \
  --policy-sha256 YOUR_FROZEN_POLICY_SHA256 \
  --observations normalized_observations.json \
  --observations-sha256 PRINTED_OBSERVATIONS_SHA256 --output unverified_replay.json
```

Both outputs refuse overwrite. The converter replays all rows in-memory to verify normalized semantics before writing.

## Critical boundaries

- A supplied coverage heartbeat is only a **claim**; actual packet/sensor completeness and identity require external audit. This adapter has no PCAP/IPAL decoder, device authentication, or timestamp synchronization proof.
- Input is **not a new dataset**. No new precision, recall, F1, or independent-site accuracy was measured in Phase 40. Previous `0.98943` macro F1 remains a post-hoc, publisher-scenario research result.
- This adapter cannot infer frozen physics flags from raw current/voltage, and does not authenticate price provenance. Both must come from separate fixed, independently audited sensor pipelines.
- The backend continues serving the narrower frozen meter model. The four-lane system remains research-only and offline. The user's real private Docker deployment, live PostgreSQL backup-restore rehearsal and external blind evaluation remain pending.

## Validation

New synthetic tests cover valid end-to-end replay, causal event hold, gap abstention/hold reset, missing values, contradictory coverage, duplicate declarations, site mismatch, unknown event kinds, invalid MACs, duplicate JSON keys, hash mismatches, fractional UTC seconds and maximum-duration refusal. These are software behavior checks, **not** ground-truth detection experiments.
