# Phase 70 — preregistered blinded time-labeled capture benchmark

**Status: harness implemented; no new blinded attack/benign capture has been scored.** Do not interpret harness unit tests as research performance.

## Frozen pre-commitment

Existing rule (unchanged): a 60-second capture-relative interval is reviewed if **more than 2 distinct TCP destination ports** and **at least one TCP SYN without ACK** were observed. A decision is available at the *end* of that interval. No threshold training or selection permitted after seeing the third-party dataset.

Before evaluating, make a manifest with **external source provenance**, original SHA256 hashes, publisher documented attack start/end intervals, verified benign-only intervals, and separately supported scope labels. Do not derive labels from detector output. Do not label a capture's entire time range as benign simply because its filename contains "benign". Preserve time zone and clock-offset evidence if the source attack log uses wall time.

Use the supplied `external_event_time_blind_eval.py`, schema v2:

```json
{
  "schema_version": 2,
  "frozen_rule": "three-or-more TCP destination ports with SYN-no-ACK in 60s",
  "captures": [{
    "path": "capture.pcap",
    "sha256": "INSERT_REAL_64_CHARACTER_SHA256",
    "events": [{"start_seconds": 120, "end_seconds": 180,
                "family": "tcp_scan", "in_scope": true}],
    "benign_intervals": [{"start_seconds": 0, "end_seconds": 90}]
  }]
}
```

Times are **seconds from first packet**; interval bounds and capture integrity checked. The event-time evaluator fails closed on overlapping attack/benign intervals and corrupt source digests. It only scores in-scope events if at least one reviewed 60-second window overlaps the interval. Reported latency is conservative window completion relative to event onset, **not direct packet-level attribution**. False alerts are counted only for whole buckets fully contained in externally verified benign intervals. Unknown or boundary-crossing buckets do not enter the benign denominator. The 24-hour criterion remains unassessable without at least 24 verified hours.

```bash
python -m pip install dpkt==1.9.8
python -m unittest -q test_external_event_time_blind_eval
python external_event_time_blind_eval.py /private/labels/manifest.json /private/raw/captures
```

## Independently identified candidate sources (no new accuracy claimed)

1. **ICS-NAD** (2026, Scientific Data; Science Data Bank DOI 10.57760/sciencedb.25938): original authors report raw PCAP, extracted CSV with labels, and attack-time logs. Inspect whether downloadable authorized bytes and timestamp synchronization allow this schema. The source is from broader industrial control systems, not a power-substation replica; report transfer limitations.
2. **TU Wien Malware Communication in Smart Factories** (DOI 10.48436/ghdc6-45k78; CC BY 4.0): raw PCAP and flow-level labels from a real factory, including Modbus/TCP, MQTT, OPC UA. Large resource (136.6 GiB); not a realistic full immediate download. Use smaller authorized subset only with preregistered selection and known timing.
3. **CIC Modbus 2023**: preferred power-domain source with packet captures and timestamped attack logs; researcher-form access required. User personally obtains it from publisher. No attempt to bypass gate.

The separate previously downloaded TU Delft scanning PCAPNG lacks confirmed attack timing and the KIOS IEC 61850 GOOSE family is outside the TCP scan detector's coverage; these cannot be relabeled into a positive event-level test.

## Decision after new data

Report in-scope event recall and **miss count**, latency upper-bound distribution, clean false alerts per 24 verified benign hours, number abstained, and all uncertainty limits. Keep manifest and checksums immutable, archive raw output privately, and **never retune on this test dataset**. If results are poor, publish them as transfer failure, then create a new preregistered independent test for any future model revision.

This changes validation readiness, **not the project's independently established detection F1 or conference/journal scientific scores**.
