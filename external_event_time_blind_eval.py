"""Event-time independent validation for the existing frozen TCP scan rule.

Intervals are seconds relative to the first packet in each verified capture.
Labels and scope must come from publisher evidence prepared before inference.
The window decision is only available at the END of its 60-second bucket.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

import dpkt

from zenodo_power_twin_frozen_tcp import score_reader

WINDOW = 60
FROZEN_POLICY = "three-or-more TCP destination ports with SYN-no-ACK in 60s"


def _interval(item):
    if not isinstance(item, dict) or set(item) != {"start_seconds", "end_seconds"}:
        raise ValueError("Interval must have start_seconds and end_seconds only")
    start, end = item["start_seconds"], item["end_seconds"]
    if any(type(x) not in (int, float) or not math.isfinite(x) for x in (start, end)):
        raise ValueError("Interval bounds must be finite numbers")
    if start < 0 or end <= start:
        raise ValueError("Invalid interval bounds")
    return float(start), float(end)


def _checked_intervals(items, duration):
    if not isinstance(items, list):
        raise ValueError("Intervals must be a list")
    intervals = [_interval(row) for row in items]
    if any(end > duration + 0.001 for _, end in intervals):
        raise ValueError("Labeled interval exceeds capture timeline")
    if any(left[1] > right[0] for left, right in zip(
            sorted(intervals), sorted(intervals)[1:])):
        raise ValueError("Overlapping intervals")
    return intervals


def _capture_path(root, entry):
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "events", "benign_intervals"}:
        raise ValueError("Capture metadata is incomplete or contains extra keys")
    name, digest = entry["path"], entry["sha256"]
    if not isinstance(name, str) or not isinstance(digest, str):
        raise ValueError("Invalid capture path or digest")
    rel = Path(name)
    if not rel.parts or rel.is_absolute() or ".." in rel.parts or rel.suffix not in (".pcap", ".pcapng"):
        raise ValueError("Unsafe capture path")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Invalid capture digest")
    path = (root / rel).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("Capture path leaves data root")
    actual = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            actual.update(block)
    if actual.hexdigest() != digest:
        raise ValueError("SHA-256 mismatch for " + name)
    return path


def _episode_count(indices):
    values = sorted(indices)
    return sum(i == 0 or minute > values[i - 1] + 1 for i, minute in enumerate(values))


def evaluate(manifest_path, data_root):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "frozen_rule", "captures"}:
        raise ValueError("Unexpected manifest format")
    if manifest["schema_version"] != 2 or manifest["frozen_rule"] != FROZEN_POLICY:
        raise ValueError("Frozen policy/schema mismatch")
    if not isinstance(manifest["captures"], list) or not manifest["captures"]:
        raise ValueError("Nonempty captures required")
    root = Path(data_root).resolve(strict=True)
    used = set()
    captures = []
    attack_total = hit = misses = abstain = 0
    latency = []
    total_benign_seconds = 0.0
    benign_review_windows = 0
    benign_episodes = 0
    for entry in manifest["captures"]:
        path = _capture_path(root, entry)
        if str(path) in used:
            raise ValueError("Repeated capture")
        used.add(str(path))
        with path.open("rb") as stream:
            reader = dpkt.pcap.Reader(stream) if path.suffix == ".pcap" else dpkt.pcapng.Reader(stream)
            scored = score_reader(reader)
        duration = scored["capture_duration_seconds"]
        attacks = entry["events"]
        if not isinstance(attacks, list):
            raise ValueError("Attack events must be a list")
        benign = _checked_intervals(entry["benign_intervals"], duration)
        parsed = []
        for event in attacks:
            if not isinstance(event, dict) or set(event) != {"start_seconds", "end_seconds", "family", "in_scope"}:
                raise ValueError("Event metadata invalid")
            start, end = _interval({k: event[k] for k in ("start_seconds", "end_seconds")})
            if end > duration + .001 or not isinstance(event["family"], str) or not event["family"].strip() or type(event["in_scope"]) is not bool:
                raise ValueError("Invalid attack label")
            parsed.append((start, end, event))
        spans = [(a,b) for a,b,_ in parsed] + benign
        if any(x[1] > y[0] for x,y in zip(sorted(spans), sorted(spans)[1:])):
            raise ValueError("Attack/benign intervals overlap")
        windows = scored["windows"]
        result_events = []
        for start, end, event in parsed:
            attack_total += 1
            if not event["in_scope"]:
                abstain += 1
                result_events.append({"family": event["family"], "decision": "ABSTAIN_UNSUPPORTED", "latency_upper_bound_seconds": None})
                continue
            # No event may be credited for a review bucket entirely before its start.
            detections = [w for w in windows if w["review"] and
                          w["minute_index"] * WINDOW < end and
                          (w["minute_index"] + 1) * WINDOW > start]
            if detections:
                hit += 1
                detected_at = (detections[0]["minute_index"] + 1) * WINDOW
                delay = max(0.0, detected_at - start)
                latency.append(delay)
                decision = "REVIEW_OVERLAPPING_EVENT"
            else:
                misses += 1
                delay = None
                decision = "MISSED_IN_SCOPE_EVENT"
            result_events.append({"family": event["family"], "decision": decision,
                                  "latency_upper_bound_seconds": delay})
        # Only FULLY benign windows are eligible as false alerts. Mixed/unknown windows excluded.
        clean = [w["minute_index"] for w in windows if w["review"] and any(
            start <= w["minute_index"]*WINDOW and
            (w["minute_index"]+1)*WINDOW <= end for start,end in benign)]
        benign_review_windows += len(clean)
        benign_episodes += _episode_count(clean)
        total_benign_seconds += sum(end-start for start,end in benign)
        captures.append({"capture": entry["path"], "frames": scored["frames"],
                         "attack_events": result_events, "benign_review_windows": len(clean),
                         "benign_hours": round(sum(end-start for start,end in benign)/3600, 6)})
    scope_n = hit + misses
    return {"status": "FROZEN_EVENT_TIME_EVALUATION", "policy": FROZEN_POLICY,
            "timing": "Capture-relative buckets; latency is upper bound at bucket completion, not packet timestamp",
            "metric_limits": "Labels externally provided; overlapping window is not packet-level attribution; unknown time excluded",
            "captures": captures, "attack_events_labeled": attack_total,
            "in_scope_event_hits": hit, "in_scope_event_misses": misses,
            "in_scope_event_recall": hit/scope_n if scope_n else None,
            "unsupported_events_abstained": abstain, "event_latency_upper_bound_seconds": latency,
            "benign_fully_labeled_hours": round(total_benign_seconds/3600, 6),
            "benign_review_windows": benign_review_windows, "benign_review_episodes": benign_episodes,
            "benign_episodes_per_24h": benign_episodes*86400/total_benign_seconds if total_benign_seconds else None,
            "benign_24h_target_assessable": total_benign_seconds >= 86400}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("captures_root", type=Path)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.manifest, args.captures_root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
