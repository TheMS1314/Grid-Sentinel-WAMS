"""Frozen external PCAP acceptance: file-level labels only, no threshold tuning.

Manifest schema v1:
{"schema_version":1,"captures":[
 {"path":"benign.pcap","sha256":"<64 hex>","truth":"benign","family":"normal",
  "tcp_scan_in_scope":false,"verified_benign_seconds":120},
 {"path":"scan.pcapng","sha256":"<64 hex>","truth":"attack","family":"tcp_scan",
  "tcp_scan_in_scope":true}
]}
Only supply verified_benign_seconds if the publisher documents truly benign coverage.
CLI: python external_capture_acceptance.py manifest.json /private/raw/captures
"""
import argparse
import hashlib
import json
from pathlib import Path

import dpkt

from zenodo_power_twin_frozen_tcp import score_reader


ALLOWED_KEYS = {"path", "sha256", "truth", "family",
                "tcp_scan_in_scope", "verified_benign_seconds"}


def _validate(entry):
    if not isinstance(entry, dict) or not (set(entry) <= ALLOWED_KEYS):
        raise ValueError("Unrecognized capture entry")
    if not {"path", "sha256", "truth", "family", "tcp_scan_in_scope"} <= set(entry):
        raise ValueError("Incomplete capture metadata")
    rel = Path(entry["path"]) if isinstance(entry["path"], str) else Path("/")
    if rel.is_absolute() or ".." in rel.parts or not rel.parts or rel.suffix not in {".pcap", ".pcapng"}:
        raise ValueError("Unsafe or unsupported capture path")
    digest = entry["sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Invalid capture SHA-256")
    if entry["truth"] not in {"benign", "attack"}:
        raise ValueError("Unknown scenario label")
    if not isinstance(entry["family"], str) or not entry["family"].strip():
        raise ValueError("Attack/benign family required")
    if type(entry["tcp_scan_in_scope"]) is not bool:
        raise ValueError("Scope flag must be boolean")
    if "verified_benign_seconds" in entry:
        seconds = entry["verified_benign_seconds"]
        if entry["truth"] != "benign" or type(seconds) not in (int, float) or not (0 < seconds):
            raise ValueError("Benign coverage seconds require a positive benign-only interval")
    return rel


def run(manifest_path, data_root):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "captures"} or manifest["schema_version"] != 1:
        raise ValueError("Unsupported manifest schema")
    captures = manifest["captures"]
    if not isinstance(captures, list) or not captures:
        raise ValueError("Nonempty capture inventory required")
    root = Path(data_root).resolve(strict=True)
    rows = []
    unique_paths = set()
    verified_benign_seconds = 0
    benign_episodes = 0
    all_benign_verified = True
    for entry in captures:
        rel = _validate(entry)
        if str(rel) in unique_paths:
            raise ValueError("Repeated source capture")
        unique_paths.add(str(rel))
        path = root / rel
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError("Capture must remain inside the declared data root")
        sha = hashlib.sha256()
        with resolved.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(block)
        if sha.hexdigest() != entry["sha256"]:
            raise ValueError("Capture SHA-256 mismatch: " + rel.name)
        with resolved.open("rb") as stream:
            reader = dpkt.pcap.Reader(stream) if rel.suffix == ".pcap" else dpkt.pcapng.Reader(stream)
            scored = score_reader(reader)
        row = {"file": str(rel), "family": entry["family"], "truth": entry["truth"],
               "tcp_scan_in_scope": entry["tcp_scan_in_scope"],
               "frames": scored["frames"], "duration_seconds": scored["capture_duration_seconds"],
               "nonempty_windows": scored["nonempty_windows"],
               "reviewed_windows": scored["reviewed_windows"],
               "review_episodes": scored["review_episodes"]}
        if entry["truth"] == "benign":
            if "verified_benign_seconds" in entry:
                seconds = entry["verified_benign_seconds"]
                if seconds > scored["capture_duration_seconds"] + 0.001:
                    raise ValueError("Claimed benign coverage exceeds observed capture timespan")
                verified_benign_seconds += seconds
            else:
                all_benign_verified = False
            benign_episodes += scored["review_episodes"]
            row["result_scope"] = "BENIGN_NEGATIVE_CONTROL"
        elif entry["tcp_scan_in_scope"]:
            row["result_scope"] = "IN_SCOPE_ATTACK_CAPTURE"
        else:
            row["result_scope"] = "ABSTAIN_UNSUPPORTED_ATTACK_FAMILY"
        rows.append(row)
    in_scope = [r for r in rows if r["result_scope"] == "IN_SCOPE_ATTACK_CAPTURE"]
    unsupported = [r for r in rows if r["result_scope"] == "ABSTAIN_UNSUPPORTED_ATTACK_FAMILY"]
    count_reviewed = sum(r["reviewed_windows"] > 0 for r in in_scope)
    safe_hours = verified_benign_seconds / 3600
    return {
        "rule": "Frozen TCP: >2 destination ports plus SYN-without-ACK in 60-second buckets",
        "metric_limits": "File-level review only; never event-level onset, packet accuracy or F1",
        "total_captures": len(rows),
        "in_scope_attack_captures": len(in_scope),
        "in_scope_attack_captures_reviewed": count_reviewed,
        "in_scope_attack_capture_review_fraction": count_reviewed / len(in_scope) if in_scope else None,
        "unsupported_attack_captures_abstained": len(unsupported),
        "benign_review_episodes": benign_episodes,
        "verified_benign_hours": safe_hours if all_benign_verified else None,
        "benign_episodes_per_24_verified_hours": (benign_episodes * 24 / safe_hours
                                                if all_benign_verified and safe_hours else None),
        "benign_24h_target_assessable": all_benign_verified and safe_hours >= 24,
        "captures": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("data_root", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.manifest, args.data_root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
