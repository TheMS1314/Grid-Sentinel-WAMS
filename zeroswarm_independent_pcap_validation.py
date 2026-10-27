"""External Zero-SWARM PCAP pilot: local benign enrollment plus source MAC novelty.

This is a different published industrial testbed, not a smart-grid site. The
feature was selected earlier using Cyber4OT; this is not a blind algorithm
selection study, and attack labels are per-file rather than per-packet.
"""
import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import dpkt


PUBLISHER_MD5 = {
    "normal": "9f8235fcdbfcacb32e7a70db14fc6c74",
    "nmap": "62bddfe28a2170b669a649fd04c9a6c9",
    "flooding": "a970eda097645d24ec3b9eb24de858b2",
    "long_normal": "eee8b87e62c482fd574b6e78d32cb12b",
}
BASELINE_SECONDS = 600
CALIBRATION_SECONDS = 300
WINDOW_SECONDS = 60


def md5(path):
    checksum = hashlib.md5()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(2 * 1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def poisson_zero_upper_rate(frames, alpha=0.05):
    if not isinstance(frames, int) or frames <= 0:
        raise ValueError("calibration must contain positive frame count")
    return -math.log(alpha) / frames


def bin_observations(samples, known_macs, anchor):
    counts = {}
    for ts, source in samples:
        bucket = int((ts - anchor) // WINDOW_SECONDS)
        current = counts.setdefault(bucket, {"frames": 0, "new_mac_frames": 0})
        current["frames"] += 1
        current["new_mac_frames"] += int(source not in known_macs)
    return [{"index": index, **data} for index, data in sorted(counts.items())]


def capture(path):
    samples = []
    with Path(path).open("rb") as f:
        for ts, payload in dpkt.pcap.Reader(f):
            if len(payload) < 12:
                raise ValueError("truncated Ethernet packet in publisher PCAP")
            samples.append((ts, payload[6:12].hex(":")))
    if not samples:
        raise ValueError("empty publisher capture")
    return samples


def stream_long_normal(path, known_macs, upper_rate):
    """Score a distinct, long benign recording without loading it into RAM."""
    frames = unknown = 0
    windows = {}
    first = last = None
    sources = Counter()
    with Path(path).open("rb") as f:
        for timestamp, payload in dpkt.pcap.Reader(f):
            if len(payload) < 12:
                raise ValueError("short Ethernet frame in long benign recording")
            if first is None:
                first = timestamp
            last = timestamp
            mac = payload[6:12].hex(":")
            sources[mac] += 1
            frames += 1
            unseen = int(mac not in known_macs)
            unknown += unseen
            index = int((timestamp - first) // WINDOW_SECONDS)
            w = windows.setdefault(index, [0, 0])
            w[0] += 1
            w[1] += unseen
    if frames == 0:
        raise ValueError("empty long benign capture")
    return {"frames": frames, "duration_seconds": last - first,
            "unknown_mac_frames": unknown, "mac_counts": dict(sorted(sources.items())),
            "windows_with_packets": len(windows),
            "windows_flagged": sum(count and novel / count > upper_rate for count, novel in windows.values()),
            "window_results": [{"index": i, "frames": count, "new_mac_frames": novel,
                                 "flag": novel / count > upper_rate}
                               for i, (count, novel) in sorted(windows.items())]}


def evaluate(paths):
    for name, path in paths.items():
        if md5(path) != PUBLISHER_MD5[name]:
            raise ValueError(f"publisher MD5 mismatch for {name}")
    normal = capture(paths["normal"])
    start = normal[0][0]
    enroll = [(ts, mac) for ts, mac in normal if ts - start < BASELINE_SECONDS]
    calibrate = [(ts, mac) for ts, mac in normal if BASELINE_SECONDS <= ts - start < BASELINE_SECONDS + CALIBRATION_SECONDS]
    holdout = [(ts, mac) for ts, mac in normal if ts - start >= BASELINE_SECONDS + CALIBRATION_SECONDS]
    if not enroll or not calibrate or not holdout:
        raise ValueError("normal capture too short for prescribed time split")
    known = frozenset(mac for _, mac in enroll)
    calibration_novel = sum(mac not in known for _, mac in calibrate)
    # We only permit the zero-novelty Poisson calibration bound in this pilot.
    # Nonzero calibration requires a separately specified, validated method.
    if calibration_novel != 0:
        return {"status": "abstain", "reason": "Unseen MAC already present during benign calibration; cannot use zero-count calibration model.",
                "calibration_novel_frames": calibration_novel}
    threshold = poisson_zero_upper_rate(len(calibrate))

    def summary(rows, anchor):
        windows = bin_observations(rows, known, anchor)
        return {"frames": len(rows),
                "novel_source_mac_frames": sum(mac not in known for _, mac in rows),
                "distinct_source_macs": sorted({mac for _, mac in rows}),
                "source_mac_counts": dict(sorted(Counter(mac for _, mac in rows).items())),
                "minutes_with_packets": len(windows),
                "windows_flagged": sum(w["new_mac_frames"] / w["frames"] > threshold for w in windows),
                "window_results": [{**w, "flag": w["new_mac_frames"] / w["frames"] > threshold} for w in windows]}

    normal_test = summary(holdout, start + BASELINE_SECONDS + CALIBRATION_SECONDS)
    attacks = {}
    for family in ("nmap", "flooding"):
        frames = capture(paths[family])
        attacks[family] = summary(frames, frames[0][0])
    long_normal = None
    cross_enrollment = None
    if "long_normal" in paths:
        long_normal = stream_long_normal(paths["long_normal"], known, threshold)
        long_inventory = set(long_normal["mac_counts"])
        cross_enrollment = {
            "long_normal_inventory": sorted(long_inventory),
            "short_normal_heldout_novel_frames_under_long_inventory": sum(
                1 for _, mac in holdout if mac not in long_inventory),
            "attack_novel_frames_under_long_inventory": {
                family: sum(count for mac, count in result["source_mac_counts"].items() if mac not in long_inventory)
                for family, result in attacks.items()},
            "warning": "Pure source-MAC novelty only, not a re-trained full detector. A locally enrolled long-normal inventory contains both attack-capture MACs. No attack anomaly follows from MAC novelty for these files."}
    return {"status": "scored", "publisher": "Zero-SWARM / Zenodo 15082260",
            "publisher_md5_verified": True,
            "warning": "Novelty feature preselected using Cyber4OT; one new published testbed, publisher scenario-level attack labels, no precise per-packet truth. Window flags are not time-localized true positives.",
            "protocol": "First 600 s normal inventory enrollment, next 300 s benign-only rate calibration, remaining normal held out. Frozen rate applied to 60-second windows of later normal and distinct attack-scenario PCAPs.",
            "normal_enrollment": {"frames": len(enroll), "source_macs": sorted(known)},
            "normal_calibration": {"frames": len(calibrate), "new_mac_frames": calibration_novel,
                                   "upper_rate_per_100000_frames": threshold * 100000},
            "normal_holdout": normal_test,
            "attack_scenarios": attacks, "long_normal": long_normal,
            "cross_enrollment": cross_enrollment}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("normal", type=Path)
    parser.add_argument("nmap", type=Path)
    parser.add_argument("flooding", type=Path)
    parser.add_argument("--long-normal", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    paths = {"normal": args.normal, "nmap": args.nmap, "flooding": args.flooding}
    if args.long_normal:
        paths["long_normal"] = args.long_normal
    result = json.dumps(evaluate(paths), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
