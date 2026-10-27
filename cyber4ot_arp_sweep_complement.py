"""Exploratory ARP-target discovery lane on Cyber4OT.

Count unique ARP-request target IPv4 addresses per capture-relative minute.
Calibrate separately using only two publisher normal files at each vantage.
ARP feature itself chosen after inspecting missed ping-scan attack scenarios:
THIS IS POST-HOC, NOT BLIND ACCURACY.
"""
import argparse
import io
import json
import socket
import zipfile
from collections import defaultdict
from pathlib import Path

import dpkt

from cyber4ot_independent_modbus_probe import md5sum, PUBLISHER_MD5
from cyber4ot_full_capture_family_audit import BENIGN, ATTACK
from cyber4ot_frozen_tcp_cross_dataset import score_member as frozen_tcp_score


BASELINE = {"central_switch": 1, "plc_port": 69}
CALIBRATION = {"central_switch": 2, "plc_port": 70}
HELDOUT = {"central_switch": 3, "plc_port": 71}


def review_arp_sweep(unique_targets, benign_max):
    if not isinstance(unique_targets, int) or not isinstance(benign_max, int):
        raise ValueError("ARP target counts must be integers")
    if unique_targets < 0 or benign_max < 0:
        raise ValueError("ARP counts must be nonnegative")
    return unique_targets > benign_max


def capture_arp(archive, ident):
    with archive.open(f"traces/Cyber4OT_{ident:03d}.pcapng") as f:
        reader = dpkt.pcapng.Reader(io.BytesIO(f.read()))
        start = None
        targets = defaultdict(set)
        frames = defaultdict(int)
        for ts, raw in reader:
            if start is None:
                start = ts
            index = int((ts - start) // 60)
            frames[index] += 1
            try:
                arp = dpkt.ethernet.Ethernet(raw).data
                if isinstance(arp, dpkt.arp.ARP) and arp.op == dpkt.arp.ARP_OP_REQUEST:
                    targets[index].add(socket.inet_ntoa(arp.tpa))
            except (dpkt.UnpackError, ValueError, OSError, IndexError):
                continue
    if not frames:
        raise ValueError("empty capture")
    return {"capture_id": ident, "minute_counts": [len(targets[i]) for i in sorted(frames)]}


def evaluate(path):
    if md5sum(path) != PUBLISHER_MD5:
        raise ValueError("Cyber4OT publisher digest mismatch")
    with zipfile.ZipFile(path) as z:
        thresholds = {}
        for scope in BASELINE:
            base = capture_arp(z, BASELINE[scope])
            cal = capture_arp(z, CALIBRATION[scope])
            thresholds[scope] = max((*base["minute_counts"], *cal["minute_counts"]))
        rows = []
        for scope, ident in HELDOUT.items():
            arp = capture_arp(z, ident)
            tcp = frozen_tcp_score(z, ident)
            rows.append({"vantage": scope, "capture_id": ident, "truth": "normal", "family": "benign",
                         "arp_max_targets": max(arp["minute_counts"]),
                         "arp_review_minutes": sum(review_arp_sweep(v, thresholds[scope]) for v in arp["minute_counts"]),
                         "tcp_review_minutes": tcp["review_windows"]})
        for scope, groups in ATTACK.items():
            for family, numbers in groups.items():
                for ident in numbers:
                    arp = capture_arp(z, ident)
                    tcp = frozen_tcp_score(z, ident)
                    rows.append({"vantage": scope, "capture_id": ident, "truth": "attack_scenario", "family": family,
                                 "arp_max_targets": max(arp["minute_counts"]),
                                 "arp_review_minutes": sum(review_arp_sweep(v, thresholds[scope]) for v in arp["minute_counts"]),
                                 "tcp_review_minutes": tcp["review_windows"]})
    groups = {}
    for row in rows:
        key = f'{row["vantage"]}/{row["family"]}'
        group = groups.setdefault(key, {"count": 0, "arp_reviewed": 0, "tcp_reviewed": 0, "either_reviewed": 0})
        group["count"] += 1
        group["arp_reviewed"] += bool(row["arp_review_minutes"])
        group["tcp_reviewed"] += bool(row["tcp_review_minutes"])
        group["either_reviewed"] += bool(row["arp_review_minutes"] or row["tcp_review_minutes"])
    return {
        "source": "Cyber4OT Zenodo 15005190, checksum verified",
        "warning": "ARP feature selected after inspection of Cyber4OT ping-scan misses; targets and benign thresholds assessed post-hoc. An OR combination is diagnostic only and unsafe to promote as cross-site validated accuracy.",
        "calibration": {scope: {"baseline": BASELINE[scope], "benign_calibration": CALIBRATION[scope],
                                "heldout_normal": HELDOUT[scope], "unique_arp_targets_per_minute_max": value}
                        for scope, value in thresholds.items()},
        "groups": groups, "rows": sorted(rows, key=lambda x: x["capture_id"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publisher_zip", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(evaluate(args.publisher_zip), sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded)


if __name__ == "__main__":
    main()
