"""Frozen, checksum-locked third-domain scan-response audit; no training.

Source: Zenodo DOI 10.5281/zenodo.23055644, Mininet digital-twin PCAPNG.
Usage: python zenodo_power_twin_frozen_tcp.py /path/to/scanningattack_packets.pcapng
No benign reference or packet-level labels are supplied: do not report F1.
"""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import dpkt

from zeroswarm_tcp_scan_negative_control import protocol_window_decision


PUBLISHER_MD5 = "5c9e8e5f51813831084c0e11cbe0d50b"
WINDOW_SECONDS = 60
FROZEN_MAX_TCP_DEST_PORTS = 2


def score_reader(reader):
    first = last = None
    buckets = defaultdict(lambda: {"frames": 0, "ports": set(), "syn_without_ack": 0})
    tcp_frames = malformed = 0
    for timestamp, frame in reader:
        if first is None:
            first = timestamp
        last = timestamp
        bucket = buckets[int((timestamp - first) // WINDOW_SECONDS)]
        bucket["frames"] += 1
        try:
            ip = dpkt.ethernet.Ethernet(frame).data
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            tcp_frames += 1
            bucket["ports"].add(tcp.dport)
            bucket["syn_without_ack"] += int(bool(tcp.flags & dpkt.tcp.TH_SYN) and
                                               not bool(tcp.flags & dpkt.tcp.TH_ACK))
        except (dpkt.UnpackError, ValueError, IndexError):
            malformed += 1
    if first is None:
        raise ValueError("Empty capture")
    windows = []
    for minute, row in sorted(buckets.items()):
        reviewed = protocol_window_decision(
            len(row["ports"]), row["syn_without_ack"], FROZEN_MAX_TCP_DEST_PORTS) == "review"
        windows.append({"minute_index": minute, "frames": row["frames"],
                        "distinct_tcp_destination_ports": len(row["ports"]),
                        "syn_without_ack": row["syn_without_ack"], "review": reviewed})
    flagged = [row["minute_index"] for row in windows if row["review"]]
    episodes = sum(index == 0 or minute != flagged[index - 1] + 1
                   for index, minute in enumerate(flagged))
    return {"frames": sum(row["frames"] for row in windows),
            "ipv4_tcp_frames": tcp_frames, "malformed_frames": malformed,
            "capture_duration_seconds": round(last - first, 3),
            "nonempty_windows": len(windows), "reviewed_windows": len(flagged),
            "review_episodes": episodes, "windows": windows}


def evaluate(path):
    path = Path(path)
    digest = hashlib.md5()
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            checksum.update(block)
    if digest.hexdigest() != PUBLISHER_MD5:
        raise ValueError("Publisher MD5 mismatch; refusing evaluation")
    with path.open("rb") as stream:
        result = score_reader(dpkt.pcapng.Reader(stream))
    return {"source_doi": "10.5281/zenodo.23055644",
            "source_sha256": checksum.hexdigest(), "publisher_md5": digest.hexdigest(),
            "rule": ">2 distinct TCP destination ports and SYN without ACK in a capture-relative 60-second bucket",
            "scope": "Unlabeled scan-response audit, not packet-level attack detection or F1",
            **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcapng", type=Path)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.pcapng), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
