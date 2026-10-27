"""Cyber4OT transfer test of the already-fixed Zero-SWARM transport rule.

Threshold and conjunction are imported unchanged from Phase 58. This is
cross-dataset transfer but not fully blind selection: Cyber4OT was previously
examined for MAC-source novelty and published labels are per scenario file.
"""
import argparse
import io
import json
import zipfile
from collections import defaultdict
from pathlib import Path

import dpkt

from cyber4ot_independent_modbus_probe import PUBLISHER_MD5, md5sum
from cyber4ot_full_capture_family_audit import ATTACK, BENIGN
from zeroswarm_tcp_scan_negative_control import protocol_window_decision


FROZEN_TRAINED_MAX_TCP_DEST_PORTS = 2
WINDOW_SECONDS = 60


def score_member(archive, ident):
    with archive.open(f"traces/Cyber4OT_{ident:03d}.pcapng") as f:
        reader = dpkt.pcapng.Reader(io.BytesIO(f.read()))
        first = None
        windows = defaultdict(lambda: {"frames": 0, "ports": set(), "syn": 0})
        for ts, data in reader:
            if first is None:
                first = ts
            index = int((ts - first) // WINDOW_SECONDS)
            row = windows[index]
            row["frames"] += 1
            try:
                ip = dpkt.ethernet.Ethernet(data).data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                row["ports"].add(tcp.dport)
                row["syn"] += int(bool(tcp.flags & dpkt.tcp.TH_SYN) and not bool(tcp.flags & dpkt.tcp.TH_ACK))
            except (dpkt.UnpackError, ValueError, IndexError):
                continue
        if not windows:
            raise ValueError(f"capture {ident} contained no frames")
        results = [{"index": index, "frames": row["frames"], "ports": len(row["ports"]),
                    "syn_probes": row["syn"], "review": protocol_window_decision(
                        len(row["ports"]), row["syn"], FROZEN_TRAINED_MAX_TCP_DEST_PORTS) == "review"}
                   for index, row in sorted(windows.items())]
        return {"capture_id": ident, "windows": len(results),
                "review_windows": sum(r["review"] for r in results),
                "max_unique_ports_per_minute": max(r["ports"] for r in results),
                "syn_probe_packets": sum(r["syn_probes"] for r in results)}


def evaluate(path):
    if md5sum(path) != PUBLISHER_MD5:
        raise ValueError("Cyber4OT publisher checksum mismatch")
    output = []
    with zipfile.ZipFile(path) as z:
        for vantage, controls in BENIGN.items():
            for n in controls:
                output.append({**score_member(z, n), "vantage": vantage,
                               "family": "benign", "scenario_truth": "normal"})
        for vantage, families in ATTACK.items():
            for family, captures in families.items():
                for n in captures:
                    output.append({**score_member(z, n), "vantage": vantage,
                                   "family": family, "scenario_truth": "attack"})
    grouped = {}
    for row in output:
        key = f'{row["vantage"]}/{row["family"]}'
        bucket = grouped.setdefault(key, {"capture_count": 0, "capture_reviewed": 0,
                                          "windows": 0, "windows_reviewed": 0})
        bucket["capture_count"] += 1
        bucket["capture_reviewed"] += bool(row["review_windows"])
        bucket["windows"] += row["windows"]
        bucket["windows_reviewed"] += row["review_windows"]
    return {"source": "Cyber4OT publisher MD5 validated; 83 attack-scenario and 4 benign comparable-vantage captures",
            "rule": "Zero-SWARM Phase58 >2 distinct TCP destination ports AND SYN-without-ACK present in a 60-second bucket, fixed without refitting",
            "warning": "Cross-dataset transfer, but Cyber4OT was previously examined by researchers; labels are scenario-level, no attacker onset truth. Packet and window labels are not independently adjudicated.",
            "groups": grouped, "captures": sorted(output, key=lambda row: row["capture_id"])}


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
