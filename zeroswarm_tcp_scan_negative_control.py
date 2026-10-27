"""Post-hoc exploratory transport-pattern lane on independent Zero-SWARM.

This feature was identified after inspecting these same PCAPs. It must never
be reported as blind independent detection accuracy or deployed unchanged.
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

import dpkt

from zeroswarm_independent_pcap_validation import PUBLISHER_MD5, md5, WINDOW_SECONDS


def protocol_window_decision(distinct_destination_ports, syn_only_packets, trained_port_count):
    if trained_port_count <= 0:
        raise ValueError("invalid benign training port count")
    # Both conditions required. SYN probes to ordinary known services alone
    # are insufficient evidence of a broad destination-port scan.
    return "review" if distinct_destination_ports > trained_port_count and syn_only_packets > 0 else "none"


def scan(path):
    first = None
    bins = defaultdict(lambda: {"frames": 0, "tcp_packets": 0, "syn_only": 0, "ports": set()})
    with Path(path).open("rb") as f:
        for timestamp, payload in dpkt.pcap.Reader(f):
            if first is None:
                first = timestamp
            index = int((timestamp - first) // WINDOW_SECONDS)
            row = bins[index]
            row["frames"] += 1
            try:
                ip = dpkt.ethernet.Ethernet(payload).data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                row["tcp_packets"] += 1
                row["ports"].add(tcp.dport)
                row["syn_only"] += int(bool(tcp.flags & dpkt.tcp.TH_SYN) and not bool(tcp.flags & dpkt.tcp.TH_ACK))
            except (dpkt.UnpackError, ValueError, IndexError):
                continue
    return [{"index": idx, "frames": row["frames"], "tcp_packets": row["tcp_packets"],
             "unique_destination_ports": len(row["ports"]), "syn_only_packets": row["syn_only"]}
            for idx, row in sorted(bins.items())]


def evaluate(paths):
    rows = {}
    for family, path in paths.items():
        if md5(path) != PUBLISHER_MD5[family]:
            raise ValueError(f"publisher checksum mismatch for {family}")
        rows[family] = scan(path)
    # Only the short, published benign PCAP determines the port-count bound.
    # Feature conception itself is post-hoc and the second long normal file
    # supplies an additional session-level negative control.
    trained_max = max(w["unique_destination_ports"] for w in rows["normal"])
    result = {}
    for family, windows in rows.items():
        scored = [{**w, "decision": protocol_window_decision(
            w["unique_destination_ports"], w["syn_only_packets"], trained_max)} for w in windows]
        result[family] = {"windows_with_packets": len(scored),
                          "review_windows": sum(w["decision"] == "review" for w in scored),
                          "max_distinct_destination_ports": max(w["unique_destination_ports"] for w in scored),
                          "total_syn_only_packets": sum(w["syn_only_packets"] for w in scored),
                          "window_results": scored}
    return {"warning": "Retrospective, attack-aware feature choice on Zero-SWARM: no claim of blind accuracy, independent validation, or packet-level truth. This is a proposal for prospective freezing only.",
            "method": "One-minute distinct TCP destination-port count exceeding maximum observed in normal_v2b, AND one or more SYN-without-ACK packets; long-normal is a distinct-session benign negative control.",
            "training_port_count_bound": trained_max, "results": result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("normal", type=Path)
    parser.add_argument("long_normal", type=Path)
    parser.add_argument("nmap", type=Path)
    parser.add_argument("flooding", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(evaluate({"normal": args.normal, "long_normal": args.long_normal,
                                   "nmap": args.nmap, "flooding": args.flooding}), sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
