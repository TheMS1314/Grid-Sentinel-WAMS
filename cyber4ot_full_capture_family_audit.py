"""Retrospective full publisher-scenario Cyber4OT audit, by capture vantage.

This analysis was added after examining earlier Cyber4OT attack results; its
outcomes must never be described as prospective/blind generalization.
"""
import argparse
import json
import zipfile
from pathlib import Path

from cyber4ot_independent_modbus_probe import capture_summary, md5sum, PUBLISHER_MD5


BENIGN = {"central_switch": (2, 3), "plc_port": (70, 71)}
ATTACK = {
    "central_switch": {"ping_scan": tuple(range(4, 9)), "host_scan": tuple(range(9, 69))},
    "plc_port": {"ping_scan": tuple(range(72, 77)),
                 "plc_scan": tuple(range(77, 82)),
                 "hijack_macof": (82, 84, 86, 88, 90, 92, 94, 95)},
}
BASELINE = {"central_switch": 1, "plc_port": 69}


def classification(new_mac_packets, threshold=3):
    """An exploratory >3 packet gate, selected after inspecting benign data."""
    if not isinstance(new_mac_packets, int) or new_mac_packets < 0:
        raise ValueError("novel source-MAC packet count must be nonnegative integer")
    if not isinstance(threshold, int) or threshold < 0:
        raise ValueError("threshold must be nonnegative integer")
    return "attack" if new_mac_packets > threshold else "normal"


def tally(rows, cutoff):
    attacks = [r for r in rows if r["truth"] == "attack_scenario"]
    benign = [r for r in rows if r["truth"] == "normal_scenario"]
    return {
        "threshold_exclusive": cutoff,
        "attack_captures_flagged": sum(classification(r["new_eth_mac_packets"], cutoff) == "attack" for r in attacks),
        "attack_captures_total": len(attacks),
        "benign_captures_false_flagged": sum(classification(r["new_eth_mac_packets"], cutoff) == "attack" for r in benign),
        "benign_captures_total": len(benign),
    }


def evaluate(path):
    if md5sum(path) != PUBLISHER_MD5:
        raise ValueError("Cyber4OT publisher archive MD5 mismatch")
    rows = []
    baselines = {}
    with zipfile.ZipFile(path) as z:
        for vantage, capture_id in BASELINE.items():
            base = capture_summary(z, capture_id)
            baselines[vantage] = base
            allowed_ips = frozenset(base["modbus_client_ips"])
            allowed_macs = frozenset(base["_seen_eth_macs"])
            ip_macs = {ip: frozenset(macs) for ip, macs in base["_peer_macs"].items()}
            experiments = [(n, "normal_scenario", "benign") for n in BENIGN[vantage]]
            experiments += [(n, "attack_scenario", family)
                            for family, numbers in ATTACK[vantage].items() for n in numbers]
            for number, truth, family in experiments:
                row = capture_summary(z, number, allowed_ips, ip_macs, allowed_macs)
                rows.append({
                    "vantage": vantage, "capture_id": number, "truth": truth, "family": family,
                    "frames": row["frames"], "modbus_packets": row["modbus_packets"],
                    "new_eth_mac_packets": row["new_ethernet_source_mac_packets"],
                    "new_modbus_client_packets": row["new_client_packets"],
                    "ip_mac_conflict_packets": row["known_ip_new_mac_packets"],
                })
    buckets = sorted({(r["vantage"], r["family"]) for r in rows})
    return {
        "source": "Cyber4OT; Zenodo 15005190; archive MD5 " + PUBLISHER_MD5,
        "method": "Normal capture 001 for central-switch and 069 for PLC-port; scenarios tested only at matching capture point.",
        "warning": "RETROSPECTIVE: the MAC lane and >3 cutoff were selected after exploring this corpus. Attack labels are file-level scenarios; neither packet labels, independence between scans, nor field-site validity is shown.",
        "baseline": {scope: {"capture_id": BASELINE[scope], "known_eth_macs": len(base["_seen_eth_macs"])} for scope, base in baselines.items()},
        "overall": {str(c): tally(rows, c) for c in (0, 3, 10, 100, 500, 1000)},
        "families_at_cutoff_3": [{"vantage": vantage, "family": family, **tally([r for r in rows if r["vantage"] == vantage and r["family"] == family], 3)} for vantage, family in buckets],
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publisher_zip", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(evaluate(args.publisher_zip), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
