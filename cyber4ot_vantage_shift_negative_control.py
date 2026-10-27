"""Benign observation-point/threshold sensitivity for Cyber4OT MAC novelty.

No attack-stage model fitting. Thresholds are exploratory, post-hoc sensitivity
after the prior publication's results were already inspected. They are not
prospectively selected deployment thresholds.
"""
import argparse
import json
import zipfile
from pathlib import Path

from cyber4ot_independent_modbus_probe import capture_summary, md5sum, PUBLISHER_MD5


BASELINES = {"plc_port": 69, "central_switch": 1}
NORMAL = {"plc_port": (70, 71), "central_switch": (2, 3)}
ATTACK_PLC = (82, 84, 86, 88, 90, 92, 94, 95)
THRESHOLDS = (0, 10, 100, 500, 1000)


def alert_count(observations, key, cutoff):
    return sum(row[key] > cutoff for row in observations)


def vantage_bound_decision(training_vantage, observed_vantage, novelty_packets):
    """Require externally authenticated provenance; otherwise return unscored.

    The recorded vantage string is supplied metadata, NOT inferred from PCAP.
    """
    if not training_vantage or not observed_vantage or training_vantage != observed_vantage:
        return "abstain"
    return "attack" if novelty_packets > 0 else "normal"


def evaluate(path):
    if md5sum(path) != PUBLISHER_MD5:
        raise ValueError("Cyber4OT publisher MD5 mismatch")
    output = {"source": "Zenodo 15005190; publisher MD5 verified",
              "warning": "Every threshold comparison is retrospective; benign capture labels are scenario-level, not independent site approvals.",
              "baselines": {}, "comparisons": [], "threshold_sensitivity": []}
    with zipfile.ZipFile(path) as archive:
        policies = {}
        for scope, trace_id in BASELINES.items():
            source = capture_summary(archive, trace_id)
            policies[scope] = {
                "clients": frozenset(source["modbus_client_ips"]),
                "macs": {ip: frozenset(items) for ip, items in source["_peer_macs"].items()},
                "ethernet_macs": frozenset(source["_seen_eth_macs"])}
            output["baselines"][scope] = {
                "normal_source_capture": trace_id,
                "known_ethernet_mac_count": len(policies[scope]["ethernet_macs"]),
                "modbus_clients": sorted(policies[scope]["clients"])}

        for source_scope, policy in policies.items():
            for test_scope, traces in NORMAL.items():
                for trace in traces:
                    obs = capture_summary(archive, trace, policy["clients"],
                                          policy["macs"], policy["ethernet_macs"])
                    output["comparisons"].append({
                        "training_vantage": source_scope, "testing_vantage": test_scope,
                        "capture_id": trace,
                        "new_eth_mac_packets": obs["new_ethernet_source_mac_packets"],
                        "new_modbus_client_packets": obs["new_client_packets"],
                        "flag_any_new_mac": obs["alert_new_ethernet_mac"],
                        "flag_modbus_novelty": obs["alert_new_client"],
                        "vantage_bound_decision": vantage_bound_decision(source_scope, test_scope,
                                                                         obs["new_ethernet_source_mac_packets"])})

        # Threshold sensitivity is explicitly post-hoc, NOT threshold selection.
        plc = policies["plc_port"]
        attack_rows = [capture_summary(archive, n, plc["clients"], plc["macs"], plc["ethernet_macs"])
                       for n in ATTACK_PLC]
        benign_rows = [r for r in output["comparisons"] if r["training_vantage"] == "plc_port"]
        for cutoff in THRESHOLDS:
            output["threshold_sensitivity"].append({
                "min_unknown_mac_packets_exclusive": cutoff,
                "attack_containing_plc_captures_flagged": alert_count(attack_rows, "new_ethernet_source_mac_packets", cutoff),
                "attack_containing_plc_captures_total": len(attack_rows),
                "benign_same_vantage_captures_flagged": sum(r["new_eth_mac_packets"] > cutoff for r in benign_rows if r["testing_vantage"] == "plc_port"),
                "benign_same_vantage_captures_total": len(NORMAL["plc_port"]),
                "benign_other_vantage_captures_flagged": sum(r["new_eth_mac_packets"] > cutoff for r in benign_rows if r["testing_vantage"] == "central_switch"),
                "benign_other_vantage_captures_total": len(NORMAL["central_switch"])})
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publisher_zip", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(evaluate(args.publisher_zip), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded)


if __name__ == "__main__":
    main()
