"""Deterministic benign MAC-change stress test; NOT an observed dataset.

Starts with genuine normal Cyber4OT capture counts and adds hypothetical
Ethernet frames whose source MAC is absent from the frozen inventory.
No packets are modified and these are NOT new publisher-labeled captures.
"""
import argparse
import hashlib
import json
from pathlib import Path


BENIGN_EVALUATION_IDS = {3, 71}
NOVEL_FRAMES = (0, 1, 5, 10, 50, 100, 1000)


def decide(unknown_mac_frames, total_frames, upper_rate):
    if not all(isinstance(n, int) for n in (unknown_mac_frames, total_frames)):
        raise ValueError("counts must be integers")
    if total_frames <= 0 or unknown_mac_frames < 0 or unknown_mac_frames > total_frames:
        raise ValueError("inconsistent packet counts")
    if not isinstance(upper_rate, (float, int)) or not 0 <= upper_rate < 1:
        raise ValueError("invalid rate threshold")
    return "attack" if unknown_mac_frames / total_frames > upper_rate else "normal"


def counterfactual(known_unknown, known_total, injected_novel, threshold):
    if not isinstance(injected_novel, int) or injected_novel < 0:
        raise ValueError("injected count must be nonnegative integer")
    # The hypothetical device contributes genuinely new Ethernet frames. The
    # numerator and denominator both increase: avoid rate inflation artifacts.
    return decide(known_unknown + injected_novel, known_total + injected_novel, threshold)


def evaluate(phase54, phase55):
    if len(phase54.get("rows", [])) != 87:
        raise ValueError("expected unmodified Phase54 capture-level evidence")
    benign = {r["capture_id"]: r for r in phase54["rows"] if r["capture_id"] in BENIGN_EVALUATION_IDS}
    if len(benign) != 2 or any(r["truth"] != "normal_scenario" for r in benign.values()):
        raise ValueError("later benign controls missing")
    boundaries = {scope: values["upper_rate_per_100000_packets"] / 100000
                  for scope, values in phase55["calibration"].items()}
    results = []
    for capture_id, original in sorted(benign.items()):
        rate_bound = boundaries[original["vantage"]]
        for injected in NOVEL_FRAMES:
            results.append({
                "baseline_capture": capture_id,
                "vantage": original["vantage"],
                "hypothetical_new_source_mac_frames": injected,
                "simulated_unknown_source_mac_frames": original["new_eth_mac_packets"] + injected,
                "simulated_total_frames": original["frames"] + injected,
                "decision_if_benign_device_change": counterfactual(
                    original["new_eth_mac_packets"], original["frames"], injected, rate_bound),
            })
    return {
        "warning": "SYNTHETIC COUNTERFACTUAL based on real benign count denominators; no maintenance event was observed or relabeled. An attacker can impersonate an allowed MAC; this lane alone cannot authenticate device identity.",
        "source": "Phase54 observed benign counts and Phase55 benign-only per-vantage rate thresholds",
        "results": results,
        "synthetic_false_alert_counts": {
            str(n): sum(r["decision_if_benign_device_change"] == "attack" for r in results
                        if r["hypothetical_new_source_mac_frames"] == n)
            for n in NOVEL_FRAMES},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase54_json", type=Path)
    parser.add_argument("phase55_json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    a, b = args.phase54_json.read_bytes(), args.phase55_json.read_bytes()
    result = evaluate(json.loads(a), json.loads(b))
    result["input_sha256"] = {"phase54": hashlib.sha256(a).hexdigest(), "phase55": hashlib.sha256(b).hexdigest()}
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded)


if __name__ == "__main__":
    main()
