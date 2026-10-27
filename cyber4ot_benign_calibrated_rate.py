"""Phase 55 retrospective MAC-rate audit with benign-only cutoff calibration.

Not blind: the MAC feature itself was selected after inspecting Cyber4OT.
Conditional one-sided Poisson upper rates are heuristic under correlated packets.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path


CALIBRATION = {"central_switch": 2, "plc_port": 70}
REFERENCE = {"central_switch": 1, "plc_port": 69}
ALPHA = 0.05


def poisson_cdf(k, mean):
    if not isinstance(k, int) or k < 0 or not math.isfinite(mean) or mean < 0:
        raise ValueError("invalid Poisson parameters")
    # Adequate for our small calibration counts. Reject huge k to avoid
    # underflow masquerading as a meaningful confidence statement.
    if k > 50:
        raise ValueError("calibration count too high for this simple exact CDF")
    term = math.exp(-mean)
    total = term
    for n in range(1, k + 1):
        term *= mean / n
        total += term
    return total


def upper_mean(k, alpha=ALPHA):
    """Solve P(Poisson(lambda)<=k)=alpha using deterministic bisection."""
    if not 0 < alpha < 1:
        raise ValueError("alpha must lie strictly between 0 and 1")
    low, high = 0.0, max(2.0, (k + 1) * 2.0)
    while poisson_cdf(k, high) > alpha:
        high *= 2
    for _ in range(90):
        mid = (low + high) / 2
        if poisson_cdf(k, mid) > alpha:
            low = mid
        else:
            high = mid
    return (low + high) / 2


def calibrated_rate(count, frames, alpha=ALPHA):
    if not isinstance(frames, int) or frames <= 0:
        raise ValueError("frame count must be positive integer")
    return upper_mean(count, alpha) / frames


def evaluate(payload):
    rows = payload["rows"]
    if len(rows) != 87 or len({(r["vantage"], r["capture_id"]) for r in rows}) != 87:
        raise ValueError("expected 87 unique scored comparable-vantage Cyber4OT captures")
    boundaries = {}
    predictions = []
    for scope, cal_id in CALIBRATION.items():
        matches = [r for r in rows if r["vantage"] == scope and r["capture_id"] == cal_id]
        if len(matches) != 1 or matches[0]["truth"] != "normal_scenario":
            raise ValueError("missing benign-only calibration capture")
        source = matches[0]
        boundary = calibrated_rate(source["new_eth_mac_packets"], source["frames"])
        boundaries[scope] = {"capture_id": cal_id, "unknown_source_mac_packets": source["new_eth_mac_packets"],
                             "frames": source["frames"], "upper_rate_per_100000_packets": boundary * 100000}
        for row in rows:
            if row["vantage"] != scope or row["capture_id"] == cal_id:
                continue
            count, frames = row["new_eth_mac_packets"], row["frames"]
            if frames <= 0 or count < 0 or count > frames:
                raise ValueError("invalid capture count")
            value = count / frames
            predictions.append({"capture_id": row["capture_id"], "vantage": scope,
                                "family": row["family"], "truth": row["truth"],
                                "rate_per_100000_packets": value * 100000,
                                "decision": "attack" if value > boundary else "normal"})
    benign = [r for r in predictions if r["truth"] == "normal_scenario"]
    attacks = [r for r in predictions if r["truth"] == "attack_scenario"]
    return {"method": "At each viewpoint, freeze MAC inventory on baseline 001/069; calibrate a one-sided 95% Poisson upper anomaly rate on benign 002/070 only; test later benign 003/071 and publisher scenario attacks.",
            "warning": "Feature/corpus chosen post-hoc. Packet independence for Poisson is implausible. Two benign calibration recordings, two later benign tests and correlated attacks are far too few for field false-alert estimates.",
            "alpha": ALPHA, "calibration": boundaries,
            "results": {"attack_scenarios_flagged": sum(r["decision"] == "attack" for r in attacks),
                        "attack_scenarios_total": len(attacks),
                        "heldout_benign_false_flagged": sum(r["decision"] == "attack" for r in benign),
                        "heldout_benign_total": len(benign)},
            "predictions": sorted(predictions, key=lambda r: r["capture_id"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase54_json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = args.phase54_json.read_bytes()
    result = evaluate(json.loads(data))
    result["source_phase54_json_sha256"] = hashlib.sha256(data).hexdigest()
    value = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(value)
    else:
        print(value)


if __name__ == "__main__":
    main()
