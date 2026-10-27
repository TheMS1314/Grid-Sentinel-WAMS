"""Offline research claim audit; standard library only, never fits a detector.

Validates the bundled retrospective confusion matrices and prints independently
recomputed macro/micro F1, benign alert burden and explicit caveats.
Usage: python research_evidence_audit.py
"""
import json
from pathlib import Path


PROJECT = Path(__file__).resolve().parent
FUSION = "reports/SmartGrid_Phase36_Four_Lane_Results_2026-10-26.json"
ABLATION = "reports/SmartGrid_Phase37_Four_Lane_Ablation_2026-10-26.json"
TRANSFER = "reports/SmartGrid_Phase50_Leave_Domain_Out_2026-10-27.json"
PRIMARY = ("S1_industroyer_pv", "S2_industroyer_bss",
           "S3_arp_spoof_bss_meter_half_values",
           "S4_arp_spoof_loads_pv_two_phase",
           "S5_arp_spoof_loads_pv_bss_two_phase",
           "S6_mqtt_supply_chain_compromise")


def _read(root, name):
    return json.loads((Path(root) / name).read_text(encoding="utf-8"))


def _scores(counts):
    tp, fp, fn, tn = (counts[k] for k in ("tp", "fp", "fn", "tn"))
    if any(type(v) is not int or v < 0 for v in (tp, fp, fn, tn)):
        raise ValueError("Invalid confusion-matrix entry")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def audit(root=PROJECT):
    fusion = _read(root, FUSION)
    ablation = _read(root, ABLATION)
    transfer = _read(root, TRANSFER)
    by_name = {s["scenario"]: s for s in fusion["scenarios"]}
    if len(by_name) != len(fusion["scenarios"]) or not set(PRIMARY) <= set(by_name):
        raise ValueError("Missing or duplicated primary benchmark campaigns")
    aggregate = {key: 0 for key in ("tp", "fp", "fn", "tn")}
    per_scenario = []
    episodes = 0
    for name in PRIMARY:
        row = by_name[name]
        cm = row["four_lane_or"]
        if sum(cm[key] for key in aggregate) != row["rows"]:
            raise ValueError("Confusion-matrix count does not match benchmark rows: " + name)
        computed = _scores(cm)
        for field in ("precision", "recall", "f1"):
            if abs(computed[field] - cm[field]) > 0.000011:
                raise ValueError("Reported score differs from counts: " + name + "/" + field)
        for key in aggregate:
            aggregate[key] += cm[key]
        if row["clean_alert_episodes"]["alert_seconds"] != cm["fp"]:
            raise ValueError("False-alert seconds differ from FP rows: " + name)
        episodes += row["clean_alert_episodes"]["episodes"]
        per_scenario.append({"scenario": name, "f1": computed["f1"],
                             "false_alert_rows": cm["fp"],
                             "benign_rows": cm["fp"] + cm["tn"],
                             "false_alert_episodes": row["clean_alert_episodes"]["episodes"]})
    macro = sum(r["f1"] for r in per_scenario) / len(per_scenario)
    micro = _scores(aggregate)["f1"]
    if abs(macro - fusion["macro_F1_S1_through_S6"]) > 0.000011:
        raise ValueError("Published macro F1 does not match independent recomputation")
    if abs(macro - ablation["macro_F1_S1_through_S6"]) > 0.000011:
        raise ValueError("Fusion/ablation macro disagreement")
    clean = by_name.get("S0_benign_baseline")
    if not clean or clean["four_lane_or"]["fp"] != 4 or clean["rows"] != 360:
        raise ValueError("S0 negative-control holdout mismatch")
    candidate = [row for row in transfer["candidates"]
                 if row["target"] == "real_modbus" and row["variant"] == "flow_plus_arp"
                 and row["model"] == "rf_pooled"]
    if len(candidate) != 1:
        raise ValueError("Missing unambiguous real-Modbus transfer candidate")
    transfer_row = candidate[0]
    if abs(_scores(transfer_row)["f1"] - transfer_row["f1"]) > 0.000011:
        raise ValueError("Transfer F1 inconsistent with confusion matrix")
    return {
        "source": "Bundled historical Data4Cyber and external MITM JSONL-derived aggregates",
        "research_scope": "RETROSPECTIVE_POSTHOC_NOT_DEPLOYED",
        "primary_scenarios": list(PRIMARY),
        "excluded_from_macro": ["S0_benign_baseline", "S1_industroyer_pv_alt"],
        "macro_f1": macro, "pooled_micro_f1": micro,
        "aggregate": aggregate, "benign_rows": aggregate["fp"] + aggregate["tn"],
        "benign_row_false_alert_rate": aggregate["fp"] / (aggregate["fp"] + aggregate["tn"]),
        "benign_false_alert_episodes": episodes,
        "s0_holdout": {"rows": 360, "false_alert_rows": 4,
                       "false_alert_episodes": clean["clean_alert_episodes"]["episodes"]},
        "ablation_macro_without_physics": ablation["leave_one_lane_out_macro"]["physics"]["macro_f1_without_lane"],
        "external_real_modbus_rf_false_positive_rows": transfer_row["fp"],
        "per_scenario": per_scenario,
        "limitations": ["Candidate lanes and hold durations selected post-hoc on examined campaigns",
                        "Source identities and ARP claims unauthenticated",
                        "Correlated per-second observations, no prospective site-days",
                        "External flow classifier and four-lane research fusion not deployed",
                        "No field accuracy, real-world attack confirmation or event onset truth"]
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, sort_keys=True))
