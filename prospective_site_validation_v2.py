"""Offline site acceptance audit with three-way decisions and sensor health.

Consumes independently prepared CSVs/manifest; never trains, tunes or reaches
a live grid. V1 is intentionally unchanged. This evaluator is not a detector.
"""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from prospective_site_validation import confined_path, sha256, validate_manifest, binary, ratio


REQUIRED = {"timestamp_utc", "attack_active", "decision", "event_id", "attack_family", "observation_health"}
DECISIONS = {"normal", "attack", "abstain"}
HEALTH = {"healthy", "missing_sensor", "unsupported_domain", "invalid_schema", "untrusted_source"}


def audit(manifest_path):
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("protocol_version") != 2:
        raise ValueError("protocol_version must be 2")
    validate_manifest({**manifest, "protocol_version": 1})
    criteria = manifest.get("acceptance_criteria")
    if not isinstance(criteria, dict) or set(criteria) != {
            "min_scored_coverage", "min_attack_event_detection", "max_false_alert_episodes_per_clean_day"}:
        raise ValueError("Explicit three-field acceptance_criteria required")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or
           not (0 <= value <= 1) for key, value in criteria.items()
           if key in ("min_scored_coverage", "min_attack_event_detection")):
        raise ValueError("Coverage/event-detection targets must lie in [0,1]")
    limit = criteria["max_false_alert_episodes_per_clean_day"]
    if isinstance(limit, bool) or not isinstance(limit, (int, float)) or not (0 <= limit < float("inf")):
        raise ValueError("False-alert limit must be finite and nonnegative")

    model_path = confined_path(manifest_path.parent, manifest["frozen_model_path"])
    if sha256(model_path).lower() != manifest["frozen_model_sha256"].lower():
        raise ValueError("Frozen model hash mismatch")
    out = []
    for run in manifest["evaluation_runs"]:
        input_path = confined_path(manifest_path.parent, run["csv_path"])
        if sha256(input_path).lower() != run["csv_sha256"].lower():
            raise ValueError(f"CSV hash mismatch: {run['run_id']}")
        confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        health_counts = defaultdict(int)
        abstain_clean = abstain_attack = clean = attack = 0
        events = defaultdict(lambda: {"family": None, "detected": False, "seen_scored": False})
        previous_time = None
        previous_false_alert = False
        false_episodes = 0
        with input_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames):
                raise ValueError(f"Missing columns: {sorted(REQUIRED-set(reader.fieldnames or []))}")
            for line, row in enumerate(reader, start=2):
                stamp = row["timestamp_utc"]
                if not stamp.endswith("Z"):
                    raise ValueError(f"Row {line}: timestamp must end in Z")
                try:
                    when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ValueError(f"Row {line}: malformed timestamp") from exc
                if when.utcoffset() is None or when.utcoffset().total_seconds() != 0:
                    raise ValueError(f"Row {line}: UTC timestamp required")
                if previous_time is not None:
                    interval = (when - previous_time).total_seconds()
                    if interval < run["sample_seconds"] * 0.5 or interval > run["sample_seconds"] * 1.5:
                        raise ValueError(f"Row {line}: duplicate, reversed or irregular timestamp")
                previous_time = when
                truth = binary(row["attack_active"])
                decision = row["decision"]
                health = row["observation_health"]
                if decision not in DECISIONS or health not in HEALTH:
                    raise ValueError(f"Row {line}: invalid decision or observation_health")
                if health != "healthy" and decision != "abstain":
                    raise ValueError(f"Row {line}: unhealthy sensor cannot receive a scored decision")
                event_id, family = row["event_id"].strip(), row["attack_family"].strip()
                if truth and (not event_id or not family):
                    raise ValueError(f"Row {line}: attacks require event_id and attack_family")
                if not truth and (event_id or family):
                    raise ValueError(f"Row {line}: benign rows must have blank attack metadata")
                attack += int(truth)
                clean += int(not truth)
                health_counts[health] += 1
                if truth:
                    event = events[event_id]
                    if event["family"] not in (None, family):
                        raise ValueError(f"Row {line}: event family changed")
                    event["family"] = family
                    event["seen_scored"] |= decision != "abstain"
                    event["detected"] |= decision == "attack"
                if decision == "abstain":
                    abstain_attack += int(truth)
                    abstain_clean += int(not truth)
                elif truth:
                    confusion["tp" if decision == "attack" else "fn"] += 1
                else:
                    confusion["fp" if decision == "attack" else "tn"] += 1
                false_now = (not truth and decision == "attack")
                if false_now and not previous_false_alert:
                    false_episodes += 1
                previous_false_alert = false_now
        if previous_time is None:
            raise ValueError("Empty held-out run")
        total = clean + attack
        event_total = len(events)
        event_detected = sum(bool(x["detected"]) for x in events.values())
        seconds = run["sample_seconds"]
        clean_days = clean * seconds / 86400
        # Rates use all observed clean time. Abstentions are NOT true negatives.
        false_rate = ratio(false_episodes, clean_days)
        coverage = ratio(total - abstain_clean - abstain_attack, total)
        event_rate = ratio(event_detected, event_total)
        by_family = {}
        for family in sorted({x["family"] for x in events.values()}):
            sub = [x for x in events.values() if x["family"] == family]
            by_family[family] = {"events": len(sub),
                                 "scored_events": sum(x["seen_scored"] for x in sub),
                                 "detected_events": sum(x["detected"] for x in sub),
                                 "end_to_end_recall": ratio(sum(x["detected"] for x in sub), len(sub))}
        gates = {
            "scored_coverage": coverage is not None and coverage >= criteria["min_scored_coverage"],
            "attack_event_detection": event_rate is not None and event_rate >= criteria["min_attack_event_detection"],
            "false_alert_burden": false_rate is not None and false_rate <= limit,
        }
        out.append({"run_id": run["run_id"], "site_id": run["site_id"], "rows": total,
                    "normal_rows": clean, "attack_rows": attack,
                    "abstain_normal": abstain_clean, "abstain_attack": abstain_attack,
                    "scored_coverage": coverage, "observation_health": dict(sorted(health_counts.items())),
                    "scored_confusion": confusion,
                    "end_to_end_attack_sample_recall": ratio(confusion["tp"], attack),
                    "scored_only_attack_sample_recall": ratio(confusion["tp"], confusion["tp"] + confusion["fn"]),
                    "false_alert_episodes": false_episodes,
                    "false_alert_episodes_per_clean_day": false_rate,
                    "attack_events": event_total, "detected_attack_events": event_detected,
                    "end_to_end_attack_event_recall": event_rate,
                    "attack_families": by_family, "acceptance_gates": gates,
                    "passes_precommitted_criteria": all(gates.values()),
                    "provenance_reference": run["provenance_reference"]})
    return {"protocol_version": 2, "manifest_sha256": sha256(manifest_path),
            "frozen_model_sha256": manifest["frozen_model_sha256"],
            "site_overlap_checked": True,
            "acceptance_criteria": criteria, "runs": out,
            "all_runs_pass": all(x["passes_precommitted_criteria"] for x in out),
            "caution": "Offline CSV audit only. Recorded site identity, ground truth, provenance, and sensor fidelity still need independent verification."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    text = json.dumps(audit(args.manifest), indent=2, sort_keys=True) + "\n"
    if args.output:
        target = Path(args.output)
        if target.exists():
            raise ValueError("Refusing to overwrite existing audit output")
        target.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
