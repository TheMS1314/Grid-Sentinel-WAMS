"""Out-of-domain MITM flow-feature transfer and sensor-availability stress.

Models train on *only* the named source experimental group. No target fitting,
normalization, threshold selection or target-data adaptation is permitted.
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline

from external_mitm_experiment_holdout import ARP, FEATURES, load_workbooks, scores


DOMAINS = ("real_modbus", "sim_modbus", "sim_mms")


def make_model():
    return make_pipeline(SimpleImputer(strategy="median"), RandomForestClassifier(
        n_estimators=300, min_samples_leaf=5, class_weight="balanced",
        random_state=42, n_jobs=1))


def concatenate(groups, scope):
    selected = [groups[k] for k in sorted(groups) if groups[k]["scope"] == scope]
    return pd.concat([s["frame"] for s in selected], ignore_index=True), np.concatenate([s["label"] for s in selected])


def support_mask(train, target, features):
    """Conservative, SOURCE-ONLY 0.5–99.5 percentile feature support check.

    This is a diagnostic abstention heuristic, not a calibrated OOD detector.
    """
    lower = train[features].quantile(0.005)
    upper = train[features].quantile(0.995)
    good = target[features].notna().all(axis=1)
    good &= np.isfinite(target[features].to_numpy()).all(axis=1)
    good &= target[features].ge(lower).all(axis=1) & target[features].le(upper).all(axis=1)
    return good.to_numpy(dtype=bool)


def selective_result(y, pred, accepted):
    accepted_y, accepted_pred = y[accepted], pred[accepted]
    positives = int((y == 1).sum())
    passed_attacks = int(((y == 1) & accepted).sum())
    conditional = scores(accepted_y, accepted_pred) if len(accepted_y) else None
    return {"accepted_rows": int(accepted.sum()), "abstained_rows": int((~accepted).sum()),
            "coverage": round(float(accepted.mean()), 6),
            "accepted_attacks": passed_attacks,
            "attack_coverage": round(passed_attacks / positives, 6) if positives else None,
            "end_to_end_recall": round((conditional["tp"] if conditional else 0) / positives, 6) if positives else None,
            "accepted_only_metrics": conditional}


def benchmark(groups):
    result = {"design": "zero-target-adaptation, group-to-group domain transfer; fixed Phase48 RF settings",
              "scope": "Exploratory engineered-feature baseline, not frozen Grid Sentinel packet/meter policy",
              "pairs": [], "sensor_ablation": [],
              "caveats": ["Source and target workbooks can share experiment-generating software/parameters",
                          "No evidence of real-site generalization or operational false-alert rate",
                          "Missing features replaced by SOURCE-trained medians, no target leakage"]}
    pooled = {domain: concatenate(groups, domain) for domain in DOMAINS}
    for source in DOMAINS:
        train, train_y = pooled[source]
        for features_name, features in (("flow_only", FEATURES), ("flow_plus_arp", FEATURES + [ARP])):
            model = make_model()
            model.fit(train[features], train_y)
            for target in DOMAINS:
                target_df, target_y = pooled[target]
                if source != target:
                    prediction = model.predict(target_df[features])
                    accepted = support_mask(train, target_df, features)
                    result["pairs"].append({"train": source, "test": target,
                                            "features": features_name,
                                            **scores(target_y, prediction),
                                            "source_quantile_support_gate": selective_result(target_y, prediction, accepted)})
            # Conservative one-sensor-lost test: expose a NaN value to the
            # SOURCE-fitted imputer, not a fresh imputer fit on the test domain.
            for target in DOMAINS:
                if target == source:
                    continue
                target_df, target_y = pooled[target]
                for feature in features:
                    masked = target_df[features].astype(float).copy()
                    masked.loc[:, feature] = np.nan
                    result["sensor_ablation"].append({
                        "train": source, "test": target, "features": features_name,
                        "lost_sensor": feature,
                        **scores(target_y, model.predict(masked))})
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("publisher_zip", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    output = json.dumps(benchmark(load_workbooks(args.publisher_zip)), indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
