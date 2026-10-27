"""Auditable exploratory leave-one-workbook-out MITM benchmark.

Dataset: Elrawy et al., Zenodo 8375657. Workbook is an experimental group,
not an IID row. This DOES NOT evaluate the frozen Data4Cyber four-lane model.
"""
import argparse
import hashlib
import io
import json
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import make_pipeline


EXPECTED_MD5 = "8ceb392f6a69086635159ff5bd0fff17"
FEATURES = ["IRTT", "TTOC", "MITR", "MATR", "NROC"]
ARP = "ARP poisoning indicator"


def load_workbooks(path):
    if hashlib.md5(Path(path).read_bytes()).hexdigest() != EXPECTED_MD5:
        raise ValueError("Source ZIP does not match publisher MD5")
    groups = {}
    with zipfile.ZipFile(path) as z:
        for name in sorted(n for n in z.namelist() if n.endswith(".xlsx")):
            df = pd.read_excel(io.BytesIO(z.read(name)))
            if list(df.columns[:6]) != FEATURES + [ARP]:
                raise ValueError(f"Unexpected feature schema: {name}")
            values = df.iloc[:, -1].to_numpy()
            if not set(values).issubset({1, 50, 500, 1000, 2000}):
                raise ValueError(f"Unexpected labels: {name}")
            short = Path(name).stem
            scope = "real_modbus" if "Real_life" in name else ("sim_mms" if short in ("D1", "D2", "D3", "D4") else "sim_modbus")
            groups[short] = {"scope": scope, "frame": df, "label": (values != 1).astype(int)}
    return groups


def scores(y, pred):
    tn, fp, fn, tp = [int(n) for n in confusion_matrix(y, pred, labels=[0, 1]).ravel()]
    return {"normal": int((y == 0).sum()), "attacks": int((y == 1).sum()),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(float(precision_score(y, pred, zero_division=0)), 6),
            "recall": round(float(recall_score(y, pred, zero_division=0)), 6),
            "f1": round(float(f1_score(y, pred, zero_division=0)), 6)}


def evaluate(groups):
    output = {"dataset": "Zenodo 8375657 (Elrawy et al., 2023)",
              "source_md5": EXPECTED_MD5,
              "design": "exploratory leave-one-workbook-out, no row-random splits; fixed RF(300, min_samples_leaf=5, class_weight=balanced, seed=42)",
              "warning": "New external flow-feature baseline; NOT evaluation of frozen Data4Cyber four-lane Grid Sentinel model. Post-hoc inspection makes model comparisons exploratory.",
              "workbooks": {}, "scopes": {}}
    for name, data in groups.items():
        frame = data["frame"]
        labels = frame.iloc[:, -1]
        output["workbooks"][name] = {"scope": data["scope"], "rows": len(frame),
            "label_counts": {str(k): int(v) for k, v in sorted(Counter(labels).items())},
            "arp_indicator_counts": {str(k): int(v) for k, v in sorted(Counter(frame[ARP]).items())},
            "missing_cells": int(frame.isna().sum().sum()), "exact_duplicate_rows": int(frame.duplicated().sum())}
    for scope in ("real_modbus", "sim_mms", "sim_modbus"):
        names = sorted(n for n in groups if groups[n]["scope"] == scope)
        variants = {"arp_indicator_only": [], "flow_features_only": [], "flow_plus_arp": []}
        for held in names:
            others = [groups[n] for n in names if n != held]
            train = pd.concat([d["frame"] for d in others], ignore_index=True)
            train_y = np.concatenate([d["label"] for d in others])
            test = groups[held]["frame"]
            test_y = groups[held]["label"]
            for variant, features in (("flow_features_only", FEATURES), ("flow_plus_arp", FEATURES + [ARP])):
                model = make_pipeline(SimpleImputer(strategy="median"),
                    RandomForestClassifier(n_estimators=300, min_samples_leaf=5,
                                           class_weight="balanced", random_state=42, n_jobs=1))
                model.fit(train[features], train_y)
                pred = model.predict(test[features])
                variants[variant].append({"held_out": held, **scores(test_y, pred)})
            variants["arp_indicator_only"].append({"held_out": held,
                **scores(test_y, (test[ARP].to_numpy() == 1).astype(int))})
        output["scopes"][scope] = {}
        for variant, rows in variants.items():
            # Fold macro F1 excludes all-normal held-out workbooks: their F1 is undefined
            # in the attack class; all-normal false positives still count in pooled metrics.
            positive = [r["f1"] for r in rows if r["attacks"] > 0]
            tp, fp, fn, tn = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn", "tn"))
            denom_p, denom_r = tp+fp, tp+fn
            precision = tp/denom_p if denom_p else 0
            recall = tp/denom_r if denom_r else 0
            output["scopes"][scope][variant] = {"pooled": {
                "tp":tp,"fp":fp,"fn":fn,"tn":tn,
                "precision":round(precision,6),"recall":round(recall,6),
                "f1":round(2*precision*recall/(precision+recall),6) if precision+recall else 0},
                "attack_workbook_macro_f1": round(float(np.mean(positive)),6) if positive else None,
                "folds": rows}
    return output


def main():
    p = argparse.ArgumentParser()
    p.add_argument("publisher_zip", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = evaluate(load_workbooks(args.publisher_zip))
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content)


if __name__ == "__main__":
    main()
