"""Experimental leave-one-domain-out binary MITM generalization benchmark.

Two *complete* sources train each candidate, the third is a never-trained test
domain. Candidate comparison is exploratory because all three test domains
are subsequently inspected. No target data (labeled or unlabeled) is used in
training, normalization, model selection, or threshold adjustment.
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import RobustScaler

from external_mitm_experiment_holdout import ARP, FEATURES, load_workbooks, scores
from external_mitm_domain_transfer import DOMAINS, concatenate


def model_for(name):
    if name.startswith("rf_"):
        return make_pipeline(SimpleImputer(strategy="median"),
            RandomForestClassifier(n_estimators=300, min_samples_leaf=5,
                class_weight="balanced", random_state=42, n_jobs=1))
    if name == "robust_logistic":
        return make_pipeline(SimpleImputer(strategy="median"), RobustScaler(),
            LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42))
    if name == "hist_gradient_boosting":
        return make_pipeline(SimpleImputer(strategy="median"),
            HistGradientBoostingClassifier(max_iter=100, learning_rate=0.05,
                                           l2_regularization=1.0, random_state=42))
    raise ValueError(f"Unknown candidate {name}")


def test_candidates(groups):
    pooled = {scope: concatenate(groups, scope) for scope in DOMAINS}
    candidates = ("rf_pooled", "rf_domain_balanced", "robust_logistic", "hist_gradient_boosting")
    results = {"design": "train two domains, hold third domain fully excluded; labels binary (all !=1 attack)",
               "source": "Elrawy et al., Zenodo 8375657, publisher MD5 pinned by loader",
               "not_deployment_evidence": "These domains are one publication's engineered-feature environments, not independent real utilities; post-hoc candidate comparison has no final blind test.",
               "candidates": []}
    for target in DOMAINS:
        sources = [s for s in DOMAINS if s != target]
        X = pd.concat([pooled[s][0] for s in sources], ignore_index=True)
        y = np.concatenate([pooled[s][1] for s in sources])
        source_ids = np.concatenate([np.repeat(s, len(pooled[s][1])) for s in sources])
        X_test, y_test = pooled[target]
        for feature_name, feature_set in (("flow_only", FEATURES), ("flow_plus_arp", FEATURES + [ARP])):
            for candidate in candidates:
                model = model_for(candidate)
                weights = None
                if candidate == "rf_domain_balanced":
                    # Each training domain gets equal total weight; do NOT
                    # infer weights or normalizers from the target domain.
                    weights = np.array([len(y)/(len(sources)*int((source_ids==s).sum())) for s in source_ids])
                if weights is None:
                    model.fit(X[feature_set], y)
                else:
                    model.fit(X[feature_set], y, randomforestclassifier__sample_weight=weights)
                y_hat = model.predict(X_test[feature_set])
                results["candidates"].append({"target": target,
                    "train": sources, "variant": feature_name, "model": candidate,
                    **scores(y_test, y_hat)})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publisher_zip", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = json.dumps(test_candidates(load_workbooks(args.publisher_zip)), indent=2) + "\n"
    if args.output:
        args.output.write_text(data)
    else:
        print(data)


if __name__ == "__main__":
    main()
