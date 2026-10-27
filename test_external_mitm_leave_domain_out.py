"""Fixed-candidate and source-exclusive study design checks."""
import unittest

import numpy as np
import pandas as pd

from external_mitm_experiment_holdout import ARP, FEATURES
from external_mitm_leave_domain_out import model_for, test_candidates as evaluate_candidates


class LeaveDomainOutTests(unittest.TestCase):
    def test_candidate_names_are_explicit(self):
        for name in ("rf_pooled", "rf_domain_balanced", "robust_logistic", "hist_gradient_boosting"):
            self.assertTrue(hasattr(model_for(name), "fit"))
        with self.assertRaises(ValueError):
            model_for("optimistic_target_tuned")

    def test_train_domains_exclude_target(self):
        # Small in-memory fixture makes the exclusion logic independently testable.
        # 30 rows per domain, both classes represented, six required columns.
        frames = {}
        for offset, scope in enumerate(("real_modbus", "sim_modbus", "sim_mms")):
            values = np.arange(30, dtype=float) + offset
            frame = pd.DataFrame({f: values + j for j, f in enumerate(FEATURES)})
            frame[ARP] = (values % 2 == 0).astype(int)
            frame["Label"] = [1] * 15 + [500] * 15
            frames[scope] = {"scope": scope, "frame": frame, "label": np.array([0] * 15 + [1] * 15)}
        # Model training is deliberately bounded to predeclared source domains.
        output = evaluate_candidates(frames)
        self.assertEqual(len(output["candidates"]), 3 * 2 * 4)
        for result in output["candidates"]:
            self.assertNotIn(result["target"], result["train"])


if __name__ == "__main__":
    unittest.main()
