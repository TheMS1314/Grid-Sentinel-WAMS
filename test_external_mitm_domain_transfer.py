import unittest

import numpy as np
import pandas as pd

from external_mitm_domain_transfer import selective_result, support_mask


class DomainTransferTests(unittest.TestCase):
    def test_source_support_rejects_ood_and_missing(self):
        train = pd.DataFrame({"x": np.linspace(0, 100, 101)})
        target = pd.DataFrame({"x": [25.0, 1000.0, np.nan]})
        self.assertEqual(support_mask(train, target, ["x"]).tolist(), [True, False, False])

    def test_abstention_is_not_counted_as_true_negative(self):
        truth = np.array([1, 1, 0, 0])
        predictions = np.array([1, 1, 0, 0])
        accepted = np.array([True, False, True, False])
        result = selective_result(truth, predictions, accepted)
        self.assertEqual(result["accepted_rows"], 2)
        self.assertEqual(result["abstained_rows"], 2)
        self.assertEqual(result["accepted_only_metrics"]["f1"], 1.0)
        self.assertEqual(result["end_to_end_recall"], 0.5)

    def test_full_abstention_no_division_failure(self):
        result = selective_result(np.array([1, 0]), np.array([1, 0]), np.array([False, False]))
        self.assertEqual(result["end_to_end_recall"], 0)
        self.assertEqual(result["coverage"], 0)


if __name__ == "__main__":
    unittest.main()
