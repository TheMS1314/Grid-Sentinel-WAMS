"""Integrity and metric tests for external MITM evaluation."""
import unittest
import numpy as np

from external_mitm_experiment_holdout import EXPECTED_MD5, scores


class ExternalMitmTests(unittest.TestCase):
    def test_publisher_digest_is_pinned(self):
        self.assertEqual(EXPECTED_MD5, "8ceb392f6a69086635159ff5bd0fff17")

    def test_confusion_for_binary_attack(self):
        result = scores(np.array([0, 1, 1, 0]), np.array([0, 1, 0, 1]))
        self.assertEqual([result[k] for k in ("tn", "fp", "fn", "tp")], [1, 1, 1, 1])
        self.assertEqual(result["f1"], 0.5)

    def test_no_attack_fold_remains_defined(self):
        result = scores(np.array([0, 0]), np.array([0, 1]))
        self.assertEqual(result["f1"], 0)
        self.assertEqual(result["fp"], 1)


if __name__ == "__main__":
    unittest.main()
