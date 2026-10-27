import unittest

from cyber4ot_maintenance_counterfactual import counterfactual, decide


class MaintenanceCounterfactualTests(unittest.TestCase):
    def test_zero_injection_preserves_original_decision(self):
        self.assertEqual(counterfactual(3, 126492, 0, 0.00007452), "normal")

    def test_new_benign_mac_can_trigger_false_alert(self):
        self.assertEqual(counterfactual(3, 126492, 10, 0.00007452), "attack")
        self.assertEqual(counterfactual(0, 12147, 10, 0.0003691), "attack")

    def test_denominator_increases_with_added_frames(self):
        self.assertEqual(counterfactual(0, 1, 1, 0.75), "normal")
        self.assertEqual(counterfactual(0, 1, 1, 0.25), "attack")

    def test_same_counts_cannot_discriminate_intent(self):
        # An attacker and a benign maintenance event can yield identical counts.
        self.assertEqual(decide(50, 1000, 0.001), decide(50, 1000, 0.001))

    def test_bad_count_rejected(self):
        for args in [(-1, 100, 0.1), (101, 100, 0.1), (0, 0, 0.1), (0, 10, 1)]:
            with self.assertRaises(ValueError):
                decide(*args)
        with self.assertRaises(ValueError):
            counterfactual(0, 100, -1, 0.1)


if __name__ == "__main__":
    unittest.main()
