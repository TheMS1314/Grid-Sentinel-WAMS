import unittest

from cyber4ot_vantage_shift_negative_control import BASELINES, NORMAL, THRESHOLDS, alert_count, vantage_bound_decision


class VantageTests(unittest.TestCase):
    def test_training_capture_not_reused_as_benign_holdout(self):
        for viewpoint, trace_id in BASELINES.items():
            self.assertNotIn(trace_id, NORMAL[viewpoint])

    def test_strict_unknown_mac_threshold(self):
        rows = [{"unknown": 0}, {"unknown": 2}, {"unknown": 10}, {"unknown": 1349}]
        self.assertEqual(alert_count(rows, "unknown", 0), 3)
        self.assertEqual(alert_count(rows, "unknown", 10), 1)
        self.assertEqual(alert_count(rows, "unknown", 1349), 0)

    def test_threshold_grid_ordered_and_nonnegative(self):
        self.assertEqual(THRESHOLDS, tuple(sorted(set(THRESHOLDS))))
        self.assertGreaterEqual(THRESHOLDS[0], 0)

    def test_wrong_or_missing_vantage_is_abstention_not_benign(self):
        self.assertEqual(vantage_bound_decision("plc_port", "central_switch", 100000), "abstain")
        self.assertEqual(vantage_bound_decision("plc_port", "", 0), "abstain")
        self.assertEqual(vantage_bound_decision("plc_port", "plc_port", 0), "normal")
        self.assertEqual(vantage_bound_decision("plc_port", "plc_port", 1), "attack")


if __name__ == "__main__":
    unittest.main()
