import unittest

import numpy as np

from data4cyber_temporal_false_alerts import attribute_false_alerts


class TemporalAttributionTests(unittest.TestCase):
    def test_near_far_and_direction_counts(self):
        truth = np.array([False, False, True, False, False, False])
        alerts = np.array([True, True, False, True, True, True])
        stamps = np.array([0, 9, 10, 14, 25, 60], dtype=float)
        report = attribute_false_alerts(truth, alerts, stamps)
        self.assertEqual(report['false_alert_rows_total'], 5)
        self.assertEqual(report['within_5_seconds'], 2)
        self.assertEqual(report['between_5_and_30_seconds'], 2)
        self.assertEqual(report['farther_than_30_seconds'], 1)
        self.assertEqual(report['nearest_attack_before_alert'], 3)
        self.assertEqual(report['nearest_attack_after_alert'], 2)

    def test_clean_run_keeps_all_false_alerts(self):
        report = attribute_false_alerts([False] * 4, [True, False, True, False], [0, 1, 2, 3])
        self.assertEqual(report['farther_than_30_seconds'], 2)
        self.assertEqual(report['far_clean_rows'], 4)
        self.assertEqual(report['far_clean_alert_rate'], 0.5)

    def test_rejects_unordered_clock(self):
        with self.assertRaisesRegex(ValueError, 'increasing'):
            attribute_false_alerts([False, True], [True, False], [1, 1])


if __name__ == '__main__':
    unittest.main()
