import unittest

import numpy as np

from data4cyber_four_lane_fusion import fusion, ablate_lanes, LANE_NAMES


class FusionTests(unittest.TestCase):
    def test_union_and_alignment(self):
        a = np.array([True, False, False, False])
        b = np.array([False, True, False, False])
        c = np.array([False, False, True, False])
        d = np.array([False, False, False, True])
        np.testing.assert_array_equal(fusion(a, b, c, d), np.ones(4, dtype=bool))

    def test_refuses_mismatched_timelines(self):
        with self.assertRaisesRegex(ValueError, 'timeline'):
            fusion([True], [False, True], [False], [True])

    def test_lane_ablation_counts_unique_true_and_false_alarms(self):
        labels = np.array([True, True, False, False, True])
        lanes = dict(zip(LANE_NAMES, (
            np.array([True, False, False, False, True]),
            np.array([False, True, False, False, True]),
            np.array([False, False, True, False, False]),
            np.array([False, False, False, True, False]))))
        outcome = ablate_lanes(labels, lanes)
        self.assertEqual(outcome['physics']['exclusive_true_positive_rows'], 1)
        self.assertEqual(outcome['modbus_source_hold5']['exclusive_true_positive_rows'], 1)
        self.assertEqual(outcome['arp_claim_hold2']['exclusive_false_positive_rows'], 1)
        self.assertEqual(outcome['price_domain']['exclusive_false_positive_rows'], 1)
        # Shared positive row 4 must not count as exclusive to either lane.
        self.assertEqual(sum(v['exclusive_true_positive_rows'] for v in outcome.values()), 2)


if __name__ == '__main__':
    unittest.main()
