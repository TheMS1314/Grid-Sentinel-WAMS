"""Counterfactual arithmetic checks; real data results from separate audit."""
import unittest
import numpy as np

from data4cyber_price_shift_stress import stress


class ShiftTests(unittest.TestCase):
    def test_known_values_and_missingness(self):
        out = stress(np.array([0., .01, np.nan]), (0., 1., .02), shifts=(0., .01, -.10))
        self.assertEqual([(x['false_review_seconds'], x['observed_benign_seconds']) for x in out],
                         [(0, 2), (0, 2), (2, 2)])

    def test_all_missing_and_nonfinite_shift_refused(self):
        with self.assertRaisesRegex(ValueError, 'Valid observed'):
            stress([np.nan], (0., 1., 2.))
        with self.assertRaisesRegex(ValueError, 'Finite tariff'):
            stress([.1], (0., 1., 2.), shifts=[float('inf')])


if __name__ == '__main__':
    unittest.main()
