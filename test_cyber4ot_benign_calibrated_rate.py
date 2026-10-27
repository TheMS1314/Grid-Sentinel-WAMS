import math
import unittest

from cyber4ot_benign_calibrated_rate import calibrated_rate, evaluate, poisson_cdf, upper_mean


class RateAuditTests(unittest.TestCase):
    def test_upper_bound_zero_count(self):
        self.assertAlmostEqual(upper_mean(0), -math.log(0.05), places=9)

    def test_upper_bound_two_counts(self):
        self.assertAlmostEqual(upper_mean(2), 6.2957936219, places=7)
        self.assertAlmostEqual(poisson_cdf(2, upper_mean(2)), 0.05, places=9)

    def test_more_exposure_reduces_rate_bound(self):
        self.assertLess(calibrated_rate(2, 100000), calibrated_rate(2, 50000))

    def test_reject_invalid_inputs(self):
        for val in (-1, 51):
            with self.assertRaises(ValueError):
                upper_mean(val)
        with self.assertRaises(ValueError):
            calibrated_rate(0, 0)

    def test_reject_incomplete_or_duplicates(self):
        with self.assertRaises(ValueError):
            evaluate({"rows": []})


if __name__ == "__main__":
    unittest.main()
