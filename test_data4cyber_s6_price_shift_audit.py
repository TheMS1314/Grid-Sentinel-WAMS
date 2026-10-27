import unittest

import numpy as np
import pandas as pd

from data4cyber_s6_price_shift_audit import PRICE, calibrate, classify


class PriceDomainTests(unittest.TestCase):
    def test_clean_calibration_fails_when_price_missing(self):
        frame = pd.DataFrame({PRICE: [float('nan')] * 100})
        with self.assertRaisesRegex(ValueError, 'Not enough observed'):
            calibrate(frame)

    def test_missing_prices_abstain_and_outlier_flags(self):
        frame = pd.DataFrame({PRICE: [0.02, 2.3, float('nan')]})
        alarm, observed = classify(frame, (0.0, 0.01, 3.0))
        np.testing.assert_array_equal(alarm, [False, True, False])
        np.testing.assert_array_equal(observed, [True, True, False])


if __name__ == '__main__':
    unittest.main()
