import unittest

import numpy as np
import pandas as pd

from data4cyber_arp_negative_control import summarize


class NonArpNegativeControlTests(unittest.TestCase):
    def test_unrelated_attack_alerts_not_counted_as_clean(self):
        sample = pd.DataFrame({'timestamp': pd.date_range('2026-01-01', periods=5, freq='s', tz='UTC'),
                               'attack_active': [False, True, True, False, False]})
        report = summarize(sample, np.array([True, True, False, True, False]), 'S2_industroyer_bss')
        self.assertEqual(report['arp_alert_seconds_during_unrelated_attack'], 1)
        self.assertEqual(report['arp_alert_seconds_during_clean'], 2)
        self.assertEqual(report['clean_alert_episodes']['episodes'], 2)
        self.assertAlmostEqual(report['clean_row_alert_rate'], 2/3, places=6)


if __name__ == '__main__':
    unittest.main()
