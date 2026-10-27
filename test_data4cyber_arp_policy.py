"""Unit tests for alert-burden and phase breakdown accounting."""
import unittest

import numpy as np
import pandas as pd

from data4cyber_arp_policy_sweep import alert_episodes, per_phase


class PolicyAccountingTests(unittest.TestCase):
    def test_alert_episodes_separate_gaps(self):
        self.assertEqual(alert_episodes([False, True, True, False, True],
                                        [0, 1, 2, 3, 4]),
                         {'episodes': 2, 'alert_seconds': 3, 'longest_episode_seconds': 2})

    def test_phase_scoring_excludes_benign_rows(self):
        df = pd.DataFrame({'attack_active': [False, True, True, False, True],
                           'attack_phase': ['none', 'a', 'a', 'none', 'b']})
        result = per_phase(df, np.array([True, True, False, False, False]),
                           np.array([True, False, True, False, True]))
        self.assertEqual(result['a']['labeled_seconds'], 2)
        self.assertEqual(result['a']['or_detected_seconds'], 2)
        self.assertEqual(result['b']['arp_detected_seconds'], 1)


if __name__ == '__main__':
    unittest.main()
