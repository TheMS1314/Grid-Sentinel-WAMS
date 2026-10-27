import unittest

from arp_identity_ambiguity import audit, causal_flags, EVENT_SECONDS, TOTAL_SECONDS


class IdentityAmbiguityTests(unittest.TestCase):
    def test_causal_hold_never_alerts_before_observation(self):
        flags = causal_flags(12, [5], 2)
        self.assertEqual([i for i, flag in enumerate(flags) if flag], [5, 6, 7])

    def test_known_synthetic_burden_is_deterministic(self):
        records = {r['hold_seconds']: r for r in audit()['records']}
        self.assertEqual(records[0]['synthetic_maintenance_false_alert_seconds'], 11)
        self.assertEqual(records[2]['synthetic_maintenance_false_alert_seconds'], 33)
        self.assertEqual(records[5]['synthetic_maintenance_false_alert_seconds'], 56)
        self.assertEqual(records[2]['synthetic_spoof_attack_detected_seconds'], 33)

    def test_same_claims_yield_same_alerts_regardless_of_hidden_truth(self):
        maintenance_observed = causal_flags(TOTAL_SECONDS, EVENT_SECONDS, 2)
        impersonation_observed = causal_flags(TOTAL_SECONDS, EVENT_SECONDS, 2)
        self.assertEqual(maintenance_observed, impersonation_observed)

    def test_out_of_range_and_invalid_parameters_fail(self):
        for length, events, hold in ((10, [10], 2), (10, [-1], 2), (10, [], 31)):
            with self.subTest(length=length, hold=hold), self.assertRaises(ValueError):
                causal_flags(length, events, hold)


if __name__ == '__main__':
    unittest.main()
