import unittest

from data4cyber_arp_uncertainty import upper_bound_zero_events, summarize


class ZeroEventBounds(unittest.TestCase):
    def test_exact_one_trial(self):
        self.assertAlmostEqual(upper_bound_zero_events(1), .95)

    def test_decreases_with_count(self):
        self.assertGreater(upper_bound_zero_events(5), upper_bound_zero_events(3442))

    def test_bad_inputs_rejected(self):
        for n in (0, -2, 1.2):
            with self.assertRaises(ValueError):
                upper_bound_zero_events(n)

    def test_zero_event_audit_rejects_an_alert(self):
        rows = [{'scenario': f'S{i}', 'arp_hold_seconds': 2,
                 'arp_alert_seconds_total': int(i == 1),
                 'known_ip_mac_mismatch_packets': 0, 'clean_seconds': 10,
                 'arp_packets_observed': 100} for i in range(5)]
        with self.assertRaises(ValueError):
            summarize(rows)


if __name__ == '__main__':
    unittest.main()
