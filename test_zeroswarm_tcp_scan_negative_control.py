import unittest

from zeroswarm_tcp_scan_negative_control import protocol_window_decision


class TransportLaneTests(unittest.TestCase):
    def test_requires_both_signals(self):
        self.assertEqual(protocol_window_decision(500, 20, 2), "review")
        self.assertEqual(protocol_window_decision(500, 0, 2), "none")
        self.assertEqual(protocol_window_decision(2, 20, 2), "none")

    def test_unsupported_bound(self):
        with self.assertRaises(ValueError):
            protocol_window_decision(3, 1, 0)


if __name__ == "__main__":
    unittest.main()
