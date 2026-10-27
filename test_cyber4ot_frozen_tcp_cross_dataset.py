import unittest

from cyber4ot_frozen_tcp_cross_dataset import FROZEN_TRAINED_MAX_TCP_DEST_PORTS
from zeroswarm_tcp_scan_negative_control import protocol_window_decision


class FrozenTransferTests(unittest.TestCase):
    def test_no_refitting_of_source_threshold(self):
        self.assertEqual(FROZEN_TRAINED_MAX_TCP_DEST_PORTS, 2)
        self.assertEqual(protocol_window_decision(3, 1, FROZEN_TRAINED_MAX_TCP_DEST_PORTS), "review")
        self.assertEqual(protocol_window_decision(2, 100, FROZEN_TRAINED_MAX_TCP_DEST_PORTS), "none")


if __name__ == "__main__":
    unittest.main()
