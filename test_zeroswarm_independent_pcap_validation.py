import math
import unittest

from zeroswarm_independent_pcap_validation import bin_observations, poisson_zero_upper_rate


class ExternalPcapTests(unittest.TestCase):
    def test_zero_count_calibration(self):
        self.assertAlmostEqual(poisson_zero_upper_rate(1000), -math.log(0.05) / 1000)

    def test_invalid_denominator(self):
        with self.assertRaises(ValueError):
            poisson_zero_upper_rate(0)

    def test_window_binning_and_novelty(self):
        rows = [(100., "a"), (140., "b"), (161., "a"), (222., "c")]
        self.assertEqual(bin_observations(rows, {"a"}, 100.), [
            {"index": 0, "frames": 2, "new_mac_frames": 1},
            {"index": 1, "frames": 1, "new_mac_frames": 0},
            {"index": 2, "frames": 1, "new_mac_frames": 1}])


if __name__ == "__main__":
    unittest.main()
