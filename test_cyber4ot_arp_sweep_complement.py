import unittest

from cyber4ot_arp_sweep_complement import review_arp_sweep


class SweepPolicyTests(unittest.TestCase):
    def test_strict_cutoff(self):
        self.assertFalse(review_arp_sweep(6, 6))
        self.assertTrue(review_arp_sweep(7, 6))

    def test_invalid(self):
        for pair in ((-1, 6), (6, -1), (2.5, 2)):
            with self.assertRaises(ValueError):
                review_arp_sweep(*pair)


if __name__ == "__main__":
    unittest.main()
