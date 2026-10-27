import unittest

from cyber4ot_full_capture_family_audit import ATTACK, BENIGN, classification, tally


class FamilyAuditTests(unittest.TestCase):
    def test_publisher_scenario_partition(self):
        all_numbers = [1, 69] + [n for ns in BENIGN.values() for n in ns]
        all_numbers += [n for groups in ATTACK.values() for ns in groups.values() for n in ns]
        self.assertEqual(len(all_numbers), len(set(all_numbers)))
        self.assertEqual(len(all_numbers), 89)  # excludes 7 attacker-endpoint/non-comparable captures

    def test_posthoc_threshold_is_strict(self):
        self.assertEqual(classification(3), "normal")
        self.assertEqual(classification(4), "attack")

    def test_unscorable_input_rejected(self):
        for bad in (-1, 2.5, "2"):
            with self.assertRaises(ValueError):
                classification(bad)

    def test_tally(self):
        rows = [{"truth": "normal_scenario", "new_eth_mac_packets": 3},
                {"truth": "attack_scenario", "new_eth_mac_packets": 4},
                {"truth": "attack_scenario", "new_eth_mac_packets": 0}]
        self.assertEqual(tally(rows, 3)["attack_captures_flagged"], 1)
        self.assertEqual(tally(rows, 3)["benign_captures_false_flagged"], 0)


if __name__ == "__main__":
    unittest.main()
