"""Frozen report consistency tests, not new detection performance."""
import copy
import json
import unittest
from pathlib import Path

from data4cyber_price_context_policy import compare


ROOT = Path(__file__).resolve().parent


class ContextPolicyTests(unittest.TestCase):
    def fixtures(self):
        research = json.loads((ROOT / 'smartgrid_platform/backend/model/phase36_four_lane_results.json').read_text())
        stress = json.loads((ROOT / 'reports/SmartGrid_Phase44_Price_Shift_Stress_2026-10-26.json').read_text())
        return research, stress

    def test_policy_tradeoff_matches_ablation(self):
        research, stress = self.fixtures()
        outcome = compare(research, stress)
        self.assertEqual(outcome['full_or_macro_f1'], 0.98943)
        self.assertEqual(outcome['security_only_macro_f1'], 0.83355)
        self.assertEqual(outcome['price_exclusive_attack_rows_not_security_alerted'], 1308)
        self.assertEqual(outcome['price_exclusive_benign_alert_rows_not_security_alerted'], 12)
        self.assertEqual(len(outcome['scenarios']), 6)

    def test_counters_detect_tamper(self):
        research, stress = self.fixtures()
        research['scenarios'][1]['four_lane_or']['tp'] = -1
        with self.assertRaisesRegex(ValueError, 'logical OR'):
            compare(research, stress)
        research, stress = self.fixtures()
        research['leave_one_lane_out_macro']['price_domain']['exclusive_attack_rows_across_S1_S6'] += 1
        with self.assertRaisesRegex(ValueError, 'Macro price-exclusive'):
            compare(research, stress)

    def test_invalid_research_or_stress_status_rejected(self):
        research, stress = self.fixtures()
        stress['status'] = 'UNVERIFIED'
        with self.assertRaisesRegex(ValueError, 'isolated S0'):
            compare(research, stress)


if __name__ == '__main__':
    unittest.main()
