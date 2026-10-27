import copy
import json
import tempfile
import unittest
from pathlib import Path

from research_evidence_audit import FUSION, ABLATION, TRANSFER, PROJECT, audit


class ResearchEvidenceAuditTests(unittest.TestCase):
    def test_bundled_research_arithmetic_and_exclusion(self):
        result = audit()
        self.assertAlmostEqual(result["macro_f1"], 0.989425, places=5)
        self.assertEqual(result["aggregate"], {"tp": 6612, "fp": 69, "fn": 64, "tn": 4019})
        self.assertEqual(result["benign_false_alert_episodes"], 17)
        self.assertEqual(result["excluded_from_macro"],
                         ["S0_benign_baseline", "S1_industroyer_pv_alt"])

    def test_false_alarm_burden_not_suppressed(self):
        result = audit()
        self.assertAlmostEqual(result["benign_row_false_alert_rate"], 69 / 4088, places=7)
        self.assertEqual(result["s0_holdout"]["false_alert_rows"], 4)
        self.assertEqual(result["external_real_modbus_rf_false_positive_rows"], 492)

    def test_tampered_confusion_matrix_blocks_reporting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in (FUSION, ABLATION, TRANSFER):
                output = root / name
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes((PROJECT / name).read_bytes())
            data = json.loads((root / FUSION).read_text())
            row = next(row for row in data["scenarios"] if row["scenario"] == "S1_industroyer_pv")
            row["four_lane_or"]["tp"] += 1
            (root / FUSION).write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "count does not match"):
                audit(root)


if __name__ == "__main__":
    unittest.main()
