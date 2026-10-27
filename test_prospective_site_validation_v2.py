"""Offline contract tests: fail-closed sensor health and abstentions."""
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from prospective_site_validation_v2 import audit


HEADERS = ["timestamp_utc", "attack_active", "decision", "event_id", "attack_family", "observation_health"]
ROWS = [
    ["2026-10-27T00:00:00Z", "0", "normal", "", "", "healthy"],
    ["2026-10-27T00:00:01Z", "1", "attack", "e1", "mitm", "healthy"],
    ["2026-10-27T00:00:02Z", "1", "abstain", "e1", "mitm", "missing_sensor"],
    ["2026-10-27T00:00:03Z", "0", "attack", "", "", "healthy"],
    ["2026-10-27T00:00:04Z", "0", "abstain", "", "", "unsupported_domain"],
    ["2026-10-27T00:00:05Z", "1", "normal", "e2", "arp", "healthy"],
    ["2026-10-27T00:00:06Z", "1", "abstain", "e2", "arp", "untrusted_source"],
    ["2026-10-27T00:00:07Z", "0", "normal", "", "", "healthy"],
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SiteAuditV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = self.root / "model.bin"
        self.model.write_bytes(b"frozen-test-only-model")
        self.csv = self.root / "run.csv"
        self.manifest = self.root / "manifest.json"
        self.rows = [row.copy() for row in ROWS]
        self.write_fixture()

    def write_fixture(self):
        with self.csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)
            writer.writerows(self.rows)
        self.data = {"protocol_version": 2, "frozen_model_sha256": digest(self.model),
            "frozen_model_path": "model.bin", "frozen_policy": {"name": "fixture"},
            "training_site_ids": ["training"],
            "acceptance_criteria": {"min_scored_coverage": 0.5,
                                    "min_attack_event_detection": 0.5,
                                    "max_false_alert_episodes_per_clean_day": 21600},
            "evaluation_runs": [{"run_id": "holdout", "site_id": "new-site", "csv_path": "run.csv",
                                 "csv_sha256": digest(self.csv), "provenance_reference": "independent-review-needed",
                                 "sample_seconds": 1}]}
        self.manifest.write_text(json.dumps(self.data))

    def test_abstention_not_true_negative_or_successful_attack_detection(self):
        row = audit(self.manifest)["runs"][0]
        self.assertEqual((row["abstain_normal"], row["abstain_attack"]), (1, 2))
        self.assertEqual(row["scored_confusion"], {"tp": 1, "fp": 1, "tn": 2, "fn": 1})
        self.assertEqual(row["scored_coverage"], 0.625)
        self.assertEqual(row["end_to_end_attack_sample_recall"], 0.25)
        self.assertEqual(row["end_to_end_attack_event_recall"], 0.5)
        self.assertEqual(row["attack_families"]["arp"]["end_to_end_recall"], 0)
        self.assertTrue(row["passes_precommitted_criteria"])

    def test_unhealthy_sensor_cannot_score_attack(self):
        self.rows[2][2] = "attack"
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "unhealthy sensor"):
            audit(self.manifest)

    def test_modified_csv_rejected_by_sha(self):
        self.csv.write_text(self.csv.read_text() + "garbage")
        with self.assertRaisesRegex(ValueError, "CSV hash mismatch"):
            audit(self.manifest)

    def test_training_site_overlap_rejected(self):
        self.data["training_site_ids"] = ["new-site"]
        self.manifest.write_text(json.dumps(self.data))
        with self.assertRaisesRegex(ValueError, "Training-site overlap"):
            audit(self.manifest)

    def test_unscored_run_fails_coverage_gate(self):
        for row in self.rows:
            row[2] = "abstain"
            row[5] = "missing_sensor"
        self.write_fixture()
        output = audit(self.manifest)["runs"][0]
        self.assertEqual(output["scored_coverage"], 0)
        self.assertFalse(output["passes_precommitted_criteria"])

    def test_too_dense_timestamps_rejected(self):
        self.rows[1][0] = "2026-10-27T00:00:00.100000Z"
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "irregular timestamp"):
            audit(self.manifest)


if __name__ == "__main__":
    unittest.main()
