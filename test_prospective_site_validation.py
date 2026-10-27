"""Synthetic fixtures test the evaluator, not defender performance."""
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from prospective_site_validation import evaluate


class ProspectiveValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.csv = self.root / 'capture.csv'
        self.model = self.root / 'frozen-model.json'
        self.model.write_text('{"threshold": 0.5}', encoding='utf-8')
        with self.csv.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['timestamp_utc', 'attack_active', 'alert', 'event_id'])
            w.writerows([
                ['2026-10-26T01:00:00Z', '0', '0', ''],
                ['2026-10-26T01:00:01Z', '0', '1', ''],
                ['2026-10-26T01:00:02Z', '1', '0', 'event-1'],
                ['2026-10-26T01:00:03Z', '1', '1', 'event-1'],
                ['2026-10-26T01:00:04Z', '1', '0', 'event-2'],
            ])
        self.doc = {
            'protocol_version': 1,
            'frozen_model_sha256': hashlib.sha256(self.model.read_bytes()).hexdigest(),
            'frozen_model_path': 'frozen-model.json',
            'frozen_policy': {'threshold': 0.5, 'trained_on': 'site-A'},
            'training_site_ids': ['site-A'],
            'evaluation_runs': [{
                'run_id': 'blind-1', 'site_id': 'site-B',
                'csv_path': 'capture.csv',
                'csv_sha256': hashlib.sha256(self.csv.read_bytes()).hexdigest(),
                'sample_seconds': 1, 'provenance_reference': 'signed-change-ticket-123'
            }]
        }
        self.manifest = self.root / 'manifest.json'
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.doc), encoding='utf-8')

    def test_run_metrics_and_events(self):
        result = evaluate(self.manifest)
        self.assertEqual(result['held_out_site_count'], 1)
        case = result['runs'][0]
        self.assertEqual([case[x] for x in ('tp', 'fp', 'tn', 'fn')], [1, 1, 1, 2])
        self.assertEqual(case['detected_events'], 1)
        self.assertEqual(case['attack_events'], 2)
        self.assertEqual(case['event_detection_rate'], 0.5)
        self.assertEqual(case['false_alert_episodes'], 1)
        self.assertEqual(case['first_detection_latency_seconds'], [1.0])

    def test_mutated_frozen_model_rejected(self):
        self.model.write_text('{"threshold": 0.9}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'model checksum'):
            evaluate(self.manifest)

    def test_missing_time_interval_rejected(self):
        self.csv.write_text(self.csv.read_text().replace('01:00:04Z', '01:00:14Z'))
        self.doc['evaluation_runs'][0]['csv_sha256'] = hashlib.sha256(self.csv.read_bytes()).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, 'Missing observations'):
            evaluate(self.manifest)

    def test_invalid_timestamp_rejected(self):
        self.csv.write_text(self.csv.read_text().replace('2026-10-26T01:00:04Z', '2026-99-26T01:00:04Z'))
        self.doc['evaluation_runs'][0]['csv_sha256'] = hashlib.sha256(self.csv.read_bytes()).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, 'Invalid ISO8601'):
            evaluate(self.manifest)

    def test_same_site_rejected(self):
        self.doc['evaluation_runs'][0]['site_id'] = 'site-A'
        self.save()
        with self.assertRaisesRegex(ValueError, 'overlap'):
            evaluate(self.manifest)

    def test_mutated_predictions_rejected(self):
        self.csv.write_text(self.csv.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            evaluate(self.manifest)

    def test_missing_provenance_rejected(self):
        self.doc['evaluation_runs'][0].pop('provenance_reference')
        self.save()
        with self.assertRaisesRegex(ValueError, 'provenance'):
            evaluate(self.manifest)

    def test_bad_labels_rejected(self):
        self.csv.write_text(self.csv.read_text().replace(',1,0,event-2', ',2,0,event-2'))
        self.doc['evaluation_runs'][0]['csv_sha256'] = hashlib.sha256(self.csv.read_bytes()).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, '0 or 1'):
            evaluate(self.manifest)

    def test_path_traversal_rejected(self):
        self.doc['evaluation_runs'][0]['csv_path'] = '../capture.csv'
        self.save()
        with self.assertRaisesRegex(ValueError, 'inside'):
            evaluate(self.manifest)


if __name__ == '__main__':
    unittest.main()
