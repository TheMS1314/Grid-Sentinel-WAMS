import json
import tempfile
import unittest
from pathlib import Path

from scripts.codespace_reopen_acceptance import compare, record


class CodespaceReopenTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name) / 'backups' / 'baseline.json'
        self.state = {'analysis_id': 'abc', 'detail_sha256': 'a' * 64,
                      'totals': {'analyses': 1, 'observations': 24,
                                 'review_rows': 5, 'abstention_rows': 0}}
        self.snapshot = lambda _: dict(self.state)
        self.healthy = lambda: {'status': 'LOCAL_SMOKE_PASS'}

    def test_prepare_and_verify_does_not_call_docker_or_write_database(self):
        result = record(baseline=self.base, project=Path(self.temporary.name),
                        take_snapshot=self.snapshot, check_smoke=self.healthy)
        self.assertEqual(result['status'], 'CODESPACE_REOPEN_BASELINE_SAVED')
        result = compare(baseline=self.base, project=Path(self.temporary.name),
                         take_snapshot=self.snapshot, check_smoke=self.healthy)
        self.assertEqual(result['status'], 'CODESPACE_REOPEN_PERSISTENCE_PASS')
        self.assertEqual(json.loads(self.base.read_text())['schema'], 1)

    def test_refuses_to_overwrite_prior_baseline(self):
        record(baseline=self.base, take_snapshot=self.snapshot,
               check_smoke=self.healthy)
        with self.assertRaises(FileExistsError):
            record(baseline=self.base, take_snapshot=self.snapshot,
                   check_smoke=self.healthy)

    def test_refuses_to_record_unhealthy_stack(self):
        with self.assertRaises(RuntimeError):
            record(baseline=self.base, take_snapshot=self.snapshot,
                   check_smoke=lambda: {'status': 'BLOCKED'})
        self.assertFalse(self.base.exists())

    def test_refuses_drift_after_reopen(self):
        record(baseline=self.base, take_snapshot=self.snapshot,
               check_smoke=self.healthy)
        altered = {**self.state, 'detail_sha256': 'b' * 64}
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            compare(baseline=self.base, take_snapshot=lambda _: altered,
                    check_smoke=self.healthy)

    def test_refuses_missing_or_corrupted_baseline(self):
        with self.assertRaises(ValueError):
            compare(baseline=self.base, take_snapshot=self.snapshot,
                    check_smoke=self.healthy)
        self.base.parent.mkdir(parents=True)
        self.base.write_text('{"schema": 0}')
        with self.assertRaises(ValueError):
            compare(baseline=self.base, take_snapshot=self.snapshot,
                    check_smoke=self.healthy)

    def test_refuses_symlink(self):
        origin = Path(self.temporary.name) / 'original.json'
        origin.write_text('{}')
        self.base.parent.mkdir(parents=True)
        self.base.symlink_to(origin)
        with self.assertRaises(ValueError):
            compare(baseline=self.base, take_snapshot=self.snapshot,
                    check_smoke=self.healthy)
        with self.assertRaises(ValueError):
            record(baseline=self.base, take_snapshot=self.snapshot,
                   check_smoke=self.healthy)


if __name__ == '__main__':
    unittest.main()
