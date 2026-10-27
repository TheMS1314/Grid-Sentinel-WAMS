import tempfile
import unittest
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.persistence_acceptance import check, snapshot


class PersistenceAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.project = Path(self.directory.name)
        (self.project / 'compose.yaml').write_text('services: {}')
        self.before = {'analysis_id': 'abc', 'detail_sha256': 'a' * 64,
                       'totals': {'analyses': 1, 'observations': 24,
                                  'review_rows': 5, 'abstention_rows': 0}}

    def test_dry_run_never_restarts_database(self):
        def forbidden(*a, **kw):
            self.fail('No Docker restart in default mode')
        result = check(self.project, runner=forbidden,
                       smoke=lambda: {'status': 'LOCAL_SMOKE_PASS'},
                       take_snapshot=lambda _: self.before)
        self.assertEqual(result['status'], 'BASELINE_CAPTURED_NO_RESTART')

    def test_explicit_restart_preserves_exact_snapshot(self):
        called = []
        def runner(cmd, **kwargs):
            called.append(cmd)
            return SimpleNamespace(returncode=0)
        result = check(self.project, execute=True, runner=runner,
                       smoke=lambda: {'status': 'LOCAL_SMOKE_PASS'},
                       take_snapshot=lambda _: dict(self.before))
        self.assertEqual(result['status'], 'POSTGRES_RESTART_PERSISTENCE_PASS')
        self.assertEqual(called, [['docker', 'compose', 'restart', 'db']])

    def test_refuses_mismatched_persisted_data(self):
        count = 0
        def snapshots(_):
            nonlocal count
            count += 1
            return self.before if count == 1 else {**self.before, 'detail_sha256': 'b' * 64}
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            check(self.project, execute=True,
                  runner=lambda *a, **k: SimpleNamespace(returncode=0),
                  smoke=lambda: {'status': 'LOCAL_SMOKE_PASS'},
                  take_snapshot=snapshots)

    def test_no_restart_if_smoke_fails(self):
        def forbidden(*a, **kw):
            self.fail('Must not restart after failed smoke')
        with self.assertRaises(RuntimeError):
            check(self.project, execute=True, runner=forbidden,
                  smoke=lambda: {'status': 'BLOCKED'},
                  take_snapshot=lambda _: self.before)

    def test_restart_failure_is_not_success(self):
        with self.assertRaisesRegex(RuntimeError, 'restart command failed'):
            check(self.project, execute=True,
                  runner=lambda *a, **k: SimpleNamespace(returncode=1),
                  smoke=lambda: {'status': 'LOCAL_SMOKE_PASS'},
                  take_snapshot=lambda _: self.before)

    def test_snapshot_reads_saved_detail_and_totals_without_writes(self):
        class Reply:
            status = 200
            def __init__(self, url, payload):
                self.url = url
                self.stream = io.BytesIO(json.dumps(payload).encode())
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def geturl(self): return self.url
            def read(self, n=-1): return self.stream.read(n)
        seen = []
        def opener(request, timeout):
            seen.append(request.full_url)
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + 'A' * 48)
            suffix = request.full_url.split('/api/', 1)[1]
            payload = {'overview': {'analyses': 1, 'observations': 24,
                                    'review_rows': 5, 'abstention_rows': 0},
                       'analyses?limit=1': [{'id': 'abcdef12-1234'}],
                       'analyses/abcdef12-1234': {'id': 'abcdef12-1234', 'findings': [1, 2]}}[suffix]
            return Reply(request.full_url, payload)
        with patch('scripts.persistence_acceptance.read_private_token', return_value='A' * 48):
            saved = snapshot(self.project, opener=opener)
        self.assertEqual(saved['totals']['analyses'], 1)
        self.assertEqual(saved['analysis_id'], 'abcdef12-1234')
        self.assertEqual(len(seen), 3)

    def test_snapshot_never_follows_redirects(self):
        class Redirect:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def geturl(self): return 'http://not-local.example'
        with patch('scripts.persistence_acceptance.read_private_token', return_value='A' * 48):
            with self.assertRaisesRegex(RuntimeError, 'redirected'):
                snapshot(self.project, opener=lambda *a, **kw: Redirect())


if __name__ == '__main__':
    unittest.main()
