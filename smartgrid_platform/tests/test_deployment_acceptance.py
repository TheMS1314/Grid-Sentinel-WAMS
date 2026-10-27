import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.deployment_acceptance import accept, parse_compose_ps, evaluate_compose
from tests.test_deployment_preflight import PreflightTests


PROJECT = Path(__file__).resolve().parents[1]


def fixtures(tmp):
    root = Path(tmp)
    PreflightTests().build_fixture(root)
    (root / '.env').write_text('POSTGRES_PASSWORD=LongPrivateAcceptanceFixtureKey123\nGRID_SENTINEL_ACCESS_TOKEN=IndependentAcceptanceFixtureKeyLongEnough123456789\n')
    return root


def healthy():
    return [{"Service": name, "State": "running", "Health": "healthy"}
            for name in ('db', 'backend', 'frontend')]


class AcceptanceTests(unittest.TestCase):
    def test_parser_json_and_jsonl(self):
        rows = healthy()
        self.assertEqual(len(parse_compose_ps(json.dumps(rows))), 3)
        self.assertEqual(len(parse_compose_ps('\n'.join(map(json.dumps, rows)))), 3)

    def test_duplicate_or_missing_service_fails(self):
        with self.assertRaises(ValueError):
            parse_compose_ps(json.dumps([*healthy(), healthy()[0]]))
        with self.assertRaises(ValueError):
            parse_compose_ps(json.dumps(healthy()[:2]))

    def test_missing_health_is_blocked(self):
        rows = {r['Service']: r for r in healthy()}
        rows['frontend'].pop('Health')
        errors, _ = evaluate_compose(rows)
        self.assertTrue(any('frontend health' in line for line in errors))

    def test_offline_never_calls_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            def forbidden(*args, **kwargs):
                raise AssertionError('offline command must not call Docker')
            result = accept(fixtures(tmp), runner=forbidden, smoke=forbidden)
            self.assertEqual(result['status'], 'STATIC_ONLY_NOT_DEPLOYED')

    def test_live_healthy_service_and_local_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            called = []
            def run(command, **kwargs):
                called.append(command)
                return SimpleNamespace(returncode=0, stdout='\n'.join(json.dumps(row) for row in healthy()))
            result = accept(fixtures(tmp), live=True, docker_path='docker', runner=run,
                            smoke=lambda base: {"status": "LOCAL_SMOKE_PASS"})
            self.assertEqual(result['status'], 'LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS')
            self.assertEqual(called, [['docker', 'compose', 'ps', '--format', 'json']])

    def test_unhealthy_or_cli_failure_does_not_pretend_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fixtures(tmp)
            bad = healthy()
            bad[1]['Health'] = 'unhealthy'
            blocked = accept(root, live=True, docker_path='docker',
                             runner=lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(bad)),
                             smoke=lambda base: self.fail('Must not call API smoke after unhealthy Compose'))
            self.assertEqual(blocked['status'], 'LIVE_VALIDATION_BLOCKED')
            self.assertTrue(blocked['live']['errors'])
            blocked = accept(root, live=True, docker_path='docker',
                             runner=lambda *a, **kw: SimpleNamespace(returncode=1, stdout=''))
            self.assertNotEqual(blocked['status'], 'LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS')

    def test_missing_local_secret_blocks_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fixtures(tmp)
            (root / '.env').unlink()
            self.assertEqual(accept(root, live=True, docker_path='docker')['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
