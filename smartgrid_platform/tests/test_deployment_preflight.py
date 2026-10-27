"""Static configuration checks: no Docker or host services are started."""
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.deployment_preflight import inspect_project


PROJECT = Path(__file__).resolve().parents[1]


class PreflightTests(unittest.TestCase):
    def build_fixture(self, root):
        shutil.copyfile(PROJECT / 'compose.yaml', root / 'compose.yaml')
        for name in ('backend/Dockerfile', 'backend/model/smartgrid_meter_integrity_model.json',
                     'backend/alembic.ini', 'backend/migrations/env.py',
                     'frontend/Dockerfile', 'frontend/nginx.conf',
                     'frontend/package-lock.json', '.env.example'):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('HEALTHCHECK CMD true' if name.endswith('Dockerfile') else 'synthetic fixture')

    def test_frozen_compose_passes_with_local_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            (root / '.env').write_text('POSTGRES_PASSWORD=LongSecretForSyntheticTests012345\nGRID_SENTINEL_ACCESS_TOKEN=LongUniqueLocalAccessTokenForSyntheticTests0123456789\n')
            result = inspect_project(root)
            self.assertEqual(result['status'], 'STATIC_PREFLIGHT_PASS_NOT_DEPLOYED')
            self.assertEqual(result['errors'], [])
            self.assertTrue(any('NOT built containers' in item for item in result['warnings']))

    def test_missing_env_refuses_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            result = inspect_project(root)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertTrue(any('Missing private .env' in error for error in result['errors']))

    def test_placeholder_password_rejected_without_exposing_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            (root / '.env').write_text('POSTGRES_PASSWORD=REPLACE_WITH_A_LONG_RANDOM_PASSWORD\n')
            self.assertEqual(inspect_project(root)['status'], 'BLOCKED')
            self.assertNotIn('REPLACE_WITH_A_LONG_RANDOM_PASSWORD', str(inspect_project(root)))

    def test_public_port_and_database_host_port_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            (root / '.env').write_text('POSTGRES_PASSWORD=LongSecretForSyntheticTests012345\nGRID_SENTINEL_ACCESS_TOKEN=LongUniqueLocalAccessTokenForSyntheticTests0123456789\n')
            content = (root / 'compose.yaml').read_text()
            (root / 'compose.yaml').write_text(content.replace('127.0.0.1:8080:8080', '0.0.0.0:8080:8080'))
            result = inspect_project(root)
            self.assertTrue(any('bind exclusively' in error for error in result['errors']))
            (root / 'compose.yaml').write_text(content.replace('services:\n  db:\n',
                'services:\n  db:\n    ports: ["5432:5432"]\n'))
            result = inspect_project(root)
            self.assertTrue(any('must not publish host ports' in error for error in result['errors']))

    def test_compose_service_injection_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            (root / '.env').write_text('POSTGRES_PASSWORD=LongSecretForSyntheticTests012345\nGRID_SENTINEL_ACCESS_TOKEN=LongUniqueLocalAccessTokenForSyntheticTests0123456789\n')
            content = (root / 'compose.yaml').read_text()
            (root / 'compose.yaml').write_text(content.replace('services:\n',
                                                              'services:\n  injected:\n    image: busybox\n'))
            result = inspect_project(root)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertTrue(any('Unexpected Compose services' in error for error in result['errors']))

    def test_missing_or_reused_access_token_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            password = 'LongPrivateDatabasePasswordForTests1234567'
            (root / '.env').write_text(f'POSTGRES_PASSWORD={password}\n')
            result = inspect_project(root)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertTrue(any('Private access token' in error for error in result['errors']))
            (root / '.env').write_text(f'POSTGRES_PASSWORD={password}\nGRID_SENTINEL_ACCESS_TOKEN={password}\n')
            self.assertEqual(inspect_project(root)['status'], 'BLOCKED')
            self.assertNotIn(password, str(inspect_project(root)))

    def test_removed_authentication_gate_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_fixture(root)
            (root / '.env').write_text('POSTGRES_PASSWORD=LongDatabasePasswordForSyntheticTests987\nGRID_SENTINEL_ACCESS_TOKEN=SeparateLongAccessTokenForSyntheticTests0123456789\n')
            compose = (root / 'compose.yaml').read_text()
            (root / 'compose.yaml').write_text(compose.replace('GRID_SENTINEL_AUTH_REQUIRED: "1"', 'GRID_SENTINEL_AUTH_REQUIRED: "0"'))
            self.assertTrue(any('authentication' in error for error in inspect_project(root)['errors']))


if __name__ == '__main__':
    unittest.main()
