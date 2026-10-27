import io
import hashlib
import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

from scripts.backup_db import backup
from scripts.smoke_check import verify
from scripts.verify_backup import verify_backup


class OperationsTests(unittest.TestCase):
    def test_backup_produces_nonoverwriting_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'compose.yaml').write_text('services: {}')
            target = root / 'backups' / 'research.dump'

            def fake_dump(command, cwd, stdout, stderr, check):
                self.assertEqual(command[:3], ['docker', 'compose', 'exec'])
                stdout.write(b'PGDMP\x00test-payload')
                return SimpleNamespace(returncode=0)

            result = backup(target, root, runner=fake_dump)
            self.assertEqual(target.read_bytes(), b'PGDMP\x00test-payload')
            self.assertFalse(result['overwrote_existing_file'])
            with self.assertRaises(FileExistsError):
                backup(target, root, runner=fake_dump)

    def test_backup_failure_does_not_publish_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'compose.yaml').write_text('services: {}')
            target = root / 'backups' / 'failed.dump'

            def failing_dump(command, cwd, stdout, stderr, check):
                stdout.write(b'PGDMP\x00partial')
                return SimpleNamespace(returncode=2)

            with self.assertRaises(RuntimeError):
                backup(target, root, runner=failing_dump)
            self.assertFalse(target.exists())

    def test_backup_verifier_requires_matching_independent_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'backup.dump'
            archive.write_bytes(b'PGDMP\x00example')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checked = verify_backup(archive, digest)
            self.assertEqual(checked['status'], 'BACKUP_FILE_VERIFIED')
            self.assertEqual(checked['archive_structure'], 'not_requested')
            archive.write_bytes(archive.read_bytes() + b'TAMPERED')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                verify_backup(archive, digest)

    def test_backup_verifier_checks_format_and_optional_pg_restore_list(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'backup.dump'
            archive.write_bytes(b'PGDMP\x00example')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()

            def successful_list(command, **kwargs):
                self.assertEqual(command[:2], ['pg_restore', '--list'])
                return SimpleNamespace(returncode=0)

            self.assertEqual(verify_backup(archive, digest, True, runner=successful_list)
                             ['archive_structure'], 'list_passed')

            def failed_list(command, **kwargs):
                return SimpleNamespace(returncode=1)

            with self.assertRaises(RuntimeError):
                verify_backup(archive, digest, True, runner=failed_list)
            archive.write_bytes(b'WRONG!')
            with self.assertRaisesRegex(ValueError, 'custom-format'):
                verify_backup(archive, hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_smoke_rejects_nonlocal_or_credentialed_urls(self):
        for url in ('https://127.0.0.1:8080', 'http://example.com',
                    'http://user:password@localhost:8080', 'http://localhost:8080/api'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                verify(url)

    def test_smoke_accepts_mocked_research_endpoints(self):
        class MockResponse:
            status = 200
            headers = {'cache-control': 'no-store'}

            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, n=-1):
                return self.payload.read(n)

        def mock_open(url, timeout):
            path = urllib.parse.urlsplit(url).path
            payloads = {'/api/health': {'status': 'alive'},
                        '/api/ready': {'status': 'ready_research_only'},
                        '/api/model': {'status': 'research_only'},
                        '/api/arp-research': {'status': 'POSTHOC_NOT_AUTHENTICATED'}}
            return MockResponse(io.BytesIO(json.dumps(payloads[path]).encode()))

        self.assertEqual(verify(opener=mock_open)['status'], 'LOCAL_SMOKE_PASS')

    def test_smoke_rejects_redirected_response(self):
        class RedirectedResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return 'http://example.com/surprise'

        def redirected_open(url, timeout):
            return RedirectedResponse()

        with self.assertRaisesRegex(RuntimeError, 'redirected'):
            verify(opener=redirected_open)

    def test_smoke_sends_private_token_only_to_protected_endpoints(self):
        observed = []
        class Reply:
            status = 200
            headers = {'cache-control': 'no-store'}
            def __init__(self, body):self.body = io.BytesIO(json.dumps(body).encode())
            def __enter__(self):return self
            def __exit__(self, *args):return False
            def read(self, count=-1):return self.body.read(count)
        def open_request(req, timeout):
            path = urllib.parse.urlsplit(req.full_url if hasattr(req, 'full_url') else req).path
            auth = req.get_header('Authorization') if hasattr(req, 'get_header') else None
            observed.append((path, auth))
            payload = {'/api/health': {'status':'alive'},'/api/ready': {'status':'ready_research_only'},
                       '/api/model': {'status':'research_only'},'/api/arp-research': {'status':'POSTHOC_NOT_AUTHENTICATED'}}
            return Reply(payload[path])
        secret = 'A' * 48
        self.assertEqual(verify(opener=open_request, access_token=secret)['status'], 'LOCAL_SMOKE_PASS')
        self.assertEqual(observed[:2], [('/api/health', None),('/api/ready', None)])
        self.assertTrue(all(header == 'Bearer ' + secret for _, header in observed[2:]))


if __name__ == '__main__':
    unittest.main()
