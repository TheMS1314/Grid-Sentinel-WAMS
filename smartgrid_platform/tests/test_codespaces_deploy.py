import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.codespaces_deploy import deploy, ensure_secrets, show_token


class CodespacesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        (self.project / "compose.yaml").write_text("services: {}")

    def test_secrets_created_once_distinct_and_not_replaced(self):
        self.assertTrue(ensure_secrets(self.project))
        token = show_token(self.project)
        self.assertGreaterEqual(len(token), 40)
        original = (self.project / ".env").read_bytes()
        self.assertFalse(ensure_secrets(self.project))
        self.assertEqual((self.project / ".env").read_bytes(), original)
        self.assertNotIn(token, str(self.project))
        if os.name != "nt":
            self.assertEqual((self.project / ".env").stat().st_mode & 0o777, 0o600)

    def test_refuses_secret_symlinks(self):
        (self.project / ".env").symlink_to(self.project / "compose.yaml")
        with self.assertRaises(ValueError):
            ensure_secrets(self.project)
        with self.assertRaises(ValueError):
            show_token(self.project)

    def test_requires_codespaces_without_mutation(self):
        with patch.dict(os.environ, {"CODESPACES": ""}):
            with self.assertRaises(EnvironmentError):
                deploy(self.project, docker_path="docker")
        self.assertFalse((self.project / ".env").exists())

    @patch.dict(os.environ, {"CODESPACES": "true"})
    def test_one_command_success_uses_private_compose_and_isolated_restore(self):
        events = []
        def launch(cmd, **kwargs):
            events.append(("start", cmd))
            self.assertEqual(cmd[:3], ["docker", "compose", "up"])
            self.assertIn("--wait", cmd)
            return SimpleNamespace(returncode=0)
        def check(project):
            events.append(("preflight", None))
            return {"errors": []}
        def acceptance(project, live, docker_path):
            events.append(("accept", None))
            self.assertTrue(live)
            return {"status": "LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS"}
        def make_backup(path, compose_dir):
            events.append(("backup", None))
            self.assertEqual(compose_dir, self.project)
            return {"sha256": "a" * 64}
        def restore(path, sha, execute, project):
            events.append(("restore", None))
            self.assertTrue(execute)
            self.assertEqual(sha, "a" * 64)
            return {"status": "ISOLATED_RESTORE_DRILL_PASS", "restored_table_rows":
                    {"analysis_runs": 0, "findings": 0}, "temporary_database_removed": True}
        result = deploy(self.project, docker_path="docker", runner=launch, check=check,
                        accept_stack=acceptance, backup_fn=make_backup, restore_fn=restore)
        self.assertEqual(result["status"], "LIVE_STACK_AND_RECOVERY_PASS")
        self.assertEqual([name for name, _ in events],
                         ["preflight", "start", "accept", "backup", "restore"])
        self.assertTrue((self.project / ".env").exists())

    @patch.dict(os.environ, {"CODESPACES": "true"})
    def test_failing_preflight_never_starts_docker(self):
        def forbidden(*args, **kwargs):
            self.fail("Docker should not be called")
        with self.assertRaises(RuntimeError):
            deploy(self.project, docker_path="docker", check=lambda _: {"errors": ["unsafe"]},
                   runner=forbidden)

    @patch.dict(os.environ, {"CODESPACES": "true"})
    def test_nonhealthy_stack_never_backed_up(self):
        def forbidden(*args, **kwargs):
            self.fail("Database backup must not run on failed acceptance")
        with self.assertRaises(RuntimeError):
            deploy(self.project, docker_path="docker", check=lambda _: {"errors": []},
                   runner=lambda *a, **kw: SimpleNamespace(returncode=0),
                   accept_stack=lambda *a, **kw: {"status": "LIVE_VALIDATION_BLOCKED"},
                   backup_fn=forbidden)


if __name__ == "__main__":
    unittest.main()
