import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.restore_drill import rehearse


class RestoreDrillTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.project = Path(self.directory.name)
        (self.project / "compose.yaml").write_text("services: {}")
        self.archive = self.project / "backup.dump"
        self.archive.write_bytes(b"PGDMP\x00test backup")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.name = "grid_restore_drill_0123456789abcdef"

    def test_default_is_read_only(self):
        def forbidden(*args, **kwargs):
            self.fail("Read-only mode must never call Docker")
        self.assertEqual(rehearse(self.archive, self.digest, project=self.project,
                                 runner=forbidden)["status"], "VERIFIED_ONLY_NO_RESTORE")

    def test_success_checks_tables_then_drops_only_created_database(self):
        commands = []
        def run(cmd, **kwargs):
            commands.append(cmd)
            self.assertEqual(kwargs["cwd"], self.project)
            if "--single-transaction" in cmd:
                self.assertEqual(kwargs["stdin"].read(5), b"PGDMP")
            if "SELECT count(*) FROM public.analysis_runs" in cmd:
                return SimpleNamespace(returncode=0, stdout=b"17\n")
            if "SELECT count(*) FROM public.findings" in cmd:
                return SimpleNamespace(returncode=0, stdout=b"2\n")
            return SimpleNamespace(returncode=0, stdout=b"")
        result = rehearse(self.archive, self.digest, execute=True, project=self.project,
                          runner=run, database_name=self.name)
        self.assertEqual(result["restored_table_rows"], {"analysis_runs": 17, "findings": 2})
        self.assertEqual(len(commands), 5)
        self.assertIn("CREATE DATABASE " + self.name, commands[0])
        self.assertEqual(commands[-1][-1], self.name)
        self.assertIn("dropdb", commands[-1])

    def test_does_not_drop_when_create_fails(self):
        commands = []
        def run(cmd, **kwargs):
            commands.append(cmd)
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"secret")
        with self.assertRaisesRegex(RuntimeError, "details omitted"):
            rehearse(self.archive, self.digest, execute=True, project=self.project,
                      runner=run, database_name=self.name)
        self.assertEqual(len(commands), 1)

    def test_restore_failure_cleans_up_created_database(self):
        commands = []
        def run(cmd, **kwargs):
            commands.append(cmd)
            return SimpleNamespace(returncode=1 if "pg_restore" in cmd else 0, stdout=b"")
        with self.assertRaises(RuntimeError):
            rehearse(self.archive, self.digest, execute=True, project=self.project,
                      runner=run, database_name=self.name)
        self.assertEqual(len(commands), 3)
        self.assertIn("dropdb", commands[-1])

    def test_bad_digest_prevents_all_docker_actions(self):
        def forbidden(*args, **kwargs):
            self.fail("Digest mismatch must never invoke Docker")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            rehearse(self.archive, "0" * 64, execute=True, project=self.project,
                      runner=forbidden, database_name=self.name)

    def test_rejects_non_ephemeral_database_names(self):
        def forbidden(*args, **kwargs):
            self.fail("Unsafe name must be rejected")
        for name in ("smartgrid", "postgres", "grid_restore_drill_0000;DROP DATABASE smartgrid"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                rehearse(self.archive, self.digest, execute=True, project=self.project,
                         runner=forbidden, database_name=name)


if __name__ == "__main__":
    unittest.main()
