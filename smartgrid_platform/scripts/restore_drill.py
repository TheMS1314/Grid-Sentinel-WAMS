"""Explicit, isolated PostgreSQL backup recovery rehearsal on a private Docker host.

The production database is never targeted. A randomly named throwaway database
is created, restored, inspected and dropped only if this run created it.
Requires --execute, the backup file, and its separately recorded SHA-256.
"""
import argparse
import json
import re
import secrets
import subprocess
from pathlib import Path

try:
    from scripts.verify_backup import verify_backup
except ModuleNotFoundError:
    from verify_backup import verify_backup


PROJECT = Path(__file__).resolve().parents[1]
PREFIX = "grid_restore_drill_"


def _compose(project, args, *, runner, input_file=None):
    command = ["docker", "compose", "exec", "-T", "db", *args]
    if input_file is not None:
        with Path(input_file).open("rb") as stream:
            result = runner(command, cwd=project, stdin=stream, capture_output=True,
                            check=False, timeout=180)
    else:
        result = runner(command, cwd=project, capture_output=True,
                        check=False, timeout=60)
    if result.returncode:
        raise RuntimeError("PostgreSQL restore drill command failed (details omitted)")
    return result.stdout.decode("utf-8", "replace") if isinstance(result.stdout, bytes) else result.stdout


def rehearse(backup, digest, *, execute=False, project=PROJECT, runner=subprocess.run,
             database_name=None):
    project = Path(project).resolve(strict=True)
    if not (project / "compose.yaml").is_file():
        raise ValueError("Not a Docker Compose project directory")
    integrity = verify_backup(backup, digest)
    if not execute:
        return {"status": "VERIFIED_ONLY_NO_RESTORE", "sha256": integrity["sha256"],
                "note": "Use --execute on your private Docker host to restore to a throwaway database"}
    name = database_name or (PREFIX + secrets.token_hex(8))
    if not re.fullmatch(r"grid_restore_drill_[0-9a-f]{16}", name):
        raise ValueError("Invalid ephemeral recovery database name")
    created = False
    counts = {}
    try:
        _compose(project, ["psql", "-U", "smartgrid", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
                           "-c", f"CREATE DATABASE {name}"], runner=runner)
        created = True
        _compose(project, ["pg_restore", "-U", "smartgrid", "-d", name, "--exit-on-error",
                           "--no-owner", "--no-acl", "--single-transaction"],
                 runner=runner, input_file=backup)
        for table in ("analysis_runs", "findings"):
            response = _compose(project, ["psql", "-U", "smartgrid", "-d", name,
                                          "-v", "ON_ERROR_STOP=1", "-A", "-t", "-c",
                                          f"SELECT count(*) FROM public.{table}"], runner=runner)
            value = response.strip()
            if not value.isdecimal():
                raise RuntimeError("Unexpected restored row-count response")
            counts[table] = int(value)
    finally:
        if created:
            # Only drop the uniquely named database created successfully by this invocation.
            _compose(project, ["dropdb", "-U", "smartgrid", "--if-exists", name], runner=runner)
    return {"status": "ISOLATED_RESTORE_DRILL_PASS", "sha256": integrity["sha256"],
            "restored_table_rows": counts, "temporary_database_removed": True,
            "scope": "Backup restores and two tables are readable; no disaster recovery time guarantee"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--execute", action="store_true", help="Create and drop an isolated test DB")
    parser.add_argument("--project", type=Path, default=PROJECT)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.backup, args.sha256, execute=args.execute,
                               project=args.project), indent=2))


if __name__ == "__main__":
    main()
