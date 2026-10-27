"""One-command *private* Codespaces Docker deployment and recovery acceptance.

Run from the Codespaces terminal: python smartgrid_platform/scripts/codespaces_deploy.py
This runs only on an operator-controlled Codespace; it never changes GitHub port
visibility or publishes a secret. Existing .env files are never replaced.
"""
import argparse
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

try:
    from scripts.backup_db import backup
    from scripts.deployment_preflight import inspect_project
    from scripts.deployment_acceptance import accept
    from scripts.restore_drill import rehearse
except ModuleNotFoundError:
    from backup_db import backup
    from deployment_preflight import inspect_project
    from deployment_acceptance import accept
    from restore_drill import rehearse


PROJECT = Path(__file__).resolve().parents[1]


def ensure_secrets(project=PROJECT):
    """Create once with restrictive permissions; never print or replace secrets."""
    destination = Path(project) / ".env"
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError("Refusing an unsafe existing .env path")
        return False
    password, token = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(f"POSTGRES_PASSWORD={password}\nGRID_SENTINEL_ACCESS_TOKEN={token}\n")
    return True


def show_token(project=PROJECT):
    """Reveal only on explicit operator request in their own private terminal."""
    env = Path(project) / ".env"
    if env.is_symlink() or not env.is_file():
        raise ValueError("No regular private .env file")
    values = [line.split("=", 1)[1].strip() for line in env.read_text(encoding="utf-8").splitlines()
              if line.startswith("GRID_SENTINEL_ACCESS_TOKEN=")]
    if len(values) != 1 or len(values[0]) < 40:
        raise ValueError("Access token is missing or invalid")
    return values[0]


def deploy(project=PROJECT, *, runner=subprocess.run, docker_path=None,
           do_restore=True, check=inspect_project, accept_stack=accept,
           backup_fn=backup, restore_fn=rehearse):
    project = Path(project).resolve(strict=True)
    if not (project / "compose.yaml").is_file():
        raise ValueError("Expected smartgrid_platform/compose.yaml")
    if not os.environ.get("CODESPACES"):
        raise EnvironmentError("This launcher is restricted to GitHub Codespaces")
    docker = docker_path or shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker CLI not found inside Codespace")
    created = ensure_secrets(project)
    preflight = check(project)
    if preflight["errors"]:
        raise RuntimeError("Private deployment preflight failed; review local configuration")
    # Arguments rather than shell interpolation; stderr can contain user secrets,
    # so do not print or return raw Docker subprocess output on failure.
    result = runner([docker, "compose", "up", "-d", "--build", "--wait",
                     "--wait-timeout", "300"], cwd=project, capture_output=True,
                    check=False, timeout=1200)
    if result.returncode:
        raise RuntimeError("Docker build/start failed; review logs privately in Codespaces")
    acceptance = accept_stack(project, live=True, docker_path=docker)
    if acceptance["status"] != "LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS":
        raise RuntimeError("Live stack acceptance failed; no restore drill started")
    summary = {"status": "LIVE_STACK_AND_RECOVERY_PASS" if do_restore else "LIVE_STACK_PASS_RECOVERY_UNTESTED",
               "secrets_created": created, "private_forwarded_port": 8080,
               "port_visibility": "MUST_CONFIRM_PRIVATE_IN_CODESPACES_PORTS_PANEL",
               "live_acceptance": acceptance["status"]}
    if do_restore:
        target = project / "backups" / ("grid_codespaces_drill_" + secrets.token_hex(8) + ".dump")
        dump = backup_fn(target, compose_dir=project)
        drill = restore_fn(target, dump["sha256"], execute=True, project=project)
        if drill["status"] != "ISOLATED_RESTORE_DRILL_PASS":
            raise RuntimeError("Isolated database restore was not confirmed")
        summary.update({"backup_sha256": dump["sha256"], "backup_filename": target.name,
                        "restored_table_rows": drill["restored_table_rows"],
                        "ephemeral_database_removed": drill["temporary_database_removed"]})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=PROJECT)
    parser.add_argument("--show-token", action="store_true", help="Display login token in your private terminal")
    parser.add_argument("--skip-restore", action="store_true", help="Run stack acceptance without recovery drill")
    args = parser.parse_args()
    if args.show_token:
        print(show_token(args.project))
        return
    try:
        print(json.dumps(deploy(args.project, do_restore=not args.skip_restore), indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        # Avoid exposing raw Docker output, environment values or tokens.
        print(json.dumps({"status": "DEPLOYMENT_BLOCKED", "reason": str(exc)}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
