"""Grid Sentinel private-host deployment acceptance; no database mutations.

Usage:
  python scripts/deployment_acceptance.py             # static only
  python scripts/deployment_acceptance.py --live      # Docker + API checks

Never launches, stops, reconfigures, upgrades, or restores a service. The live
mode requires an operator-controlled localhost Compose stack already running.
"""
import argparse
import json
import shutil
import subprocess
from pathlib import Path

try:
    from scripts.deployment_preflight import inspect_project
    from scripts.smoke_check import verify
except ModuleNotFoundError:
    from deployment_preflight import inspect_project
    from smoke_check import verify


PROJECT = Path(__file__).resolve().parents[1]
EXPECTED = {"db", "backend", "frontend"}


def parse_compose_ps(output):
    """Accept both Docker Compose JSON-array and JSONL command output."""
    text = output.strip()
    if not text:
        raise ValueError("Docker Compose returned no service status")
    try:
        decoded = json.loads(text)
        rows = decoded if isinstance(decoded, list) else [decoded]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Unexpected Compose service status")
    by_name = {}
    for row in rows:
        name = row.get("Service")
        if not isinstance(name, str) or not name:
            raise ValueError("Compose status lacks service identity")
        if name in by_name:
            raise ValueError("Ambiguous duplicate Compose service status")
        by_name[name] = row
    if set(by_name) != EXPECTED:
        raise ValueError("Unexpected or missing Compose service(s)")
    return by_name


def evaluate_compose(rows):
    """Fail closed when health data is missing, pending or unhealthy."""
    errors, services = [], {}
    for name in sorted(EXPECTED):
        row = rows[name]
        state = row.get("State", "")
        health = row.get("Health", "")
        services[name] = {"state": state, "health": health}
        if state != "running":
            errors.append(f"{name} is not running")
        if health != "healthy":
            errors.append(f"{name} health is not confirmed healthy")
    return errors, services


def accept(project=PROJECT, live=False, docker_path=None, runner=subprocess.run, smoke=verify):
    project = Path(project).resolve()
    static = inspect_project(project)
    result = {"status": "BLOCKED" if static["errors"] else
              ("LIVE_VALIDATION_BLOCKED" if live else "STATIC_ONLY_NOT_DEPLOYED"),
              "static": {"status": static["status"], "checks": static["checks"],
                         "errors": static["errors"], "warnings": static["warnings"]},
              "live_requested": bool(live), "live": {"checks": [], "errors": []},
              "limitations": ["No real-grid devices used", "No PostgreSQL restore/reboot drill performed",
                              "No authentication or independent field-accuracy certification"]}
    if static["errors"] or not live:
        return result
    docker = docker_path if docker_path is not None else shutil.which("docker")
    if not docker:
        result["live"]["errors"].append("Docker CLI unavailable on this machine")
        return result
    try:
        check = runner([docker, "compose", "ps", "--format", "json"], cwd=project,
                       text=True, capture_output=True, check=False, timeout=30)
        if check.returncode != 0:
            raise RuntimeError("Docker Compose service listing failed")
        states = parse_compose_ps(check.stdout)
        errors, summary = evaluate_compose(states)
        result["live"]["services"] = summary
        if errors:
            result["live"]["errors"].extend(errors)
            return result
        result["live"]["checks"].append("All three Compose services report running and healthy")
        # Loopback-only, read-only GETs; smoke refuses HTTP redirects.
        smoke_results = smoke("http://127.0.0.1:8080")
        if smoke_results.get("status") != "LOCAL_SMOKE_PASS":
            raise RuntimeError("API smoke did not report success")
        result["live"]["checks"].append("Local API health, PostgreSQL readiness, model and ARP research warnings passed")
        result["status"] = "LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        # Avoid leaking subprocess stderr, which may contain a machine's
        # sensitive Docker environment or project paths.
        result["live"]["errors"].append("Deployment verification failed or timed out")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=PROJECT)
    parser.add_argument("--live", action="store_true", help="Inspect an already-running private Docker stack")
    args = parser.parse_args()
    result = accept(args.project, args.live)
    print(json.dumps(result, indent=2))
    if result["status"] not in ({"LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS"} if args.live else {"STATIC_ONLY_NOT_DEPLOYED"}):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
