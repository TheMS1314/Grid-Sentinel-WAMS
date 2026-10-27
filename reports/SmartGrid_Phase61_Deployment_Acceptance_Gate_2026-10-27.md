# Phase 61 — One-command private Docker deployment acceptance

## Outcome

Previous handoffs had a working React/Vite build, FastAPI unit/integration tests on SQLite, PostgreSQL/Alembic definitions, a loopback-only three-container Compose file and isolated preflight/smoke/backup tools. They **did not offer a single strict verification entrypoint** for an operator's real private host. Phase 61 adds `smartgrid_platform/scripts/deployment_acceptance.py` and adversarial fixture tests.

Run on your **own** Windows PC after extracting the source ZIP, installing Docker Desktop and setting an unshared `.env` password:

```powershell
cd smartgrid_platform
python -m pip install -r requirements-preflight.txt
Copy-Item .env.example .env
notepad .env
python scripts/deployment_acceptance.py
docker compose up --build -d
docker compose ps
python scripts/deployment_acceptance.py --live
python scripts/backup_db.py
```

Never share `.env`, Docker credentials, or backups. A local `.env` must be created and edited **on the intended host**; it is intentionally absent from this ZIP. Backups contain private data; separately record their digest and rehearse recovery before operational approval.

## Gate definitions

| Gate | Condition | Reported status |
|---|---|---|
| Static Compose review | Three reviewed services, loopback-only ingress, no exposed backend/DB, network/health/capability/read-only controls, no placeholder DB secret, required files | `STATIC_ONLY_NOT_DEPLOYED` (success for static mode) |
| Live Compose health | Exactly `db`, `backend`, `frontend` running and reporting healthy | Required for live pass |
| Live API/DB/model | Redirect-rejecting loopback GET health, DB readiness, frozen model status, ARP research caveat | Required for live pass |
| Live read-only acceptance | Every gate passes | `LIVE_STACK_READ_ONLY_ACCEPTANCE_PASS` |
| Offline/host unavailable/failed | Missing `.env`, unavailable Docker or daemon, unhealthy services, failed API checks | `BLOCKED` or `LIVE_VALIDATION_BLOCKED` |

The script **never starts/stops/upgrades services, creates analysis data, mutates PostgreSQL, connects to grid devices, or performs a restore**. It does not claim real traffic fitness or authentication for public access.

## Test evidence and remaining external actions

The new acceptance tests validate JSON and JSONL Compose parsing, duplicate/missing services, fail-closed unreported health, offline no-Docker behavior, healthy mocks, CLI failure, unhealthy services and missing `.env`. Existing backend/API, operations and React build regressions are rerun for the release. The environment providing this artifact **has no Docker binary** or user-host secrets. Running `--live` here correctly returns `BLOCKED` because `.env` does not exist; **there is no measured live Compose/PostgreSQL pass**. Restore rehearsal, reboot persistence, actual target-PC firewall and independent site detection testing are still required. Project-wide readiness remains an estimate of **88/100**; an offline acceptance tool alone does not raise it.

The deployment guide was corrected: `scripts/smoke_check.py` is the real smoke path, production `/docs` is disabled, and guarded Alembic migrations—not unversioned table recreation—apply at container startup. No paper was written.
