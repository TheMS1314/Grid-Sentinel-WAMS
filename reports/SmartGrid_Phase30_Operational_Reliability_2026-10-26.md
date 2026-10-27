# Grid Sentinel Phase 30 — operational reliability and recovery preparation

Date: 2026-10-26. **Private research deployment only; no real Docker/PostgreSQL recovery was exercised. No research paper.**

## Deliverables

1. `smartgrid_platform/scripts/backup_db.py`: creates a private PostgreSQL custom-format dump from the running Docker Compose `db` service. The command uses a fixed argv vector (no shell expansion), does not pass passwords to the host CLI, writes a temporary file with OS-restricted permissions, checks subprocess exit status and the `PGDMP` magic header, computes SHA-256, flushes to disk, and publishes using a hard link that fails if the target filename already exists. A failed attempt removes its partial temporary file. It does not change database contents or upload data elsewhere.
2. `smartgrid_platform/scripts/smoke_check.py`: reads four endpoints through the localhost-bound Nginx frontend (`/api/health`, `/api/ready`, `/api/model`, `/api/arp-research`), checking response status, `Cache-Control: no-store`, database/model readiness, and the explicit unauthenticated-research evidence status. Non-loopback URLs, credentials and URL paths are rejected. This does not submit or modify telemetry.
3. `smartgrid_platform/tests/test_operations.py`: four unit tests covering non-overwriting backup success, failure cleanup, smoke-check URL restrictions and successful mocked API responses.

## Private PC/server instructions

From the extracted `smartgrid_platform/` directory, after Docker Desktop is installed and the private stack is up with its `.env` password:

```bash
python scripts/smoke_check.py
python scripts/backup_db.py
```

The backup is written under `smartgrid_platform/backups/` with a UTC timestamp. The script fails if a backup with that exact filename exists. It prints a SHA-256 digest so the operator can verify an offline copy. Store backups in an access-controlled and preferably encrypted location, outside the active machine, using a separately approved retention policy. Do not commit backups or `.env` secrets to source control. The packager excludes backups entirely.

## Recovery safety boundary

**Restore is intentionally not automated.** Restoring a database can overwrite or destroy current analyses. Before any restore, the operator should select a specific verified backup, confirm the correct Grid Sentinel deployment, stop writes, preserve an additional recovery copy of the current database, and rehearse restoration into an isolated empty test database. Only then should an explicitly authorized, deployment-specific restore plan be executed. The script makes no claim that backups are recoverable until such a restore drill succeeds.

## Verified versus pending

- Four operations unit tests passed using a simulated pg_dump process and mocked localhost responses. This proves file-handling behavior, not that Docker or PostgreSQL are configured correctly on the user's server.
- Phase 29 FastAPI regressions (12 tests) and React production build had passed previously; no model parameters or attack scores changed in Phase 30.
- Docker CLI was unavailable, so actual container startup, live `pg_dump`/`pg_restore`, Nginx delivery, persistence after reboot, and disaster-recovery timing remain **unverified**.
- Full safety requires independent cyberattack/benign field datasets, protected device provenance, a tested authentication/authorization design if access expands beyond trusted localhost, backups with restore drills, migration management and operational false-alert budgets.
