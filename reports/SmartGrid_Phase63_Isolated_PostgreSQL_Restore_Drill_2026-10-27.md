# Phase 63 — Isolated PostgreSQL restore rehearsal

## Verified implementation

Added `smartgrid_platform/scripts/restore_drill.py` with a read-only-by-default interface. It verifies an independently recorded SHA-256 digest and PGDMP signature before attempting a restore. Only `--execute` permits database mutation, and it targets a randomly named temporary database matching `grid_restore_drill_[0-9a-f]{16}`. The script restores via `pg_restore --single-transaction --exit-on-error`, checks SQL row counts in `analysis_runs` and `findings`, and drops only the database that this invocation successfully created.

The six new mocked operation tests cover the non-mutating default, successful workflow and cleanup, refused bad digest, refused unsafe database name, failed creation with no drop, and failed restore with test-database cleanup. They do **not** prove a real PostgreSQL image starts or restores on the user's machine.

## Interpretation and limits

- The private production `smartgrid` database is never selected for restore, dropped or renamed by this script.
- The script deliberately requires a running Docker Compose stack and operator invocation with `--execute`.
- If the script or host is interrupted between temporary database creation and cleanup, that test database may remain and requires manual investigation. Cleanup failure is reported, not hidden.
- A successful drill verifies that the backup is restorable and two expected tables can be queried; it is **not** an audited complete business-recovery plan, a measured recovery-time objective, or a field-validation result.
- There was no installed Docker runtime or private PostgreSQL volume in the research execution environment. No live restore was performed, and readiness remains **89/100** until on-host acceptance evidence is available.

## On the user's private Docker host

From `smartgrid_platform`, with the stack already healthy:

```powershell
python scripts/backup_db.py
python scripts/restore_drill.py --backup backups/NAME.dump --sha256 PREVIOUSLY_SAVED_SHA256
python scripts/restore_drill.py --backup backups/NAME.dump --sha256 PREVIOUSLY_SAVED_SHA256 --execute
python scripts/deployment_acceptance.py --live
```

Store backup files and independently recorded hashes privately. No research paper was produced.
