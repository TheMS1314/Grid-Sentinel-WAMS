# Grid Sentinel Phase 31 — guarded, versioned database migration baseline

Date: 2026-10-26. **Engineering improvement; not an independent attack-detection result or a live PostgreSQL deployment certificate.** No research paper.

## Why

Previously FastAPI called SQLAlchemy `create_all()` during startup. That is useful for a prototype but has no versioned schema history and can mask incomplete database upgrades. The private Docker backend now runs a guarded Alembic baseline upgrade before accepting requests. The application itself no longer silently creates schema tables.

## Implemented

- `backend/alembic.ini`, `backend/migrations/env.py` and `versions/0001_existing_schema.py` establish migration version `0001_grid_baseline`.
- For a **fresh empty database**, the revision creates the two ORM tables (`analysis_runs`, `findings`) plus indexes and the Alembic version marker.
- For a **legacy pre-Alembic database**, the revision checks that both tables have the expected columns, required indexes and the `findings.analysis_id` foreign key before versioning it; it neither drops nor rewrites existing analysis rows.
- For a partial or drifted schema, the migration raises an error and prevents the backend process from starting. This is intentional fail-closed behavior, not automatic schema repair.
- Schema downgrades are deliberately unsupported, because dropping data or tables without a targeted backup and recovery plan would be destructive.
- The backend Dockerfile now includes migration files and runs `alembic upgrade head` before starting Uvicorn. Versioned startup runs before its readiness health check. Database credentials remain in the Compose environment, not in `alembic.ini`.
- `backend/requirements.txt` now includes Alembic. Programmatic configuration can supply a database connection for isolated tests.

## Verified

Five migration tests on disposable SQLite databases cover fresh creation, legacy-row preservation, rejection of partial schemas, rejection of unexpected columns, and rejection of missing indexes. The combined migration plus API suite passes **17/17**. The tests do **not** prove actual PostgreSQL Docker startup or a production database upgrade. The earlier four backup/smoke-check tests passed using mocks; they do not prove backup recoverability.

## Operator checklist before any real upgrade

1. Keep the Compose frontend bound to `127.0.0.1` and the PostgreSQL service unexposed.
2. Create and safeguard a verified database backup with `python scripts/backup_db.py` while the existing stack still operates.
3. Test recovery separately on an isolated database before trusting a backup.
4. Only then rebuild and start the backend. Its migration must report success before accepting requests.
5. On a schema mismatch, stop and inspect the database and migration logs; **do not** manually stamp the version or drop tables to bypass validation.
6. Backups, migrations, authentication and on-site reliability need to be verified in a real Docker/PostgreSQL environment before labeling deployment complete.

## Reproduce on a disposable development database

```bash
cd smartgrid_platform
python -m venv .venv
.venv/bin/pip install -r backend/requirements-test.txt
PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/test_migrations.py backend/tests/test_api.py
```

Reference: [Alembic official migration tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html) and [Alembic cookbook — existing schema baseline](https://alembic.sqlalchemy.org/en/latest/cookbook.html).
