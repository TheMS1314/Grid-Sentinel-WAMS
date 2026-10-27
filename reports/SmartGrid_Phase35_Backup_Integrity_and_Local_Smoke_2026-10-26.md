# Phase 35 — Offline backup checks and loopback smoke-test safety

## Delivered

1. Added `smartgrid_platform/scripts/verify_backup.py`. After a backup,
   independently retain the SHA-256 printed by `scripts/backup_db.py`. Before
   any later restore attempt, run:

   ```bash
   python scripts/verify_backup.py --backup backups/NAME.dump --sha256 SAVED_SHA256
   ```

   The tool reads the archive without modifying it, requires PostgreSQL
   custom-format `PGDMP`, checks the complete SHA-256, and rejects mismatches.
   If the PostgreSQL client utilities are installed, add
   `--pg-restore-list` to ask `pg_restore` to list the archive structure
   without writing to any database. The CLI does not contain a restore action.

2. `scripts/smoke_check.py` now disables HTTP redirects on its normal network
   path and rejects any mismatched effective response URL. This closes a
   subtle case in which an otherwise-local check might follow a redirect to
   a non-loopback service. Endpoint tests stay local and read-only.

3. Expanded operations regression coverage from four to seven tests, adding
   modified-backup rejection, `pg_restore --list` success/failure simulation,
   and redirected-response rejection.

## What the result does **not** establish

- A correct checksum detects modification **relative to a trusted, separately
  retained digest**. A digest saved beside the archive and changed with it
  offers no independent assurance.
- `pg_restore --list` verifies that the client can parse the archive's catalog,
  not that all stored contents are usable or restored data are correct.
- The backup verifier and smoke tests were executed with offline synthetic
  files and fake response callbacks. No Docker daemon, PostgreSQL service,
  live backup, isolated restore rehearsal, or target-machine deployment was
  available in this environment.
- The model's attack performance is **unchanged**; no >90% readiness or new
  detection accuracy is claimed. Qualitative overall status stays ~78/100.

## Required next evidence

On the owner's private computer, execute `docker compose up --build -d`, run
the smoke check, create a fresh backup, independently retain its SHA-256,
verify the backup archive, and **rehearse restoration into a separately
authorized disposable PostgreSQL instance**. Never restore over a production
database for a test. Cross-site prospective captures and independently
verified attack-event labels are also necessary for research acceptance.
