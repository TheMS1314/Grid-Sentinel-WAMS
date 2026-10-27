# Phase 64 — GitHub Codespaces automated deployment

Grid Sentinel now has a repository-root `.devcontainer/devcontainer.json`, using a Python 3.12 development container with the official Docker-in-Docker feature and private Codespaces port 8080 forwarding. The host's `smartgrid_platform/compose.yaml` continues to map only loopback 8080 and gives no published ports to the API or database.

`smartgrid_platform/scripts/codespaces_deploy.py` is a Codespaces-only launcher with an idempotent secret generator, strict static preflight, detached Docker Compose build/health wait, read-only live API/database acceptance, non-overwriting custom-format PostgreSQL backup, and an explicit isolated restore validation. A `--skip-restore` option permits a faster live-only check. An explicit `--show-token` option displays the login token only in the private operator terminal.

The script refuses to overwrite `.env`, rejects a symlink at that path, and does not emit Docker stderr or credentials on errors. `.env`, `backups/`, and `.local/` are gitignored. The `CODESPACES_START_HERE.md` guide walks the user through creating a private repository, creating a Codespace, running one command, verifying port visibility is **Private**, and logging in.

**Verification scope:** isolated mock tests validate command sequence, generated secret behavior, rollback boundaries, preflight failure, unhealthy service refusal, and no-Docker-unless-Codespaces. A real Codespace with Docker and PostgreSQL was not accessible from the research environment. No claim of live deployment, 100% security, or independent detection accuracy is made. The previous 89/100 readiness estimate remains until actual host deployment and site-grounded validation.
