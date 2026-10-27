# Phase 43 — offline private Docker deployment preflight

## Implementation

Added `smartgrid_platform/scripts/deployment_preflight.py` and `smartgrid_platform/requirements-preflight.txt` (PyYAML 6.x). The checker only reads local files; it performs no Docker or network calls, creates no containers, and prints no database password values. It must be run *after* the user creates a local private `.env` from `.env.example`. That `.env` is excluded from this release, intentionally.

From `smartgrid_platform/` on the intended user's Windows PC/server:

```powershell
python -m pip install -r requirements-preflight.txt
Copy-Item .env.example .env
notepad .env
python scripts/deployment_preflight.py
```

The user must replace the password placeholder with a unique, secret 20+ character string before running. A pass states `STATIC_PREFLIGHT_PASS_NOT_DEPLOYED`. A failure sets exit code 2 and explains the configuration fault without echoing secrets.

## Checked invariants

- Exactly `db`, `backend`, `frontend` services; same declared private bridge network.
- Only frontend port `127.0.0.1:8080:80`; backend and PostgreSQL publish no host port.
- Frontend/backend capability drop, no-new-privileges, backend read-only filesystem.
- All three healthchecks, whether declared in Compose or the corresponding Dockerfile.
- PostgreSQL 17 image and named volume; startup health dependencies.
- Frozen meter-model path and required Docker/build/migration files.
- Explicit required database password placeholders in Compose and strong nonplaceholder local `.env`.

## Verification and limits

Synthetic regression tests deliberately inject a public dashboard binding, exposed PostgreSQL port, extra Compose service, missing `.env`, and placeholder password; these must fail. A complete known-good fixture must pass. These are local security/configuration assertions **only**. The current environment lacks Docker; no real image build, PostgreSQL migration against a live container, browser smoke, real backup restoration, performance/latency/SLA validation or multi-user authentication was performed.

**Do not** count a static preflight pass as deployed model completion, grid-readiness or 90% scientific acceptance. The research four-lane model remains offline; the served backend remains the frozen narrow meter detector. No new independent accuracy evidence is created in this phase.
