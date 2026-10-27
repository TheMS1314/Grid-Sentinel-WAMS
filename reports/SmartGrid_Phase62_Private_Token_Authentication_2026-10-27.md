# Phase 62 — Private React login and fail-closed FastAPI access control

## Engineering outcome

The previous Docker release was restricted to `127.0.0.1` but lacked user authentication; any local browser/process with network access to the port could read research history and submit analyses. Phase 62 implements a **single private-workspace bearer-token gate**. The token is configured in `smartgrid_platform/.env` on the operator's own PC, never included in the distribution ZIP or JavaScript bundle.

- Docker Compose requires `GRID_SENTINEL_ACCESS_TOKEN` and explicitly enforces `GRID_SENTINEL_AUTH_REQUIRED=1`. The offline deployment preflight rejects a missing/placeholder/weak-length token, a secret equal to the PostgreSQL password, or disabled Compose authentication.
- FastAPI requires a matching `Authorization: Bearer ...` value for every `/api/*` route **except** `/api/health` and `/api/ready`, used by container readiness probes. Missing credentials yield `401` with bearer challenge; a required but missing server secret yields `503`. A direct API launch requires auth by default, with `GRID_SENTINEL_AUTH_REQUIRED=0` available solely as an explicit test/development opt-out.
- Authorization uses constant-time `hmac.compare_digest`. Rejected requests receive the existing private no-store response header behavior. The backend does not save the access token in PostgreSQL.
- React shows a login screen before loading private data, submits the token through an authenticated read-only `/api/model` request, retains the entered token **only in the current tab's JS memory**, and provides an explicit sign-out control. Page reload and sign-out require re-entry. The token is not persisted in localStorage or cookies and is not sent in a URL.
- The local smoke check reads the token from the private `.env` without exposing it in command-line arguments and sends it only on the protected endpoints. A static-only or unavailable Docker host still cannot be represented as live-deployed.

## Threat boundaries

This is meaningful localhost access control but **not** a production identity platform. There is no TLS, individual accounts, MFA, fine-grained authorization, brute-force rate limit, secret rotation workflow, external identity provider, or security penetration test. A malicious browser extension/XSS operating in the same tab could access JS memory. Loopback binding remains mandatory, and operational grid connectivity remains prohibited. The two unauthenticated readiness endpoints are intentionally minimal and must not be mistaken for protected data interfaces.

## Verification and host handoff

The backend API tests include missing/wrong/correct bearer, `401` no-store, health probes, and missing-key fail-closed conditions. Operations tests cover private preflight secret rules, legacy protection regression and authenticated smoke headers. The React production build compiles the new login. No Docker binary, actual PostgreSQL deployment, restore drill, or real-site blind validation is available in this research environment. The code changes therefore **close a known application security gap** without establishing live production deployment or independent field accuracy.

On Windows, generate an independent random token with `python -c "import secrets; print(secrets.token_urlsafe(48))"` and put it in your private `.env`, alongside a different strong `POSTGRES_PASSWORD`. Run preflight, `docker compose up --build -d`, and `python scripts/deployment_acceptance.py --live` as described in `smartgrid_platform/README.md`. The React login then prompts for the same token.

**No research paper was written.** A subjective overall readiness estimate may improve marginally based on tested authentication code, but actual Compose deployment and prospective site evaluation remain explicit acceptance blockers.
