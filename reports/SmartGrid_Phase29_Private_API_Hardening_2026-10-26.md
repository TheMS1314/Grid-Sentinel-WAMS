# Grid Sentinel Phase 29 — private API boundary hardening

Date: 2026-10-26. **This is defensive software engineering, not a change to the detector or a new model-accuracy result.** No research paper.

## Scope

Audited the React/FastAPI/PostgreSQL private Docker design and added low-risk safeguards to the saved-analysis API. The existing Compose file binds only the Nginx frontend to `127.0.0.1:8080`, keeps PostgreSQL unpublished, uses a private network, drops backend capabilities and privileges, and restricts the backend container to a read-only filesystem. The standalone detector also has its own request-size limit. We did not claim a live Docker deployment: the validation environment has no Docker executable.

## Implemented

1. **Bounded measurement dictionaries.** API requests still accept up to 1,000 rows, but each observation now admits at most 96 measurement fields and field names of 1–128 characters. The current detector uses 60 model inputs. Prevents arbitrarily wide telemetry dictionaries in accepted objects; does not substitute for proxy/body-size limits.
2. **Strict bad-value rejection.** Non-finite `NaN` or infinity measurement inputs are rejected by validation instead of silently flowing into analysis. Missing values (`null`) remain allowed so the detector can abstain appropriately.
3. **Source-name validation.** Whitespace-only source names are rejected and valid names trimmed prior to persistence.
4. **No-store response policy.** API responses now include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY`. Implemented through a minimal ASGI response-start hook without reading or buffering request bodies.
5. **Reduced production endpoint exposure.** FastAPI Swagger docs, ReDoc, and OpenAPI JSON endpoints are disabled by default on the private research service.
6. **Reverse-proxy policy.** Nginx adds a self-origin Content Security Policy for scripts and API connections, disables object embedding and third-party framing, and sets explicit `no-store` and protective headers on `/api/`. It allows inline CSS because existing React components use inline `style` attributes; script inline execution stays blocked. The existing 2 MB `client_max_body_size` is retained.
7. **Repeatable backend tests.** Added `backend/requirements-test.txt` for pytest and the current Starlette `httpx2` client, and expanded API tests to verify size limits, blank metadata rejection, security headers, and disabled docs.

## Verification completed

The 12 FastAPI API tests passed after the final ASGI header hook was adopted. The previous middleware-style hook was rejected after causing test hangs; it is not in the release. The React production build was previously verified in Phase 28; this phase changes no frontend TypeScript source. Four Phase 28 uncertainty unit tests passed. The ZIP packager self-tests CRC integrity and checks for accidental inclusion of `.env`, virtual environments, and `node_modules`.

## Remaining limitations and critical instructions

- **No user authentication or authorization:** this software is designed for one trusted operator on a private localhost-bound deployment. Do not publish port 8080 to the internet, configure an external reverse proxy, or grant untrusted users access without an explicitly engineered and tested authentication/authorization layer.
- Nginx's 2 MB body limit is the primary deployed byte-size gate. The direct internal FastAPI endpoint is not intended to be exposed; the Pydantic limits constrain accepted objects but FastAPI still parses a request body before validation.
- Database schema is created on startup; it lacks a production migration workflow, backups, and a long-term data-retention policy.
- Security headers and CSP were code-reviewed and API-tested, but cannot be verified through a live Nginx or Docker instance in this environment.
- None of the research-only alerts authenticate an attacker, provide a validated full AC state estimate, or authorize automatic grid control.

## Reproduce

```bash
cd smartgrid_platform
python -m venv .venv
.venv/bin/pip install -r backend/requirements-test.txt
PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/test_api.py
cd frontend
npm ci
npm run build
```

For deployment on your own PC, follow `smartgrid_platform/README.md`, provide a strong `POSTGRES_PASSWORD` in a private `.env`, and keep Compose's frontend localhost port mapping unchanged. Validate image builds and browser behavior locally before treating the deployment as complete.
