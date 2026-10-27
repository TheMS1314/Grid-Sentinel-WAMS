# Phase 21 — Grid Sentinel Full-Stack Implementation

**Date:** 25 October 2026  
**Scope:** Research-only private dashboard and inference API; no research paper was written.  
**Delivery:** `SmartGrid_Phase21_React_FastAPI_Postgres_Source_2026-10-25.zip`

## Outcome

Implemented a private three-service web application designed to run via Docker Compose on the user's Windows PC or a Linux server:

| Layer | Technology | Capability |
|---|---|---|
| Browser UI | React 19, TypeScript, Vite, Recharts | Responsive dashboard, measured-activity charts, analysis upload, synthetic sample, history, system transparency |
| API | Python 3.12, FastAPI, SQLAlchemy | Research-only three-phase meter identity assessment, validated inputs, OpenAPI and health/readiness routes |
| Storage | PostgreSQL 17 | Persists analysis summaries and derived review findings without retaining raw meter measurements |
| Serving | Nginx | Serves optimized React build and reverse-proxies `/api` to FastAPI |
| Orchestration | Docker Compose | Private bridge network and named database volume; publishes browser UI on localhost only |

The API uses the previously frozen 15-feature meter consistency model. Its output is an **engineering review flag, not a confirmed attack verdict**. The platform provides no grid control, mitigation actions, remote logging collectors, PLC connectivity, or automatic incident response.

## Verified in this environment

- React `npm run build`: **passed** (Vite generated production assets; a non-failing chunk-size advisory was reported).
- FastAPI endpoint tests: **5 passed** using an isolated SQLite test session. These cover API behavior, not deployed PostgreSQL integration.
- Docker Compose YAML: **parsed successfully**; assertions confirm its three services and `127.0.0.1:8080:80` port binding.
- Source includes a read-only deployment smoke checker, `deploy/smoke_test.py`, to test HTTP UI, database readiness, the model and overview after start.

## Not yet verified

- Docker images and PostgreSQL containers could not be started because Docker is unavailable in the execution environment.
- Full-stack browser interaction, actual PostgreSQL persistence, and throughput under realistic ingestion remain untested.
- Model false-alarm performance and cross-dataset transfer are **not** solved by the software implementation. The earlier independent Modbus/MQTT generalization concerns remain.
- The stack is intentionally restricted to a private localhost instance. It has no authentication, HTTPS certificate or multi-tenant roles; do not expose on a public network.

## How to run

1. Install and start Docker Desktop (Windows with WSL 2 backend), or Docker Engine with Compose on Linux.
2. Extract the ZIP and navigate into `smartgrid_platform`.
3. Copy `.env.example` to `.env`; replace the placeholder database password with a strong random value.
4. Execute `docker compose up --build -d`; inspect `docker compose ps` until healthy.
5. Open `http://127.0.0.1:8080` and run `python deploy/smoke_test.py`.
6. Upload timezone-aware CSV or JSON with 60 numeric fields per row, or load the clearly marked synthetic demo.

Use `docker compose down` to stop while retaining saved analyses. Avoid `docker compose down -v` unless intentionally removing the database volume.

## Project status

**Code implementation:** complete for the scoped prototype.  
**Automated application checks:** frontend build + 5 API tests + Compose structure passed.  
**Live target-PC deployment:** pending a Docker-capable host.  
**Production or scientific acceptance:** not claimed.

This report describes implementation and verification only; it is not a research paper.
