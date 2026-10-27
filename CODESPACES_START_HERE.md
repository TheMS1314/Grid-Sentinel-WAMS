# Grid Sentinel — GitHub Codespaces quick start

This is a private research deployment for a personal GitHub Codespace, **not** a public or continuously available production OT service. You do **not** need Docker Desktop on the friend's Windows PC.

## First-time GitHub setup

1. On **your own GitHub account**, create a **private** repository (e.g., `grid-sentinel-private`). Upload the **contents inside** the ZIP's `GridSentinel_Phase64_2026-10-27/` folder to the **repository root**, so `.devcontainer/devcontainer.json` is at the root next to `smartgrid_platform/`.
2. In your private GitHub repository select **Code → Codespaces → Create codespace on main**. Wait for the development container to finish. The development container installs the Docker-in-Docker feature and the minimal offline preflight dependency.
3. In the Codespaces terminal, run **one command** from the repository root:

   ```bash
   python smartgrid_platform/scripts/codespaces_deploy.py
   ```

   It generates a private `.env` file on first use, validates the config, starts React+FastAPI+PostgreSQL with Docker Compose, waits for healthy containers, runs authenticated read-only acceptance, makes a new private PostgreSQL backup and tests restoring it into a disposable database. Backup files and `.env` are ignored by git. It **does not** replace existing credentials or automatically change any GitHub port-visibility setting.

4. Open the Codespaces **Ports** tab. Verify that **8080 is marked Private** (never Public or Organization). Select its forwarded URL. Codespaces requires the owner's GitHub authentication for a private forwarded port. If the port is not private, change the visibility back to **Private before accessing the dashboard**.
5. In your private Codespaces terminal, reveal the app login token when needed:

   ```bash
   python smartgrid_platform/scripts/codespaces_deploy.py --show-token
   ```

   Copy the token into the React login screen. Do **not** paste it into a chat, GitHub Issue, terminal screenshot, or repository. The browser login keeps it in tab memory only.

## Every later session

Codespaces may be stopped automatically. Start the Codespace again, then run the same deployment command. The existing `.env` is reused if present. Each successful run creates a **new, non-overwriting** backup and performs a fresh isolated restore drill. For fast startup without a backup/restore rehearsal:

```bash
python smartgrid_platform/scripts/codespaces_deploy.py --skip-restore
```

The script does not make ports public, remove databases, delete existing backups, rotate credentials, or stop other running applications. The test database is removed after the restore drill. If the Codespace is deleted, its attached storage (including the database and backups) can be lost. Export private backup files to a secure location you control if you need long-term retention.

## Security and acceptance limitations

- Codespaces private port forwarding authenticates **your GitHub account**; the app separately requires its private token. Keep the repo and forwarded port private.
- This app uses **HTTP inside the Codespace** behind the authenticated Codespaces proxy, without custom application TLS termination; it is not suitable for direct public hosting.
- PostgreSQL and FastAPI have **no host-published ports**; the dashboard maps only loopback `127.0.0.1:8080` inside the Codespace.
- The launcher is restricted to an environment containing `CODESPACES`. If the Docker daemon or account quota is unavailable, it reports an error instead of claiming success.
- The model stays research-only. Codespaces is not an independent smart-grid site or an accuracy certification.
- No research paper is included.

## If something fails

In your private terminal, from `smartgrid_platform/` run `docker compose ps` and `docker compose logs --tail=80 backend`; **inspect logs privately** and redact secrets before sharing snippets. The automated launcher intentionally never prints raw Docker logs or private credentials.

Optional read-only acceptance from `smartgrid_platform/`:

```bash
python scripts/deployment_acceptance.py --live
```

GitHub references: [Codespaces private forwarded ports](https://docs.github.com/en/codespaces/reference/security-in-github-codespaces), [Codespaces forwarding controls](https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace), [development-container Docker-in-Docker feature](https://github.com/devcontainers/features/tree/main/src/docker-in-docker).

## Saved-analysis durability verification (Phase 65)

Once the Analysis lab has created at least one recorded run, use these commands from `smartgrid_platform/`:

```bash
python scripts/persistence_acceptance.py
python scripts/persistence_acceptance.py --execute
```

The first command only reads the authenticated local API and fingerprints the latest saved run and aggregate totals. The explicit `--execute` command **temporarily restarts PostgreSQL** (`docker compose restart db`), waits up to 120 seconds for the authenticated API to recover, and verifies the same saved run and aggregate counts remain. It does not delete data, modify saved analyses, or recreate the Compose volume. The dashboard may be temporarily unavailable during the restart. It is a single-container recovery check, not a full host-disaster or Codespaces deletion test. Keep the Codespaces port private.
