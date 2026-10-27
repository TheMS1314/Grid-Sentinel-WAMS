# Grid Sentinel WAMS — 6-minute faculty live demo

Audience: faculty project review. **Research prototype**, no live-grid control.

## Before you present (2 minutes)

1. Open the same private Codespace and run:
   ```bash
   cd /workspaces/Grid-Sentinel-WAMS
   git pull --ff-only
   python smartgrid_platform/scripts/codespaces_deploy.py --skip-restore
   cd smartgrid_platform
   docker compose ps
   ```
2. Verify the Ports panel shows port **8080 Private**. Never select **Make Public**.
3. Open the forwarded 8080 page, authenticate using the private token locally (do not display the token on a projector).
4. Have the dashboard, Research Evidence page, and this file ready; keep screenshots as backup.

## Live flow (6 minutes)

| Time | Screen/action | Core message |
|---|---|---|
| 0:00–0:40 | Overview | Cyber-physical measurement integrity and review-only decisions |
| 0:40–1:55 | Analysis lab → Load synthetic demo → Run integrity analysis | Frozen three-phase consistency model; review signals ≠ verified cyberattacks |
| 1:55–2:40 | Analysis history → saved run | PostgreSQL persistence and auditability |
| 2:40–4:30 | Research Evidence | Offline S1–S4 four-lane research benchmark and its limitations |
| 4:30–5:20 | System & model | React frontend, FastAPI API, PostgreSQL, private Docker containers |
| 5:20–6:00 | Terminal `docker compose ps` and conclusion | Operational prototype, CI and restart verification |

## Research evidence — precise, defensible wording

- Historical four-lane **offline/replayed** S1–S4 capture-level metrics have a retrospective macro F1 near **98.94%**, with scenario variability. They are **not** the deployed meter engine's accuracy or a prospective false-alarm guarantee.
- Independent Phase 68 power-system simulation: frozen TCP rule reviewed **10/15 nonempty minutes**; **no onset labels**—do not claim 10 true positives or F1.
- Independent Phase 69 GOOSE experiment: zero TCP reviews on two benign captures **and** zero on two GOOSE attack captures. This highlights scope, **not** universal attack detection.
- Deployed service: fixed meter-integrity review based on three-phase consistency; complementary TCP/ARP/Modbus/price lanes remain research evaluations, not fully deployed attack attribution.
- Main limitations: unsupported attack families; dataset viewpoint shifts; independent labeled event timing and long benign-field monitoring still pending.

## Short explanation to say aloud

> Grid Sentinel WAMS is a privately deployed cyber-physical monitoring prototype. The operational dashboard checks measurement consistency, retains findings and marks ambiguous records for review. Separately, our offline research evaluates complementary communication signals under several attack scenarios. We report both strong retrospective findings and cases that the current detector cannot cover. The next scientific milestone is blinded validation on new site data.

## Questions faculty may ask

**Why are S1/S2 meter-only results weaker than S4?** Modbus manipulation and MITM affect different observables; consistency-only physics may not distinguish legitimate process changes from well-formed malicious commands. The four-lane retrospective result adds protocol/identity context, but is not the deployed model.

**Is 98.94% the real-time accuracy?** No. It is retrospective fusion performance under benchmark labeling and sensor assumptions. The real-time dashboard is a separate frozen meter-consistency service.

**Can it detect all cyberattacks?** No. GOOSE message manipulation, for example, is out of scope for the frozen TCP-scanning rule. Missing coverage is reported as abstention/miss rather than hidden.

**Are deployment and storage tested?** Yes: private Codespaces deployment, PostgreSQL backup/isolated restore, container restart and full same-Codespace stop/reopen saved-analysis checks passed. Host deletion/new-host recovery and live-grid field reliability are not established.

**What about privacy/security?** Local loopback port 8080, authenticated private GitHub forwarding, app access token, no automatic grid-control commands. The Codespace is not a hardened public production service.

## Finish

> We have delivered a functioning, reproducible research platform and documented both its strengths and boundary conditions. We are prioritizing trustworthy real-world validation over inflated metrics.

Do not show raw private tokens or make port 8080 public. No paper is included.
