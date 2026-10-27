# Smart Grid Co-Pilot — Phase 20: Frozen Model and Local Read-Only Deployment Package

25 October 2026. The user requested 100% *deployed model* completion. We advanced the research classifier into a reproducible **local HTTP inference package**, but this is **not publicly deployed** and **not production-validated**. No paper written.

## Concrete delivered deployment work

1. **Immutable calibration bundle:** exported `smartgrid_meter_integrity_model.json` from Data4Cyber v3 `S0_benign_baseline` first 1,078 chronological rows (fit), next 360 rows (threshold), held out last 360. Bundle includes 15 strict local phase-total feature names, robust center/scale, threshold **359.4183**, input schema, causal persistence and SHA-256 of source S0 CSV. No active attack labels were fitted. This is the narrowly capable Phase 17 physics integrity head, *not* a universal smart-grid IDS.
2. **Self-contained inference service:** `smartgrid_research_service.py` uses only Python standard library for actual service. It serves `GET /health`, `GET /ready`, and `POST /v1/assess` JSON on **127.0.0.1:8765** by default. Validation constrains requests to max 2 MiB and 1–1000 1-Hz observations, requires timezone-aware strictly increasing timestamps, resets confirmation after >1.5-second gaps, rejects bad and nonfinite values, and abstains on missing required meter fields.
3. **Research-only result policy:** `LOCAL_PHYSICS_REVIEW` is a sustained within-meter power identity disagreement, not proof of cyberattack or malicious device identity. Output includes `ABSTAIN`, `NO_CONFIRMED_LOCAL_MISMATCH`, causal count and the deviating measurement-identity name. The service has no write/control interface, no self-training, no packet injection, no grid connection and no autonomous action.
4. **Six passing integration/unit tests:** training-boundary and bundle validation, clean reference parity, attack fixture alert generation, missingness abstention, non-monotonic timestamp rejection, bounded batch validation, and **actual in-process loopback HTTP requests** for `/health`, `/ready` and `/v1/assess`. The Python unittest suite has six passing test methods, some with multiple assertions.
5. **Restricted container recipe:** `Dockerfile.smartgrid-research` runs as non-root, health-checks locally, and `compose.smartgrid-research.yaml` publishes only `127.0.0.1:8765` on host, with dropped capabilities, no-new-privileges, read-only filesystem and CPU/memory limits. The service refuses a `0.0.0.0` bind except when explicitly opted into container networking. **Docker was not installed in the execution environment, so container image construction was not executed.**

## Verified local smoke and heldout measurement behavior

- The in-process HTTP test returned 200 for health, readiness and inference endpoints.
- All **6** unittest methods passed.
- On the Data4Cyber v3 heldout S0 last-360-second fixture, the service reported **4 LOCAL_PHYSICS_REVIEW rows**, **0 abstentions**, and 356 non-confirmed rows. This agrees with the exploratory offline Phase 17 model and reminds us that **even the local model has false-positive readings**.
- On the last 360 S4 attack-scenario rows, service scored **358 review rows**, **0 abstentions**, and 2 non-confirmed rows. Those scenario folder/time labels are not used by the live API; this is a direct heldout-inference smoke test on previously examined source data, not an independent blind validation.

## What is still NOT done

| Criterion | Status | Why |
|---|---|---|
| Frozen model with traceable calibration | **PASS** | JSON bundle and provenance hash generated |
| Local API endpoint and smoke tests | **PASS** | Loopback HTTP verified in a single process |
| Input validation, refusal, and abstention | **PASS** | Unit tests and finite-value guards |
| Docker container image built | **NOT VERIFIED** | Docker not installed in available environment |
| Internet-accessible deployment to intended server | **NOT DEPLOYED** | No hosting target, account or credential provided |
| Authenticated API, TLS, secrets rotation | **NOT BUILT** | Safe local demo only; public binding prohibited |
| Long-lived monitoring/alerting/rollback infrastructure | **NOT INTEGRATED** | No deployment control plane specified |
| Independent real-grid cybersecurity validation | **FAILED / PENDING** | Low Modbus/MQTT coverage, insufficient blind MITM and false-alarm evaluation, no verified protected anchor |
| Operational equipment authorization | **NOT REQUESTED OR GRANTED** | Deliberately no SCADA/control connectivity |

## Deployment policy and necessary next authority

To reach a *specific real hosted deployment*, the user must identify the target (e.g. an owned Linux VM, Kubernetes cluster or other approved container host), desired access policy (private VPC vs public authenticated API), operator/security requirements and acceptable pilot dataset. It is not permissible to infer that local proof-of-concept deployment equals 100% public or grid production deployment. We should then add the selected host's authentication, secrets, TLS, monitoring, rollback and live health checks within its security boundary.

To reach **100% operational cyber-detection validation**, new independently labeled multi-site real-attack/clean data and verified physical provenance are also needed, as detailed in Phases 18–19. Hosting an experimental model cannot cure these scientific limitations.

## Reproduce

With the code ZIP expanded, `smartgrid_meter_integrity_model.json` available, and Python 3.12:

```bash
python3 -B smartgrid_research_service.py
python3 -B -m unittest -v test_smartgrid_research_service
```

For optional Docker host (where installed):

```bash
docker compose -f compose.smartgrid-research.yaml build
docker compose -f compose.smartgrid-research.yaml up -d
docker compose -f compose.smartgrid-research.yaml ps
```

The tests use public Data4Cyber CSV fixtures via `Data4Cyber_v3_2026.zip`, plus pandas/numpy/scikit-learn for reference calculations. **Serving the frozen model** requires only Python stdlib and the JSON file. Third-party raw datasets are not included in the deployment archive. This is a fully packaged and locally tested research demo, **not a 100% completed real-world deployment**.
