# Grid Sentinel Phase 62 — handoff

This archive is organized as follows:

```
GridSentinel_Phase62_2026-10-27/
  smartgrid_platform/  React, FastAPI, PostgreSQL, Nginx and Docker Compose
  *.py                 Offline physics/protocol evaluations and test suites
  reports/             Phase 22 audit, earlier acceptance boundaries and JSONL metrics
  SHA256SUMS.txt        SHA-256 checksums for packaged members
```

Start with `smartgrid_platform/README.md` to run the interface on Docker Desktop. Do not expose the app publicly or connect it to operational grid devices.

The production model is a frozen, narrow **meter self-consistency** detector. The *Research evidence* page reports previous exploratory Data4Cyber tests, **not an accuracy estimate on your site's network**. This archive includes no third-party raw datasets, local Python virtual environments, node_modules, private `.env` credentials, or paper.

To rerun the research suite, obtain dataset ZIPs separately from the publishing repositories and place them beside these `.py` files (or pass the relevant paths to commands):

- `Data4Cyber_v3_2026.zip`: https://zenodo.org/records/22953576
- `COCOON_PV23_measurements.zip`, `COCOON_PV23_dummy_attacks.zip`, `COCOON_PV23_smart_attacks.zip`: https://www.cyber-cocoon.eu/datasets/
- `MITM Attack Datasets_V1.zip`: https://zenodo.org/records/8375657 (publisher MD5 `8ceb392f6a69086635159ff5bd0fff17`). Distinct external **flow-feature** benchmark; see Phase 48 report. It does **not** test the frozen Data4Cyber detector.
- `Cyber4OT.zip`: https://zenodo.org/records/15005190 (publisher MD5 `55510cbb43d8af72a69dfbcd6940daa5`). Independent **raw PCAPNG** Modbus/MAC *capture-level* pilot; see Phase 52 report. Source-IP/MAC observations are spoofable and cannot establish real-world F1.

From the extracted `GridSentinel_Phase62_2026-10-27/` directory, install the optional research dependencies (`numpy`, `pandas`, `openpyxl`, `scikit-learn`, `dpkt`), then run:

```bash
python -m unittest -v test_smartgrid_phase22_reliability
python smartgrid_phase22_reliability.py
python smartgrid_phase23_failure_attribution.py
python -m unittest -v test_data4cyber_protocol_lane
python data4cyber_modbus_allowlist_benchmark.py
python data4cyber_two_lane_benchmark.py
python data4cyber_passive_mqtt_audit.py
python -m unittest -v test_data4cyber_arp_lane
python data4cyber_passive_arp_audit.py
python data4cyber_arp_two_lane_benchmark.py
python -m unittest -v test_data4cyber_arp_policy
python data4cyber_arp_policy_sweep.py
python -m unittest -v test_data4cyber_arp_negative_control
python data4cyber_arp_negative_control.py
python -m unittest -v test_data4cyber_arp_uncertainty
python data4cyber_arp_uncertainty.py
python -m unittest -v test_arp_identity_ambiguity
python arp_identity_ambiguity.py
python -m unittest -v test_prospective_site_validation
python -m unittest -v test_data4cyber_four_lane_fusion test_data4cyber_modbus_register_audit test_data4cyber_s6_price_shift_audit
python -m unittest -v test_data4cyber_temporal_false_alerts
python -m unittest -v test_offline_four_lane_replay
python -m unittest -v test_offline_observation_ingest
python -m unittest -v test_offline_selective_validation
python -m unittest -v test_offline_blind_site_run
python -m unittest -v test_data4cyber_price_shift_stress
python -m unittest -v test_data4cyber_price_context_policy
python -m unittest -v test_offline_signed_tariff_verifier test_offline_tariff_context_bridge
python -m unittest -v test_offline_signed_tariff_integration
python -m unittest -v test_external_mitm_experiment_holdout
python external_mitm_experiment_holdout.py '/path/to/MITM Attack Datasets_V1.zip' --output reports/SmartGrid_Phase48_External_MITM_Holdout_2026-10-26.json
python -m unittest -v test_external_mitm_domain_transfer
python external_mitm_domain_transfer.py '/path/to/MITM Attack Datasets_V1.zip' --output reports/SmartGrid_Phase49_External_Domain_Transfer_2026-10-26.json
python -m unittest -v test_external_mitm_leave_domain_out
python external_mitm_leave_domain_out.py '/path/to/MITM Attack Datasets_V1.zip' --output reports/SmartGrid_Phase50_Leave_Domain_Out_2026-10-27.json
python -m unittest -v test_prospective_site_validation_v2
python prospective_site_validation_v2.py --manifest '/path/to/site_manifest_v2.json' --output '/path/to/new_evaluation_result.json'
python -m unittest -v test_cyber4ot_independent_modbus_probe
python cyber4ot_independent_modbus_probe.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase52_Cyber4OT_Passive_Modbus_2026-10-27.json
python -m unittest -v test_cyber4ot_vantage_shift_negative_control
python cyber4ot_vantage_shift_negative_control.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase53_Vantage_Shift_Negative_Control_2026-10-27.json
python -m unittest -v test_cyber4ot_full_capture_family_audit
python cyber4ot_full_capture_family_audit.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase54_Full_Cyber4OT_Audit_2026-10-27.json
python -m unittest -v test_cyber4ot_benign_calibrated_rate
python cyber4ot_benign_calibrated_rate.py reports/SmartGrid_Phase54_Full_Cyber4OT_Audit_2026-10-27.json --output reports/SmartGrid_Phase55_Benign_Only_Rate_Calibration_2026-10-27.json
python -m unittest -v test_cyber4ot_maintenance_counterfactual
python cyber4ot_maintenance_counterfactual.py reports/SmartGrid_Phase54_Full_Cyber4OT_Audit_2026-10-27.json reports/SmartGrid_Phase55_Benign_Only_Rate_Calibration_2026-10-27.json --output reports/SmartGrid_Phase56_Maintenance_Counterfactual_2026-10-27.json
python -m unittest -v test_zeroswarm_independent_pcap_validation test_zeroswarm_tcp_scan_negative_control
python zeroswarm_independent_pcap_validation.py '/path/to/ZeroSWARM Normal data_v2b.pcap' '/path/to/[Zero-SWARM] Nmap_v1.pcap' '/path/to/[Zero-SWARM] Flooding Attack_v1.pcap' --long-normal '/path/to/ZeroSWARM Normal data_v2.pcap' --output reports/SmartGrid_Phase57_ZeroSWARM_External_PCAP_2026-10-27.json
python zeroswarm_tcp_scan_negative_control.py '/path/to/ZeroSWARM Normal data_v2b.pcap' '/path/to/ZeroSWARM Normal data_v2.pcap' '/path/to/[Zero-SWARM] Nmap_v1.pcap' '/path/to/[Zero-SWARM] Flooding Attack_v1.pcap' --output reports/SmartGrid_Phase58_ZeroSWARM_TCP_Scan_Audit_2026-10-27.json
python -m unittest -v test_cyber4ot_frozen_tcp_cross_dataset
python cyber4ot_frozen_tcp_cross_dataset.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase59_Cyber4OT_Frozen_TCP_Transfer_2026-10-27.json
python -m unittest -v test_cyber4ot_arp_sweep_complement
python cyber4ot_arp_sweep_complement.py '/path/to/Cyber4OT.zip' --output reports/SmartGrid_Phase60_Cyber4OT_ARP_Sweep_2026-10-27.json
python data4cyber_modbus_register_audit.py
python data4cyber_s6_price_shift_audit.py
python data4cyber_four_lane_fusion.py
python smartgrid_research_acceptance.py
```

The Phase 28 uncertainty audit uses only the bundled Phase 27 JSONL and standard Python; no new raw capture is required for that audit. For backend API tests, install `smartgrid_platform/backend/requirements-test.txt` (including the `httpx2` test client required by current Starlette) and run the tests with `PYTHONPATH=smartgrid_platform/backend` set.

Phase 29 adds private API input limits, no-store/security headers, production API documentation lockdown and an Nginx Content Security Policy. The API is still unauthenticated and must remain restricted to localhost. See `reports/SmartGrid_Phase29_Private_API_Hardening_2026-10-26.md`.

Phase 30 adds `smartgrid_platform/scripts/backup_db.py` (non-overwriting private PostgreSQL backup) and `smartgrid_platform/scripts/smoke_check.py` (localhost read-only readiness checks). Unit test them with `cd smartgrid_platform && python -m unittest -v tests.test_operations`. They require live Docker for real deployment verification; backup restore is intentionally manual and must be authorized and rehearsed separately. See `reports/SmartGrid_Phase30_Operational_Reliability_2026-10-26.md`.

Phase 31 adds Alembic migration `0001_grid_baseline`. The Docker backend now applies this guarded baseline before serving traffic; fresh databases are initialized, compatible older databases are preserved, and partial or drifted schemas halt startup. Test with `PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/test_migrations.py backend/tests/test_api.py` from inside `smartgrid_platform/`. Always back up and rehearse restoration before a real database upgrade. See `reports/SmartGrid_Phase31_Versioned_Database_Migrations_2026-10-26.md`.

Phase 32 includes a synthetic ARP identity counterexample: benign NIC replacement and malicious impersonation can produce identical passive ARP claims, so neither persistence tuning nor automatic inventory learning can authenticate intent. This is not a new benchmark score. See `reports/SmartGrid_Phase32_ARP_Identity_Maintenance_Limit_2026-10-26.md`.

Phase 33 adds a standard-library blind-site prediction evaluator that requires fixed model/policy provenance, CSV digests, disjoint site IDs, and immutable results. Run `python prospective_site_validation.py --manifest /path/to/manifest.json` after collecting approved, independently adjudicated predictions. The included unit tests are **synthetic software tests**, not new detection results. Read `reports/SmartGrid_Phase33_Blind_Site_Validation_2026-10-26.md` before claiming external validation.

Phase 34 strengthens this evaluator by validating the bytes of `frozen_model_path` against `frozen_model_sha256`, rejecting invalid/irregular timestamps, and reporting false-alert episodes and event detection latency. The manifest now needs `frozen_model_path`. See `reports/SmartGrid_Phase34_Model_Commitment_and_Alert_Burden_2026-10-26.md`. No new empirical detection score is claimed.

Phase 35 adds read-only backup checks (`python smartgrid_platform/scripts/verify_backup.py --backup PATH --sha256 PREVIOUSLY_SAVED_HASH`, optionally with `--pg-restore-list`) and prevents the loopback smoke check from following HTTP redirects. These are safety/reliability changes, not live recovery-test evidence. See `reports/SmartGrid_Phase35_Backup_Integrity_and_Local_Smoke_2026-10-26.md`.

**Phase 36 contains the most complete four-lane research demonstration yet:** a `0.98943` macro row-F1 across the examined S1–S6 public Data4Cyber campaigns, with per-scenario false-alarm rates included. This is **post-hoc, within-dataset, not field-validated, and not deployed**. The price-domain lane is novelty detection, not authenticated MQTT provenance; IP/MAC assertions remain spoofable. A new register-address policy provided **no** incremental coverage and was rejected. The Research Evidence page exposes these historical results and limitations. Start with `reports/SmartGrid_Phase36_Four_Lane_Benchmark_2026-10-26.md` and do not claim a production accuracy guarantee.

Phase 37 systematically removes one lane at a time and counts exclusive attack coverage and exclusive false-alert rows. Modbus, ARP and price make major complementary contributions, while meter physics increases exclusive S4/S5 detection but also generates false-alert costs and does not raise the arithmetic macro F1 on these same examined campaigns. The private dashboard now includes this tradeoff table. See `reports/SmartGrid_Phase37_Lane_Ablation_and_Tradeoff_2026-10-26.md`. These are *not* new independently held-out results.

Phase 38 traces the remaining false-alert seconds relative to published attack boundaries. Across S1–S6, 53 of 69 benign-labeled false-alert seconds occurred within 30 seconds of a labeled attack row, but 16 happened farther away; S0 retains four clean-holdout alerts. **All 69 remain counted as false positives**, and no attack-label-informed suppression was added. See `reports/SmartGrid_Phase38_False_Alert_Timing_2026-10-26.md`. The Research Evidence page includes this boundary-aware diagnostic without changing the frozen deployed meter model.

Phase 39 provides `offline_four_lane_replay.py`, a safe **site-configurable but not deployed** offline replay adapter for the four research signals. It verifies precommitted policy/observation hashes, implements causal Modbus/ARP holds, records unverified review evidence and abstains explicitly when signal visibility/inventory is incomplete. It never changes inventory, reads live network traffic, or commands grid equipment. Synthetic fixtures are in `examples/`. See `reports/SmartGrid_Phase39_Frozen_Offline_Replay_Interface_2026-10-26.md`. No new empirical accuracy figure is claimed.

Phase 40 adds `offline_observation_ingest.py`, a strict offline JSONL-to-replay adapter. It requires per-lane, per-second coverage declarations, inserts missing time bins as unknown, checks an independently precommitted SHA-256 for input events and policy, rejects duplicate JSON keys and invalid event schemas, and refuses to overwrite normalized output. This is an ingestion integrity test, **not** independently sourced site data or an operational packet decoder. The script prints the normalized observation digest; pass that digest to `offline_four_lane_replay.py --observations-sha256`. See `reports/SmartGrid_Phase40_Hash_Frozen_Offline_Event_Ingestion_2026-10-26.md`.

Phase 41 adds `offline_selective_validation.py`, which joins precommitted Phase 39/40 replay predictions to independently adjudicated, hash-frozen truth. It explicitly separates review alerts, fully observed non-alerts, and abstentions. It reports selective F1 only **together with its coverage**, as well as attack-recall lower/upper bounds accounting for unknown observations. It refuses row/site mismatch and inconsistent alert evidence; no attack truth is ever used by the detector. The new tests use **synthetic fixtures only**. See `reports/SmartGrid_Phase41_Blind_Site_Selective_Validation_2026-10-26.md`.

Phase 42 adds `offline_blind_site_run.py`, a two-step provenance workflow: `prepare` creates normalized observations, predictions, and a SHA-256 seal **without opening truth labels**; only a later `unblind` command verifies those sealed bytes and evaluates separately committed truth. It refuses output overwrites and mismatched files. This prevents accidental label exposure inside the software workflow, but cannot prove externally that human operators precommitted fairly or sourced trustworthy independent labels. See `reports/SmartGrid_Phase42_Sealed_Two_Stage_Evaluation_2026-10-26.md`.

Phase 43 adds `smartgrid_platform/scripts/deployment_preflight.py`, a read-only, locally runnable Docker Compose security/configuration preflight. Once a private `.env` is set, install `smartgrid_platform/requirements-preflight.txt` then run `python smartgrid_platform/scripts/deployment_preflight.py --project smartgrid_platform`. This verifies the reviewed three-service topology, loopback-only ingress, absent database/backend published ports, privilege restrictions, healthchecks, volume, environment password readiness and required file presence. It does not start Docker or prove live deployment. See `reports/SmartGrid_Phase43_Private_Deployment_Preflight_2026-10-26.md`.

Phase 44 stress-tests the **frozen price-only research lane** with controlled synthetic tariff offsets on the actual final 360 benign S0 seconds. Offsets of −€0.05/kWh and −€0.10/kWh produced 360/360 false reviews despite zero for the unshifted prices; this is a real measured negative-control failure, **not** a new independent-site attack score or a reason to tune thresholds on S0. The OR-based research fusion inherits any isolated price-lane false reviews. See `reports/SmartGrid_Phase44_Price_Regime_Robustness_2026-10-26.md` and its JSON table. Operationally a price-regime shift must be treated as unverified context, not authenticated MQTT compromise.

Phase 45 explicitly quantifies what happens if price novelty is reported only as contextual information and meter/Modbus/ARP are the security-review lanes. Across examined S1–S6, macro F1 drops from 0.98943 to 0.83355: **S6 collapses from 0.99558 to 0.06034 F1**, losing 1,308 price-only labelled attack rows while avoiding 12 price-only benign alarms. Historical F1 for S1–S5 is unchanged. The React Research Evidence page and read-only `/api/price-context-research` endpoint show the tradeoff and Phase 44 benign shift sensitivity with explicit not-deployed caveats. No live model or threshold was changed. See `reports/SmartGrid_Phase45_Price_Context_Tradeoff_2026-10-26.md`.

Phase 46 adds **offline Ed25519 tariff statement verification** (`offline_signed_tariff_verifier.py`) and a timestamp-strict two-track evidence join (`offline_tariff_context_bridge.py`). A separately frozen, site-specific public-key inventory can authenticate byte-level provenance and distinguish signed-but-novel tariffs, invalid signatures, observed/signed mismatch, unknown key, expired key, missing observations and replay sequence anomalies. Install `requirements-tariff.txt` only to use this optional offline research capability. Unit tests use ephemeral synthetic signing keys; **no utility keys, private keys or real MQTT messages are bundled**, and the backend four-lane capability is still not deployed. See `reports/SmartGrid_Phase46_Signed_Tariff_Provenance_2026-10-26.md`.

Phase 47 stress-tests the cryptographic trust boundary and strengthens cross-run replay handling. The offline verifier now optionally accepts an independently committed previous sequence checkpoint, returns a proposed next checkpoint, and marks batch-only runs explicitly as lacking restart replay assurance. A synthetic signer-compromise counterexample proves that honest and maliciously controlled use of the *same valid key* can yield identical signed statements. Full pipeline synthetic tests exercise normalized observation → four-lane replay → signed tariff audit → timestamp-strict context join. This is a **negative security control and engineering validation**, not new independent detection accuracy. See `reports/SmartGrid_Phase47_Tariff_Trust_and_Replay_Boundary_2026-10-26.md`.

The packaged model lives at the same relative path expected by these scripts: `smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json`.

**Phase 54** expands the exploratory Cyber4OT capture-level audit to 83 publisher-labeled attack-scenario captures (65 at central-switch vantage, 18 at PLC-port vantage) and four held-out benign captures. An exploratory, post-hoc source-MAC novelty cutoff >3 flags 83/83 attack captures and 0/4 benign captures. This is **not prospective accuracy**: the cutoff and feature were studied on the same testbed, and there are no event-level labels or independent-site verification. The frozen production meter model is unchanged. See `reports/SmartGrid_Phase54_Full_Cyber4OT_Capture_Audit_2026-10-27.md`. Project readiness remains estimated at **88/100** pending independently sourced prospective site testing and real private-host deployment validation.

**Phase 55** derives a **traffic-normalized, viewpoint-specific threshold exclusively from an earlier benign calibration capture**. It flags 83/83 publisher attack-scenario files and 0/2 later normal files (one per vantage), with an explicit warning that the MAC feature was selected post hoc and a Poisson packet independence model is not realistic. This is not field false-alarm or independent-site validation. See `reports/SmartGrid_Phase55_Benign_Only_Rate_Calibration_2026-10-27.md`.

**Phase 56** adds a synthetic device-maintenance stress test, using previously measured benign PCAP denominators. Injecting ten hypothetical benign frames with an unseen source MAC causes the Phase 55 network novelty rule to flag both later benign captures. This is **not real maintenance performance**; it demonstrates why independent trusted inventory/change records and prospective maintenance controls are needed. See `reports/SmartGrid_Phase56_Maintenance_Counterfactual_2026-10-27.md`.

**Phase 57** uses all four public Zero-SWARM captures (https://zenodo.org/records/15082260; publisher MD5 verified). The short normal session produces no MAC false flags, but **all 458 minutes of the longer benign recording falsely flag**. Its already-enrolled MAC inventory would yield zero MAC anomaly packets for either publisher attack recording. Thus MAC-only detection is not robust under normal session shift. See the Phase 57 report.

**Phase 58** explores a separate TCP destination-port breadth plus SYN-probe rule. Retrospectively it flags 21/21 attack-scenario minutes and 0/492 normal minutes across this publisher testbed, including the long benign recording. The feature was picked after examining these files: **these are not blind, deployment-ready results or the deployed model's accuracy**. See the Phase 58 report. Readiness is still estimated **88/100** pending prospective independent site and private Docker-host validation.

**Phase 59** freezes the Phase 58 TCP transport review rule and tests it on the distinct Cyber4OT PCAPNG publication without readjusting the threshold. It flags 73/83 attack-scenario files and 0/4 normal files. **All ten ping-scan captures are missed**, identifying the precise family that this lane does not cover. These are file-level, cross-dataset findings, not packet/event F1. See `reports/SmartGrid_Phase59_Frozen_TCP_Cross_Dataset_2026-10-27.md`.

**Phase 60** adds an exploratory ARP target-sweep lane, using only earlier benign captures to calibrate view-specific minute-target maxima (central switch 6, PLC port 5). The post-hoc ARP review complements fixed TCP review, yielding 83/83 attack-scenario file alerts and 0/2 later benign file alerts in Cyber4OT. **Feature selection was attack-informed**, and legitimate engineering discovery/maintenance could trigger the same rule, so this is not independent-blind or deployable field accuracy. See `reports/SmartGrid_Phase60_ARP_Sweep_Complement_2026-10-27.md`.

**Phase 61** adds `smartgrid_platform/scripts/deployment_acceptance.py`: static default, strict `--live` mode for the **user's already-running private Docker host**, fail-closed service identity/health and loopback API/DB checks, and adversarial no-mutation tests. The research environment has no Docker runtime or private `.env`; **no live deployment success is asserted**. See `reports/SmartGrid_Phase61_Deployment_Acceptance_Gate_2026-10-27.md` and the corrected Windows instructions in `smartgrid_platform/README.md`.

**Phase 62** closes the previously unauthenticated local dashboard/API access gap: Docker requires a separate 40+ character private access token, FastAPI gates every non-health API endpoint, React provides a tab-memory-only token login/sign-out screen, and preflight/smoke checks now validate authenticated operation. Localhost restriction remains mandatory; no TLS, user roles, live Docker deployment or independent site accuracy is claimed. See `reports/SmartGrid_Phase62_Private_Token_Authentication_2026-10-27.md`.

No research paper is included.

**Phase 64 — GitHub Codespaces private deployment:** The repository now includes a `.devcontainer` Docker-in-Docker configuration and a one-command `smartgrid_platform/scripts/codespaces_deploy.py` launcher. It generates noncommitted credentials, validates and starts the three-service private stack, performs read-only acceptance, and rehearses PostgreSQL backup recovery in an isolated database. All host-dependent steps require an actual Codespace; no external GitHub repository was created or live Codespace run claimed. Start with `CODESPACES_START_HERE.md` at repository root.

**Phase 63** adds a gated PostgreSQL restore drill that verifies the backup digest, restores only into a newly created randomly named test database, checks both application tables, and cleans up the test database. Six added mocked tests exercise destructive-operation boundaries. Actual Docker/PostgreSQL recovery on the user's own host remains unverified and must be initiated explicitly there. See `reports/SmartGrid_Phase63_Isolated_PostgreSQL_Restore_Drill_2026-10-27.md`.

**Phase 66 (research preregistration):** A third-domain industrial-network challenge is fixed in `reports/SmartGrid_Phase66_Third_Domain_Preregistration_2026-10-27.md` before obtaining DataSense/CIC IIoT 2025 captures. The frozen TCP rule will be evaluated without tuning, and unsupported ARP sensor viewpoints must abstain. The publisher's access form has not been completed and no new accuracy is claimed. The repository's GitHub Actions workflow independently verifies the backend, operational safeguards, React build and SHA256 source manifest.


**Phase 68 (new independent power-system scan-response audit):** The publisher-verified TU Delft/Zenodo digital-twin PCAPNG (11,372 frames, 970.751 seconds) was tested with the *previously frozen* TCP port-diversity/SYN rule, with no refitting. It flagged 10 of 15 nonempty minute buckets in two contiguous alert groups. Source checksums, deterministic replay and caveats are in `reports/SmartGrid_Phase68_Independent_Power_Twin_Scan_Response_2026-10-27.md`; the executable is `zenodo_power_twin_frozen_tcp.py`. The publisher supplied **no packet-level attack labels, exact attack intervals, or independent benign control**: these are review signals, **not true-positive counts, accuracy, recall, F1 or false-positive-rate measurements**. The source capture is not redistributed.


**Phase 69 (new independent GOOSE scope control):** Four published University of Cyprus/KIOS S1/S2 GOOSE substation packet captures (two attacks, two matching benign scenarios) passed publisher checksum validation. The frozen TCP scanning rule correctly produced **no TCP scan reviews**, but it does **not detect** either GOOSE FDI or message-suppression attack. These are **explicit out-of-scope abstentions (or misses if claiming all-attack coverage)**, not successful attack detection. VLAN inner EtherType `0x88B8` frames and all source hashes are reported in `reports/SmartGrid_Phase69_KIOS_GOOSE_Out_of_Scope_Control_2026-10-27.md` and reproduced by `kios_goose_scope_audit.py`. These short benign captures do not satisfy a 24-hour false-alarm acceptance requirement.
