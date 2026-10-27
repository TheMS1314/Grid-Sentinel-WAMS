# Grid Sentinel — Phase 22 Next-Level Audit and Integrated Delivery

**26 October 2026 | Research-only | No paper drafted**

## Executive status

The application now combines **React + TypeScript, FastAPI, PostgreSQL, Nginx and Docker Compose** with an in-dashboard historical evidence page. We tested the frozen 15-feature meter-integrity model against the previously inspected Data4Cyber v3 collection without refitting or selecting a new threshold. We added episode-level replay, latency, phase-specific coverage, invalid-data accounting, Wilson descriptive intervals, counterexample probes and automated parity tests.

**The engineering and evidence transparency improved materially, but we did not achieve a genuine new held-out model accuracy improvement.** Model scope is narrower than a universal cyberattack detector, and prospective field acceptance remains blocked.

| Workstream | Verifiable status |
|---|---|
| React dashboard, history, analysis lab, evidence view | Production build **passed** |
| FastAPI and database API contract tests | **6/6 passed** against isolated test DB |
| Phase 22 replay/parity/counterexample tests | **4/4 passed** |
| Previous six cross-dataset/research reproduction checks | **6/6 passed** |
| Research-readiness quality requirements | **3/10 passed**, seven unsatisfied; this is **not** a completion percentage |
| Actual Docker + PostgreSQL integration on user's PC | **Pending**, no Docker in execution environment |
| Independent unseen MITM replication and low alarm rate | **Pending / not demonstrated** |
| Research paper | **Not started**, as requested |

## Frozen-model replay results

Input: Data4Cyber v3 CSVs, S0 60% fit / 20% calibration already frozen / **last 360 benign rows tested**, plus all S1–S6 rows. The head was chosen post hoc after inspecting earlier test campaigns. `attack_active` includes preparatory stages, not only maliciously altered sensor values. Counts below are publisher-labeled *activity* states, not confirmed manipulated-record labels. Full output including scenario-specific Wilson intervals and phase names is `reports/SmartGrid_Phase22_Replay_Results_2026-10-26.jsonl`.

| Scenario | Row F1 | Row recall | Clean-period row FPR | Labeled activity episodes with any review | False review episodes |
|---|---:|---:|---:|---:|---:|
| S0 final clean holdout | N/A | N/A | **1.111% (4/360)** | N/A | **2** |
| S1 PV Modbus | 0.02355 | 1.205% | 1.130% | 1/2 | 4 |
| S2 battery Modbus | 0.01095 | 0.554% | 0.578% | 1/2 | 3 |
| S3 battery MITM | 0.56875 | 39.912% | 0.450% | 1/2 | 3 |
| **S4 loads/PV MITM** | **0.99202** | **98.886%** | 1.109% | 1/2 | 2 |
| S5 multi-meter MITM | 0.77092 | 62.864% | 0.654% | 2/3 | 1 |
| S6 MQTT price compromise | 0.06034 | 3.111% | 0.000% | 1/1 | 0 |

### Key interpretation corrections

1. The S4 *missed* 10-second `attack_active` episode is labeled `s4_reconnaissance_nmap_mitm`. This meter-physics detector should not be expected to identify network reconnaissance. The separate **1,247-row S4 MITM manipulation interval had 1,243 flagged rows**, with its first flag **4 seconds** after interval start.
   - S4 MITM **phase 1**: **620/624 = 99.36%** labeled rows reviewed; **phase 2**: **623/623 = 100%**.
2. Similarly, S1, S2, S3 and S5 each include a short reconnaissance episode without physics flags. Unqualified **episode recall** under `attack_active` therefore mixes distinct detection tasks. S5's two manipulation-related episodes each generated reviews; the first S1/S2 active Modbus manipulation episodes were detected only sparsely and late (61 s and 149 s respectively).
   - Crucially, **S5 MITM phase 1**: **745/749 = 99.47%** row recall, while **phase 2 falls to only 98/582 = 16.84%**. Aggregated S5 F1 masks this phase-specific failure; multi-meter coordinated manipulation is a priority failure mode.
3. S4 contains **31 invalid required-meter rows, all in its benign-labeled period**. The live model abstains on missing/nonfinite readings, and this exclusion must not be hidden by quoting only the row F1.
4. Two distinct false-alarm episodes in a **six-minute** S0 heldout clean sample are not operationally tolerable if representative. The extrapolation of 20 false episodes/hour is an illustration only, not a measured multi-hour rate; we do not infer the number of false alerts/day from such a short, autocorrelated sequence.
5. Wilson 95% row-rate intervals in the JSONL are **descriptive only** because one-second observations are serially dependent. They must not be interpreted as statistically independent future-site confidence guarantees.

### Controlled counterexamples (not dataset attacks)

On eight consistent synthetic one-second observations, altering only the first meter's total P by +50% starting at row 3 produced **4 review rows** (following the three-row persistence rule). Altering that same P total and *all its phase P values coherently* produced **0 review rows**. Introducing one missing meter field produced **1 abstention and no spurious review**. This directly demonstrates a fundamental evasion of local power-identity detection: a coordinated attacker can preserve the arithmetic identity. No claim about stealth against broader physics/protocol defenses follows.

## What changed in the software

- A new **Research evidence** dashboard view displays the embedded historical benchmark results, descriptive gaps, confidence boundaries, and scope warnings. It is visually separate from *live analysis history*; older historical results are not represented as fresh online model accuracy.
- The FastAPI route `GET /api/research-evidence` serves only the packaged, read-only replay results; no attack simulation is executed by the web service.
- The React production bundle is split into the application (~74 KB), React runtime (~224 KB), and chart dependency (~359 KB), eliminating the previous >500 KB advisory for a single monolithic chunk. Sizes are uncompressed JS build outputs and not browser speed measurements.
- One additional API test and four standalone replay-engine parity/uncertainty/counterexample tests passed.
- The delivery contains an offline repro harness, published source links, and the exact benchmark JSONL. **Raw third-party dataset ZIPs and private credentials are excluded.**

## New dataset and architecture prioritization

These sources were rechecked on 26 October 2026. **Only data already locally supplied were actually tested; a paper/repository listing is not a completed independent benchmark.**

| Priority | Candidate / source | Scientific value | Applicability to the frozen model |
|---|---|---|---|
| **1** | [Sherlock v3 power-grid process-aware dataset](https://zenodo.org/records/18467070) | Attack-free training and attack test scenarios, plus a rural transfer-only network; stronger unseen-network design | Likely requires a distinct SCADA/process model. Check channel availability before using; do not presume its channels equal Data4Cyber's 60-meter contract. |
| **1** | [CPDS-AD and published evaluation code](https://github.com/liuyulinlyl/CPDS-AD-Detection-Methods) | A physical three-phase scaled feeder with MQTT/Modbus, 5-second readings, local model-consistent FDI, replay and ramp drift | Strong complement for previously missed coherent FDI and protocol families; needs a *separate*, preregistered model and 5-second temporal policy. |
| **2** | [COCOON Energy Community PHIL/CHIL](https://zenodo.org/records/21476677) | Hardware-in-loop tests, attack plan JSONs, measurement/FDII artifacts | Already examined in earlier phases. Validate exact tag-to-bus mapping, timestamp alignment, injections, and uncertainty semantics before independent scoring or AC WLS. |
| **3** | [PowerBench PV/sensor attacks](https://zenodo.org/records/15401632) | Graph/topology sensor and PV attacks, localization across 34/123/8500-node feeder simulations | Requires topology-aware modeling and substantially more disk (~32.6 GB total published files); **not downloaded**. |
| **3** | [ECU-PMU-FDI/TSA data](https://doi.org/10.1038/s41597-026-07178-3) | Phasor time synchronization / false-data injection; aligns with earlier PMU lane | Complementary specialized PMU experiment rather than a direct transfer of Data4Cyber meter invariants. |

### Recommended research architecture, not yet built or validated

1. **Tier 1 — explicit integrity reviews:** retain frozen 15-feature detector *only* for the narrow phase/total mismatch use case; log abstentions and sensor-sampling quality.
2. **Tier 2 — authenticated protocol provenance:** separately detect Modbus writes/response inconsistencies and MQTT price publication deviations only with legitimate baselines and traceable command/message origin. Do not turn meter score into an attack verdict.
3. **Tier 3 — independently trusted observations:** compare protected measurement sources (PMU/meter) when cryptographic or physical provenance is established, rather than asserting an unauthenticated cross-sensor is trustworthy.
4. **Tier 4 — topology-constrained estimation:** add a physically verified feeder/network model with impedance, units and uncertainty covariance. Blindly attaching WLS to the current PV score failed clean transfer in Phase 19 (13–25% clean false alerts).
5. **Unseen evaluation gate:** preregister scenarios, attack definition, sites, thresholds, clean-day false-alarm limit, temporal alarm lag, abstention policy, and both row- and event-level scores *before* final unseen data are opened. Report source-domain and transfer-domain metrics separately.

## What prevents claiming 100% yet

New independently labeled comparable captures, verified COCOON attack windows/impedance/covariance, provenance for MQTT, trusted anchor instrumentation, and longer diverse clean recordings cannot be invented from existing test sets. There is no ethically sound shortcut via choosing new thresholds after viewing test labels. Docker end-to-end validation will be performed only after the user can run the delivered Compose stack on a Docker-capable host.

## Reproduce

The source ZIP contains `smartgrid_platform/`, offline research scripts at its top level, and `reports/`.

```bash
python3 -m pip install numpy pandas scikit-learn
python3 -B -m unittest -v test_smartgrid_phase22_reliability
python3 -B smartgrid_phase22_reliability.py --archive Data4Cyber_v3_2026.zip
python3 -B smartgrid_research_acceptance.py
```

The named dataset ZIPs must be acquired from their public publishers separately and placed beside the scripts. `--strict` on the acceptance gate exits nonzero while readiness requirements remain unsatisfied. Frontend/API tests are described in `smartgrid_platform/README.md`.

**No research paper has been created.**
