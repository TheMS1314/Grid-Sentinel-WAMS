# Grid Sentinel Phase 26 — ARP alert persistence and false-alarm trade-off

Date: 2026-10-26. **Research status: exploratory, non-deployed.** No research paper is included.

## Purpose and fixed evidence

Phase 25 improved coordinated MITM activity detection using a passive mismatch between ARP sender IP/MAC claims and the S0 published role inventory. This phase systematically measures whether a shorter alert-hold duration retains S3/S5 coverage with fewer benign-row alerts. The frozen meter-integrity model was not retrained. This sweep was designed and examined *after* inspecting the attack campaigns; choosing a threshold here would constitute post-hoc selection, not independent validation.

The `data4cyber_arp_policy_sweep.py` command evaluates hold durations 0, 1, 2, 3, 4, and 5 seconds against S0, S3, S4, and S5 packet captures and 1 Hz activity labels. Reported F1 scores are for *attack-labeled activity rows*, not authenticated intrusion attribution. Metrics cover physics-only, ARP-only, logical-OR fusion, benign-row false-positive burden, and alert episodes. S0 uses the reserved final 20% segment, consistent with previous runs.

## Exact outcomes

| Scenario | ARP hold | Combined F1 | Combined benign-row FPR | Benign alert seconds | Clean alert episodes |
|---|---:|---:|---:|---:|---:|
| S0 | 0 s | N/A | 1.111% | 4 | 2 |
| S0 | 2 s | N/A | 1.111% | 4 | 2 |
| S0 | 5 s | N/A | 1.111% | 4 | 2 |
| S3 | 0 s | 0.81883 | 0.450% | 4 | 3 |
| S3 | 2 s | 0.99341 | 0.450% | 4 | 3 |
| S3 | 5 s | 0.99506 | 0.450% | 4 | 3 |
| S4 | 0 s | 0.99202 | 1.109% | 6 | 2 |
| S4 | 2 s | 0.99202 | 1.109% | 6 | 2 |
| S4 | 5 s | 0.99202 | 1.109% | 6 | 2 |
| S5 | 0 s | 0.89190 | 1.525% | 7 | 5 |
| S5 | **2 s** | **0.99067** | **2.397%** | **11** | **2** |
| S5 | 5 s | 0.98956 | 3.050% | 14 | 2 |

S5 MITM phase 2 contains 582 labeled seconds. The frozen physics detector alerts on 98; zero-hold fusion alerts on 340; two-second fusion alerts on 582. Crucially, the 2-second improvement is offset by 11 benign S5 alert seconds versus 7 at zero hold. S5 reconnaissance (10 labeled seconds) is not identified by these policies. Full 24-policy records include 1-, 3-, and 4-second cases.

## Interpretation

- On S5, a two-second policy **dominates the five-second policy within this examined dataset** on combined F1 and benign-row alert rate; keeping a five-second alert has no measured gain over two seconds for MITM phase-2 row coverage.
- S3 obtains a large apparent gain by two seconds, but there is still a small F1 gain through five seconds.
- S4 is already physics-detected and insensitive to this ARP hold setting.
- Alert episodes count contiguous benign-row alerts, not operator incidents. An episode can straddle adjacent attack and clean rows; these labels are not a representative clean-network deployment test.
- S0 has **zero observed ARP mismatches**. Therefore its clean specificity does not challenge the new ARP lane against benign network churn, changing MAC assignments, or inventory errors. S3/S4/S5 benign rows also come from attack-campaign captures.
- ARP sender claims and captured IP/MAC associations are **not cryptographically authenticated**. This policy cannot confirm attacker identity and cannot be assumed safe for automated grid control.

**Decision:** Do not silently replace the frozen model or promote any hold parameter. Display the candidates as historical sensitivity evidence in `/api/arp-research` and the React Research page. Before any operational selection, reserve independent clean captures across days and topologies, set false-alarm budgets in advance, evaluate delayed detection and incident-level performance, and test prospective attack captures without retuning.

## Reproduction and verification

```bash
python -m unittest -v test_data4cyber_arp_policy test_data4cyber_arp_lane
python data4cyber_arp_policy_sweep.py --output SmartGrid_Phase26_ARP_Policy_Sweep_2026-10-26.jsonl
```

Requires `numpy`, `pandas`, `dpkt`, the prior scripts and frozen model, and the public Data4Cyber v3 archive placed adjacent to the project code. The ZIP includes **code and derived results, not third-party raw captures**. Test all six policies rather than treating this exploratory operating-point comparison as a new blind benchmark.

Scientific readiness is unchanged until independent data/provenance and deployment requirements are met. Phase 25's 3/10 acceptance checklist is not a statement of percent completion.
