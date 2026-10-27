# Phase 60 — ARP target-sweep complement to frozen TCP port rule

## Motivation and protocol

The Phase 59 fixed TCP destination-port/SYN rule transferred from Zero-SWARM to Cyber4OT but missed all **ten Cyber4OT ping-scan scenario files**. Direct PCAPNG inspection showed the publisher ping scans are predominantly **ARP request target sweeps**, not ICMP echo floods. This observation *preceded* design of the ARP rule, so **feature selection is post-hoc and label-informed**.

For each capture-relative 60-second bucket, count distinct destination IPv4 addresses in Ethernet ARP request packets. Keep a separate maximum from the normal baseline (`001` central switch / `069` PLC port) and one earlier benign calibration (`002` / `070`). The resulting maximum normal ARP targets/minute is **6** for central switch and **5** for PLC port. Evaluate only the *later* held-out normal recordings (`003` and `071`) plus the 83 publisher attack-scenario captures at their matched viewpoint. The companion TCP rule is held exactly as in Phase 58/59: more than two TCP destination ports AND at least one SYN-without-ACK packet in a minute.

| Scenario | Files | TCP files with review | ARP files with review | Either review |
|---|---:|---:|---:|---:|
| Central-switch host scan | 60 | 60 | 46 | 60 |
| Central-switch ping scan | 5 | 0 | 5 | 5 |
| PLC-port scan | 5 | 5 | 0 | 5 |
| PLC-port ping scan | 5 | 0 | 5 | 5 |
| PLC-port MAC/hijack | 8 | 8 | 7 | 8 |
| Later benign at two viewpoints | 2 | 0 | 0 | 0 |

In this **retrospective research audit**, the OR review decision flags **83/83 attack-containing scenario files** and **0/2 later normal files**. The extra normal calibration captures are used in threshold fitting and cannot be counted as tests. All source PCAPNG data came from independently published [Cyber4OT](https://zenodo.org/records/15005190) with publisher MD5 verified. Exact per-file score evidence is in `SmartGrid_Phase60_Cyber4OT_ARP_Sweep_2026-10-27.json`.

## Why this is not 100% detection

- The ARP feature was chosen specifically after the TCP rule missed the Cyber4OT ping-scan labels. This is **not pre-registered blind evaluation**, and repeated attack-mode captures are correlated.
- Scenario-level truth is not packet/event ground truth. Captures may mix normal and attack. A reviewed minute need not coincide with a malicious packet.
- Two held-out benign recordings are insufficient for field false-alert/day validation. Legitimate IP discovery, network maintenance, redundancy failover, or commissioning could cause similar ARP sweeps.
- Phase 57 showed that MAC novelty could produce 458/458 benign minute false reviews on a different normal session; it must not be blindly fused or treated as authenticated attribution.
- The Zero-SWARM dataset has only ordinary TCP traffic in the examined captures; it does not independently validate this new ARP-sweep criterion. The frozen meter detector remains unchanged, and there is no prospective unseen site evaluation or actual private Docker-host deployment test.

## Architecture guidance

Keep research review lanes for (1) Modbus/TCP destination-port and connection behavior, (2) ARP discovery target breadth, (3) signed/authenticated tariff context where independently configured, and (4) physics integrity. Explicitly distinguish review, normal and abstain, bind lanes to authenticated sensor viewpoint, and do not update inventories from observed suspicious traffic. Prioritize an untouched testbed with legitimate engineering scans and maintenance days to verify whether the apparent separation survives. Project readiness remains **88/100**, not a model accuracy percentage. No research paper was written.
