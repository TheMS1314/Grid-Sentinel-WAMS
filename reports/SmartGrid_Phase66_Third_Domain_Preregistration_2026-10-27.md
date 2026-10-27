# Phase 66 — Pre-registered independent industrial-network challenge

Date: 2026-10-27 (Asia/Kolkata). **Protocol commitment only; no new experiment has run.**

## Independent publication and source

Candidate: **DataSense: CIC IIoT Dataset 2025**, Canadian Institute for Cybersecurity at the University of New Brunswick, [official dataset page](https://www.unb.ca/cic/datasets/iiot-dataset-2025.html). The publisher reports 12 hours of benign execution (259,212 packets), and separate recon classes including ARP host discovery, TCP ACK/SYN discovery, ping sweeps, port scans and vulnerability scans. It also lists MITM/ARP spoofing, denial-of-service and other distinct attack families.

The [publisher's download page](https://cicresearch.ca/IOTDataset/Datasense/) requires a name, email, institution and related details and displayed a server error when inspected on 2026-10-27. **No account, form, personal information, credentials, or dataset bytes were obtained.** No claim that this source's labels are event-level or capture-level can be made until its files and metadata are inspected.

## Commitment before accessing source captures

1. Preserve the Phase 58/59 **frozen TCP** research rule without threshold fitting: in a capture-relative 60-second bucket, review only if there are **more than two distinct TCP destination ports** and **at least one TCP SYN packet without ACK**.
2. Count the number of flagged minutes and flag episodes separately from capture-level review. A file-level scenario flag is **not** attack-event onset detection, attribution or packet classification.
3. Record every file's publisher link, SHA-256, capture viewpoint, duration, packet count, label semantics, sampled interval coverage and parsing failures **before** computing detector metrics. Refuse scoring when any indispensable metadata is unknown.
4. Use all available independent benign hours, including natural changes and maintenance if documented; do not discard noisy benign traffic to improve false-positive results. Report clean alert episodes per day **with observed coverage** and uncertainty, not just zero-false-alert percentages.
5. Evaluate TCP reconnaissance captures as a predeclared **in-scope** family. Other classes (DoS, MITM, web, malware, physical signal changes) remain explicitly **out-of-scope** for this fixed TCP rule; still report misses and abstentions by family. Avoid an inflated macro F1 from silently dropping non-scanning attacks.
6. Do **not** reuse the Cyber4OT viewpoint-specific ARP target maxima of 6/5 as a third-domain production policy. ARP traffic may be analyzed descriptively, but thresholded ARP performance is marked **ABSTAIN: UNTRUSTED SENSOR VANTAGE** until a separately trusted baseline is precommitted. Legitimate ARP discovery is a required negative control.
7. Do not re-run feature selection, resample until favorable, pool the new data into training, or tune thresholds based on the outcome. If the frozen feature fails, publish the failure and keep any subsequent candidate in a separate exploratory result.
8. Predeclared research goals, not claims: on documented port-scan files, file-level recall at least 80%; on benign packets, target at most **one false alert episode per 24 observed hours**. These thresholds are demanding and the available 12 benign hours may be insufficient to certify that rate. No independent-site deployment qualification is claimed from this benchmark even if targets are met.

## Why this is important

Prior studies have a genuine split. The frozen TCP rule transferred from Zero-SWARM to Cyber4OT with **73/83 attack-scenario captures flagged and 0/4 benign captures flagged**, but missed all 10 ping-scan scenarios. A later ARP target sweep was added after observing those misses and consequently obtained a retrospective **83/83** scenario result on Cyber4OT. Its feature selection was label-informed. Separately, Zero-SWARM long-benign sessions falsified naive source-MAC novelty with **458/458** false-flagged benign minute buckets. The new dataset should challenge the **frozen** rule and expose shortcomings, not produce another post-hoc 100% headline.

The official publisher describes its records as synchronized industrial sensor and network data from a dedicated testbed. It is not the user's microgrid. The frozen deployed FastAPI model remains the 3-phase meter-consistency engine; the TCP/ARP rules are **offline research only**.

## Access and next execution gate

Only after an authorized researcher acquires the publisher files through its official process: inventory metadata, verify independently recorded file digests, confirm capture-level labels and time semantics, and execute this frozen evaluation once. Store raw captures outside the Git repository. The remaining requirement is source access; it must not be replaced with fabricated or inferred metrics.

No research paper was prepared.
