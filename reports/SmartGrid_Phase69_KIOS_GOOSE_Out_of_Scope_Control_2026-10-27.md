# Phase 69 — Independent KIOS substation GOOSE out-of-scope control

Date: 2026-10-27. **Four actual publisher captures parsed; policy remained frozen.**

## Independent dataset

Source: University of Cyprus / KIOS CoE, [SUC4 coordinated overcurrent-protection attack and benign captures](https://doi.org/10.5281/zenodo.12960228), Zenodo v1, 2024-07-26. The deposit labels two network-traffic variants per scenario: S1 normal vs. false-data injection (FDI) over IEC 61850 GOOSE, and S2 normal with circuit-breaker failure vs. GOOSE message suppression. All four captures were downloaded from the official repository with their published MD5s independently matching. Files are not redistributed here.

## Frozen TCP research detector, without tuning

The pre-existing Phase 58/59 rule reviews a 60-second capture-relative bucket only when there are more than two distinct **IPv4/TCP** destination ports AND one SYN without ACK. **It is not a GOOSE intrusion detector.** Consequently, attack/non-attack GOOSE data must be labeled **ABSTAIN: OUT-OF-SCOPE PROTOCOL** when judging model capability, regardless of whether unrelated TCP reviews appear.

## Executed facts

| Publisher scenario / condition | Frames | Duration (s) | VLAN-encapsulated GOOSE frames | IPv4/TCP frames | Nonempty 60-s windows | TCP review windows |
|---|---:|---:|---:|---:|---:|---:|
| S1 / FDI attack | 1,155 | 203.937 | 445 | 411 | 4 | **0** |
| S1 / without attack | 1,794 | 340.686 | 314 | 692 | 6 | **0** |
| S2 / message-suppression attack | 780 | 103.617 | 379 | 219 | 2 | **0** |
| S2 / without attack | 3,529 | 747.360 | 282 | 1,522 | 13 | **0** |

Publisher MD5 and independently computed SHA-256 pairs:

- S1 attack: `5e2673a84e089737df824ee45fc29416` / `e6fc6d79ec35c55071f9cb4833d145213ba772cb0645052040a5aa0a7e5c6ff7`
- S1 benign: `11e2f8448c0b6344305936a23988c2f5` / `64f46f1d1e6b7f34d03bd5340119a5c4b32c136b2e992b058baf51d114ac4a94`
- S2 attack: `276a87bddbf62b346cb89ba7035597ac` / `3319db74aca22f800a279e97e91d38ebbf28b0f009ced12ff56520f500a6e035`
- S2 benign: `96185f2ba3afff438b91384b41ef30a4` / `9042dd9edb1ae4b457abc2d9bfe54572afa7dedd4217a58466033ea6c6d4ccd7`

### Honest interpretation

- **No false TCP-scan reviews on these two short benign files** (zero reviewed windows), but that is not sufficient to establish 24-hour benign false-episode rate.
- **Both GOOSE attack files yielded zero TCP-scan reviews**, as predicted for an unsupported attack family. If claiming *all-attack coverage*, these are two attack-capture misses. For the explicitly scoped TCP reconnaissance detector, they are abstentions.
- Many GOOSE frames are 802.1Q VLAN-tagged; naive checks of only outer Ethernet type `0x8100` would miss their inner GOOSE type `0x88B8`. The replay counts the inner tag.
- File labels identify attack scenarios but do not establish packet-by-packet intrusion truth or attacker onset intervals. No prospective F1 or GOOSE accuracy is claimed.
- Short simulated substation captures do not validate the deployed meter detector, ARP lane, false-alarm episode target, or new site environment.

## Reproduction

With `dpkt==1.9.8`, download the four named PCAPNG files from the official Zenodo record and run:

```bash
python kios_goose_scope_audit.py /directory/containing/the/four/captures
python -m unittest -v test_kios_goose_scope_audit
```

The script rejects any file that fails the publisher's MD5 check and reports the intentionally unsupported GOOSE detection scope. No research paper prepared.
