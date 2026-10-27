"""Publisher-verified KIOS GOOSE scope-control audit (not a GOOSE detector).

Zenodo DOI 10.5281/zenodo.12960228; four labeled scenario PCAPNG files.
Usage: python kios_goose_scope_audit.py /directory/containing/four/files
Counts frozen TCP reviews, VLAN-encapsulated GOOSE frames and scope abstentions.
"""
import argparse
import hashlib
import json
from pathlib import Path

import dpkt

from zenodo_power_twin_frozen_tcp import score_reader


FILES = {
    "Electron_SUC4_S1_FDI_Attack_Traffic.pcapng": ("S1", "attack", "5e2673a84e089737df824ee45fc29416"),
    "Electron_SUC4_S1_Without_Attack_Traffic.pcapng": ("S1", "benign", "11e2f8448c0b6344305936a23988c2f5"),
    "Electron_SUC4_S2_MS_Attack_Traffic.pcapng": ("S2", "attack", "276a87bddbf62b346cb89ba7035597ac"),
    "Electron_SUC4_S2_Without_Attack_Traffic.pcapng": ("S2", "benign", "96185f2ba3afff438b91384b41ef30a4"),
}
GOOSE_ETHERTYPE = 0x88B8


def count_vlan_goose(frames):
    count = 0
    for _, frame in frames:
        try:
            ethernet = dpkt.ethernet.Ethernet(frame)
            tags = getattr(ethernet, "vlan_tags", ())
            if any(tag.type == GOOSE_ETHERTYPE for tag in tags):
                count += 1
            elif ethernet.type == GOOSE_ETHERTYPE:
                count += 1
        except (dpkt.UnpackError, ValueError, IndexError):
            continue
    return count


def evaluate(directory):
    directory = Path(directory)
    captures = []
    for name, (scenario, truth, expected_md5) in FILES.items():
        path = directory / name
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                md5.update(block)
                sha.update(block)
        if md5.hexdigest() != expected_md5:
            raise ValueError("Publisher MD5 mismatch: " + name)
        with path.open("rb") as stream:
            frames = list(dpkt.pcapng.Reader(stream))
        result = score_reader(frames)
        goose = count_vlan_goose(frames)
        captures.append({"scenario": scenario, "publisher_label": truth,
                         "filename": name, "sha256": sha.hexdigest(),
                         "publisher_md5": md5.hexdigest(),
                         "frames": result["frames"],
                         "duration_seconds": result["capture_duration_seconds"],
                         "goose_frames": goose,
                         "ipv4_tcp_frames": result["ipv4_tcp_frames"],
                         "nonempty_windows": result["nonempty_windows"],
                         "tcp_review_windows": result["reviewed_windows"],
                         "scope": "ABSTAIN: GOOSE message FDI/suppression not covered by frozen TCP scanning rule"})
    return {"source_doi": "10.5281/zenodo.12960228",
            "rule": "Frozen TCP >2 distinct destination ports plus SYN-without-ACK, 60 seconds",
            "scope": "Out-of-scope IEC 61850 GOOSE controls; no GOOSE attack detection claimed",
            "captures": captures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_directory", type=Path)
    print(json.dumps(evaluate(parser.parse_args().capture_directory), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
