"""External Cyber4OT passive Modbus source/identity holdout (PCAPNG).

Frozen, observational policy: a normal PLC-port capture (069) defines Modbus
client IP allowlist and known Modbus peer IP-to-Ethernet-MAC bindings. Score
later untouched benign and attack captures. No attack-label fitting.

The archive has capture-level attack-phase labels only; no packet/event F1.
"""
import argparse
import hashlib
import io
import json
import socket
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import dpkt


PUBLISHER_MD5 = "55510cbb43d8af72a69dfbcd6940daa5"
BASELINE = 69
BENIGN = (70, 71)
# Only the PLC-port view. Odd attack trace counterparts (83, 85, ...)
# were captured at an attacker endpoint and are not comparable sensors.
ATTACKS = (82, 84, 86, 88, 90, 92, 94, 95)
ATTACK_FAMILIES = {82: "macof_redirection", 84: "macof_tcpkill", 86: "macof_tcpkill",
                   88: "macof_tcpkill", 90: "successful_modbus_hijack",
                   92: "unsuccessful_modbus_hijack", 94: "post_hijack", 95: "mixed_normal_then_hijack"}


def md5sum(path):
    h = hashlib.md5()
    with Path(path).open("rb") as file:
        for block in iter(lambda: file.read(2 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def modbus_frame(frame):
    """Return IPv4 Modbus TCP peer metadata or None; malformed frames skipped."""
    try:
        eth = dpkt.ethernet.Ethernet(frame)
        if not isinstance(eth.data, dpkt.ip.IP) or not isinstance(eth.data.data, dpkt.tcp.TCP):
            return None
        ip, tcp = eth.data, eth.data.data
        if tcp.dport != 502 and tcp.sport != 502:
            return None
        return (socket.inet_ntoa(ip.src), eth.src.hex(":"), tcp.dport == 502)
    except (dpkt.UnpackError, ValueError, OSError, IndexError):
        return None


def capture_summary(archive, ident, allowed_clients=None, known_macs=None, allowed_eth_macs=None):
    member = f"traces/Cyber4OT_{ident:03d}.pcapng"
    with archive.open(member) as f:
        reader = dpkt.pcapng.Reader(io.BytesIO(f.read()))
        client_macs = defaultdict(set)
        peer_macs = defaultdict(set)
        frame_count = modbus_count = new_clients = identity_conflicts = unknown_eth_macs = 0
        seen_eth_macs = set()
        for _, frame in reader:
            frame_count += 1
            if len(frame) >= 12:
                eth_src = frame[6:12].hex(":")
                seen_eth_macs.add(eth_src)
                if allowed_eth_macs is not None and eth_src not in allowed_eth_macs:
                    unknown_eth_macs += 1
            parsed = modbus_frame(frame)
            if parsed is None:
                continue
            ip, mac, client_request = parsed
            modbus_count += 1
            peer_macs[ip].add(mac)
            if client_request:
                client_macs[ip].add(mac)
                if allowed_clients is not None and ip not in allowed_clients:
                    new_clients += 1
            if known_macs is not None and ip in known_macs and mac not in known_macs[ip]:
                identity_conflicts += 1
    return {"capture_id": ident, "frames": frame_count, "modbus_packets": modbus_count,
            "modbus_client_ips": sorted(client_macs),
            "new_client_packets": new_clients, "known_ip_new_mac_packets": identity_conflicts,
            "new_ethernet_source_mac_packets": unknown_eth_macs,
            "alert_new_client": bool(new_clients),
            "alert_ip_mac_conflict": bool(identity_conflicts),
            "alert_new_ethernet_mac": bool(unknown_eth_macs),
            "alert_fusion": bool(new_clients or identity_conflicts or unknown_eth_macs),
            "_peer_macs": {ip: sorted(values) for ip, values in peer_macs.items()},
            "_seen_eth_macs": sorted(seen_eth_macs)}


def evaluate(path):
    if md5sum(path) != PUBLISHER_MD5:
        raise ValueError("Publisher Cyber4OT ZIP digest mismatch")
    with zipfile.ZipFile(path) as z:
        for n in (BASELINE, *BENIGN, *ATTACKS):
            if f"traces/Cyber4OT_{n:03d}.pcapng" not in z.namelist():
                raise ValueError(f"Missing expected capture {n}")
        baseline = capture_summary(z, BASELINE)
        allowed_clients = frozenset(baseline["modbus_client_ips"])
        known_macs = {ip: frozenset(macs) for ip, macs in baseline.pop("_peer_macs").items()}
        allowed_eth_macs = frozenset(baseline.pop("_seen_eth_macs"))
        observations = []
        for n in (*BENIGN, *ATTACKS):
            row = capture_summary(z, n, allowed_clients, known_macs, allowed_eth_macs)
            row.pop("_peer_macs")
            row.pop("_seen_eth_macs")
            row["truth_capture"] = "benign" if n in BENIGN else "attack_scenario"
            row["attack_family"] = ATTACK_FAMILIES.get(n)
            observations.append(row)
    return {
        "source": "Cyber4OT, Zenodo 15005190 (Warsaw University of Technology)",
        "publisher_zip_md5": PUBLISHER_MD5,
        "protocol": "normal PLC-port capture 069 freezes IP/MAC Modbus policy; 070-071 held-out benign; even-numbered PLC-port attack captures 082-095 tested",
        "warning": "Exploratory capture-level detection of scenario-containing files; exact attack windows are unknown. NOT packet-level F1, attack-event recall, or independent-site performance.",
        "frozen_modbus_client_ips": sorted(allowed_clients),
        "frozen_modbus_peer_mac_bindings": {ip: sorted(macs) for ip, macs in sorted(known_macs.items())},
        "frozen_ethernet_source_macs": sorted(allowed_eth_macs),
        "training_capture": {k: v for k, v in baseline.items() if k != "alert_fusion"},
        "observations": observations,
        "summary": {
            lane: {
                "attack_scenario_captures_alerted": sum(bool(r[lane]) for r in observations if r["truth_capture"] == "attack_scenario"),
                "attack_scenario_captures_total": len(ATTACKS),
                "benign_captures_alerted": sum(bool(r[lane]) for r in observations if r["truth_capture"] == "benign"),
                "benign_captures_total": len(BENIGN)}
            for lane in ("alert_new_client", "alert_ip_mac_conflict", "alert_new_ethernet_mac", "alert_fusion")}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publisher_zip", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(evaluate(args.publisher_zip), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload)
    else:
        print(payload)


if __name__ == "__main__":
    main()
