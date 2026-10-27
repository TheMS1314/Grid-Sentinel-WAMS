"""Post-hoc S0-only Modbus write-register policy sensitivity for Data4Cyber.

Passive, read-only packet metadata. Does not transmit commands or authenticate
source IPs. Missing benign devices/registers can cause false positives.
"""
import argparse
import collections
import json
import socket
import zipfile

import dpkt
import numpy as np
import pandas as pd

from data4cyber_modbus_allowlist_benchmark import authorized_from_inventory


def decode_write(ip, tcp):
    """Return (source,destination,function,unit,start-register) or None.

    Supports fixed-address FC5, FC6, FC15, FC16, FC22. FC23 omitted because
    its read and write address layouts differ. Conservative segment-start only.
    """
    data = bytes(tcp.data)
    if tcp.dport != 502 or len(data) < 12 or int.from_bytes(data[2:4], 'big') != 0:
        return None
    length = int.from_bytes(data[4:6], 'big')
    if length < 6 or length > 253 or len(data) < 6 + length:
        return None
    code = data[7]
    if code not in (5, 6, 15, 16, 22):
        return None
    family = socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET
    return (socket.inet_ntop(family, ip.src), socket.inet_ntop(family, ip.dst),
            code, data[6], int.from_bytes(data[8:10], 'big'))


def parse_writes(stream):
    for stamp, data in dpkt.pcapng.Reader(stream):
        try:
            ip = dpkt.ethernet.Ethernet(data).data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            signature = decode_write(ip, ip.data)
            if signature is not None:
                yield (float(stamp), signature)
        except (ValueError, IndexError, dpkt.UnpackError, socket.error):
            continue


def label_rows(frame, requests):
    times = pd.to_datetime(frame['timestamp'], utc=True).astype('int64').to_numpy() / 1e9
    mask = np.zeros(len(frame), dtype=bool)
    close = 0
    for stamp, _ in requests:
        pos = np.searchsorted(times, stamp)
        candidates = [i for i in (pos - 1, pos) if 0 <= i < len(times)]
        if candidates:
            nearest = min(candidates, key=lambda i: abs(times[i] - stamp))
            if abs(times[nearest] - stamp) <= 0.55:
                mask[nearest] = True
                close += 1
    return mask, close


def score(truth, flagged):
    tp = int((truth & flagged).sum())
    fp = int((~truth & flagged).sum())
    fn = int((truth & ~flagged).sum())
    tn = int((~truth & ~flagged).sum())
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': round(tp / (tp + fp), 5) if tp + fp else None,
            'recall': round(tp / (tp + fn), 5) if tp + fn else None,
            'f1': round(2 * tp / (2 * tp + fp + fn), 5) if 2 * tp + fp + fn else None,
            'false_positive_rate': round(fp / (fp + tn), 5) if fp + tn else None}


def audit(archive, scenario, source_allow, address_allow, start_row=0):
    prefix = f'data4cyber_dataset/{scenario}/'
    frame = pd.read_csv(archive.open(prefix + 'dataset.csv'), low_memory=False,
                        usecols=['timestamp', 'attack_active', 'attack_phase'])
    if start_row:
        frame = frame.iloc[start_row:].copy()
    with archive.open(prefix + 'network_tap.pcapng') as stream:
        requests = list(parse_writes(stream))
    unseen = [(ts, signature) for ts, signature in requests if signature[0] not in source_allow]
    unknown_register = [(ts, signature) for ts, signature in requests
                        if signature[0] in source_allow and signature[1:] not in address_allow]
    # Unknown source and unknown register are disjoint by construction.
    source_alert, source_aligned = label_rows(frame, unseen)
    register_alert, register_aligned = label_rows(frame, unknown_register)
    truth = frame['attack_active'].astype(bool).to_numpy()
    return {'scenario': scenario, 'decoded_write_packets': len(requests),
            'unseen_source_packets': len(unseen), 'unseen_register_packets': len(unknown_register),
            'unseen_source_packets_aligned': source_aligned,
            'unseen_register_packets_aligned': register_aligned,
            'source_only': score(truth, source_alert),
            'register_only': score(truth, register_alert),
            'union': score(truth, source_alert | register_alert),
            'scope': 'Post-hoc source/target/function/unit/start-register metadata policy from S0; IP spoofable; no write authenticity, TCP reassembly, or intent verification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--output')
    args = parser.parse_args()
    names = ['S0_benign_baseline', 'S1_industroyer_pv', 'S2_industroyer_bss',
             'S3_arp_spoof_bss_meter_half_values', 'S4_arp_spoof_loads_pv_two_phase',
             'S5_arp_spoof_loads_pv_bss_two_phase', 'S6_mqtt_supply_chain_compromise',
             'S1_industroyer_pv_alt']
    reports = []
    with zipfile.ZipFile(args.archive) as archive:
        source_allow = set(authorized_from_inventory(archive))
        with archive.open('data4cyber_dataset/S0_benign_baseline/dataset.csv') as data:
            baseline_times = pd.read_csv(data, usecols=['timestamp'])['timestamp']
        holdout_start = int(len(baseline_times) * 0.8)
        train_stop = pd.to_datetime(baseline_times.iloc[holdout_start - 1], utc=True).timestamp()
        with archive.open('data4cyber_dataset/S0_benign_baseline/network_tap.pcapng') as source:
            baseline = [(stamp, signature) for stamp, signature in parse_writes(source)
                        if stamp <= train_stop]
        address_allow = {signature[1:] for _, signature in baseline
                         if signature[0] in source_allow}
        print(json.dumps({'training': 'S0 chronological first 80% packet metadata only',
                          'S0_holdout_start_row': holdout_start,
                          'authorized_source_count': len(source_allow),
                          'observed_write_register_signatures': len(address_allow),
                          'decoded_S0_write_packets': len(baseline),
                          'policy': 'Conservative observed-only signature; no S1-S6 labels used for fit'}))
        for name in names:
            report = audit(archive, name, source_allow, address_allow,
                           holdout_start if name == 'S0_benign_baseline' else 0)
            reports.append(report)
            print(json.dumps(report))
    if args.output:
        from pathlib import Path
        Path(args.output).write_text('\n'.join(json.dumps(row) for row in reports) + '\n', encoding='utf8')


if __name__ == '__main__':
    main()
