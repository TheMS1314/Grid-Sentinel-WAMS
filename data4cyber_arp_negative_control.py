"""ARP IP/MAC mismatch stress-test on non-ARP attack campaigns.

This is an out-of-family *within-dataset* negative control, not independent
blind validation. Attack activity labels describe other threat classes;
ARP anomalies should not be automatically credited as true positives here.
"""
import argparse
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from data4cyber_passive_arp_audit import evaluate, known_mapping
from data4cyber_arp_policy_sweep import alert_episodes


CONTROLS = (
    'S0_benign_baseline',
    'S1_industroyer_pv', 'S1_industroyer_pv_alt',
    'S2_industroyer_bss', 'S6_mqtt_supply_chain_compromise',
)


def summarize(df, flags, scenario):
    if scenario == 'S0_benign_baseline':
        begin = int(.8 * len(df))
        df = df.iloc[begin:]
        flags = flags[begin:]
    attack = df['attack_active'].astype(bool).to_numpy()
    clean = ~attack
    stamps = pd.to_datetime(df['timestamp'], utc=True).astype('int64').to_numpy() / 1e9
    return {
        'total_seconds': int(len(df)),
        'clean_seconds': int(clean.sum()),
        'attack_activity_seconds': int(attack.sum()),
        'arp_alert_seconds_total': int(flags.sum()),
        'arp_alert_seconds_during_unrelated_attack': int((flags & attack).sum()),
        'arp_alert_seconds_during_clean': int((flags & clean).sum()),
        'clean_row_alert_rate': round(float((flags & clean).sum()) / max(1, int(clean.sum())), 6),
        'clean_alert_episodes': alert_episodes(flags & clean, stamps),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--holds', type=int, nargs='+', default=[0, 2, 5])
    parser.add_argument('--output')
    args = parser.parse_args()
    if not args.holds or any(hold < 0 or hold > 30 for hold in args.holds):
        parser.error('holds must be in [0,30]')
    output = []
    with zipfile.ZipFile(args.archive) as archive:
        inventory = known_mapping(archive)
        for scenario in CONTROLS:
            data = pd.read_csv(archive.open(f'data4cyber_dataset/{scenario}/dataset.csv'),
                               usecols=['timestamp', 'attack_active'])
            for hold in args.holds:
                arp_report, alert = evaluate(archive, scenario, inventory, hold, return_flags=True)
                record = {'scenario': scenario, 'arp_hold_seconds': hold,
                          'arp_packets_observed': arp_report['arp_packets_observed'],
                          'known_ip_mac_mismatch_packets': arp_report['known_ip_mac_mismatch_packets'],
                          **summarize(data, alert, scenario),
                          'status': 'WITHIN_DATASET_NON_ARP_NEGATIVE_CONTROL',
                          'warning': 'Unrelated attack activity is not a positive label for ARP-origin anomalies; IP/MAC claims are spoofable; no independent topology.'}
                output.append(record)
                print(json.dumps(record))
    if args.output:
        Path(args.output).write_text(''.join(json.dumps(x) + '\n' for x in output), encoding='utf8')


if __name__ == '__main__':
    main()
