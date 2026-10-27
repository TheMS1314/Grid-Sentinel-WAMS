"""Post-hoc four-lane OT defense fusion on published Data4Cyber campaigns.

Research only: architecture and persistence durations were selected after
the scenario outcomes were examined, so even high F1 is NOT blind generalization.
No attack traffic is generated and no model is deployed.
"""
import argparse
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from data4cyber_arp_policy_sweep import alert_episodes
from data4cyber_modbus_allowlist_benchmark import authorized_from_inventory, score_scenario
from data4cyber_passive_arp_audit import evaluate as arp_evaluate, known_mapping
from data4cyber_s6_price_shift_audit import calibrate as price_calibrate, classify as price_classify
from data4cyber_two_lane_benchmark import score
from data4cyber_temporal_false_alerts import attribute_false_alerts
from smartgrid_phase22_reliability import replay


SCENARIOS = ('S0_benign_baseline', 'S1_industroyer_pv', 'S2_industroyer_bss',
             'S3_arp_spoof_bss_meter_half_values', 'S4_arp_spoof_loads_pv_two_phase',
             'S5_arp_spoof_loads_pv_bss_two_phase', 'S6_mqtt_supply_chain_compromise',
             'S1_industroyer_pv_alt')
LANE_NAMES = ('physics', 'modbus_source_hold5', 'arp_claim_hold2', 'price_domain')


def fusion(physics, modbus, arp, price):
    sizes = {len(x) for x in (physics, modbus, arp, price)}
    if len(sizes) != 1:
        raise ValueError('Lane arrays must share an observation timeline')
    return (np.asarray(physics, bool) | np.asarray(modbus, bool) |
            np.asarray(arp, bool) | np.asarray(price, bool))


def ablate_lanes(truth, lanes):
    """Fixed leave-one-lane-out and uniquely attributable row contributions."""
    if set(lanes) != set(LANE_NAMES):
        raise ValueError('Exact four research lanes required')
    if len({len(x) for x in lanes.values()} | {len(truth)}) != 1:
        raise ValueError('Ablation lanes must share the ground-truth timeline')
    masks = {name: np.asarray(flags, bool) for name, flags in lanes.items()}
    truth = np.asarray(truth, bool)
    all_alerts = np.logical_or.reduce(list(masks.values()))
    report = {}
    for omitted in LANE_NAMES:
        remaining = np.logical_or.reduce([masks[name] for name in LANE_NAMES if name != omitted])
        exclusive = all_alerts & ~remaining
        report[omitted] = {
            'without_lane': score(truth, remaining),
            'exclusive_true_positive_rows': int(np.sum(exclusive & truth)),
            'exclusive_false_positive_rows': int(np.sum(exclusive & ~truth)),
        }
    return report


def run(archive, model):
    with archive.open('data4cyber_dataset/S0_benign_baseline/dataset.csv') as source:
        baseline = pd.read_csv(source, low_memory=False)
    price_policy, cutoff = price_calibrate(baseline)
    allowed_modbus = authorized_from_inventory(archive)
    arp_inventory = known_mapping(archive)
    records = []
    for name in SCENARIOS:
        if name == 'S0_benign_baseline':
            frame = baseline
        else:
            with archive.open(f'data4cyber_dataset/{name}/dataset.csv') as source:
                frame = pd.read_csv(source, low_memory=False)
        physics = replay(frame, model)[2]
        modbus_meta, modbus = score_scenario(archive, name, allowed_modbus,
                                             hold_seconds=5, return_alerts=True)
        arp_meta, arp = arp_evaluate(archive, name, arp_inventory, hold_seconds=2,
                                     return_flags=True)
        price, observed_price = price_classify(frame, price_policy)
        if name == 'S0_benign_baseline':
            frame = frame.iloc[cutoff:].copy()
            physics, modbus, arp, price = (x[cutoff:] for x in (physics, modbus, arp, price))
            observed_price = observed_price[cutoff:]
        truth = frame['attack_active'].astype(bool).to_numpy()
        alarms = fusion(physics, modbus, arp, price)
        lane_masks = dict(zip(LANE_NAMES, (physics, modbus, arp, price)))
        ablation = ablate_lanes(truth, lane_masks)
        stamps = pd.to_datetime(frame['timestamp'], utc=True).astype('int64').to_numpy() / 1e9
        records.append({
            'scenario': name, 'rows': len(frame),
            'physics': score(truth, physics),
            'modbus_source_hold5': score(truth, modbus),
            'arp_claim_hold2': score(truth, arp),
            'price_domain': score(truth, price),
            'four_lane_or': score(truth, alarms),
            'leave_one_lane_out': ablation,
            'clean_alert_episodes': alert_episodes(alarms & ~truth, stamps),
            'false_alert_temporal_attribution': attribute_false_alerts(truth, alarms, stamps),
            'price_observed_rows': int(np.sum(observed_price)),
            'modbus_unauthorized_writes': modbus_meta['suspicious_write_requests'],
            'arp_identity_mismatch_packets': arp_meta['known_ip_mac_mismatch_packets'],
            'interpretation': 'POSTHOC multi-scenario architecture selection; source-IP and ARP claims are unauthenticated; price lane is regime novelty, not publisher authenticity.'
        })
    primary = [x for x in records if x['scenario'] not in ('S0_benign_baseline', 'S1_industroyer_pv_alt')]
    macro = float(np.mean([x['four_lane_or']['f1'] for x in primary]))
    ablation_summary = {
        name: {
            'macro_f1_without_lane': round(float(np.mean([
                row['leave_one_lane_out'][name]['without_lane']['f1'] for row in primary])), 5),
            'exclusive_attack_rows_across_S1_S6': sum(
                row['leave_one_lane_out'][name]['exclusive_true_positive_rows'] for row in primary),
            'exclusive_benign_alert_rows_across_S1_S6': sum(
                row['leave_one_lane_out'][name]['exclusive_false_positive_rows'] for row in primary),
        } for name in LANE_NAMES
    }
    return {'research_status': 'EXPLORATORY_POSTHOC_NOT_DEPLOYED',
            'calibration': {'price_S0_first_60_percent': True,
                            'price_threshold_S0_next_20_percent': True,
                            'physics_model_frozen': True,
                            'modbus_source_hold_seconds': 5, 'arp_claim_hold_seconds': 2},
            'macro_F1_S1_through_S6': round(macro, 5),
            'leave_one_lane_out_macro': ablation_summary,
            'warning': 'Macro F1 reuses previously examined attack scenarios and after-the-fact lane/persistence choices. No site-transfer or blind-test claim.',
            'scenarios': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--model', default='smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json')
    parser.add_argument('--output')
    args = parser.parse_args()
    model = json.loads(Path(args.model).read_text())
    with zipfile.ZipFile(args.archive) as archive:
        result = run(archive, model)
    content = json.dumps(result, indent=2) + '\n'
    print(content)
    if args.output:
        Path(args.output).write_text(content, encoding='utf8')


if __name__ == '__main__':
    main()
