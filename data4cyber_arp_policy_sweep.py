"""Post-hoc causal ARP persistence sensitivity, not a trained/deployed policy.

Reports attack-phase coverage and clean alert burden. All sweep candidates were
evaluated after viewing the campaigns; none constitutes independent validation.
"""
import argparse
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from data4cyber_passive_arp_audit import evaluate, known_mapping
from data4cyber_two_lane_benchmark import score
from smartgrid_phase22_reliability import replay, streaks


SCENARIOS = (
    'S0_benign_baseline', 'S3_arp_spoof_bss_meter_half_values',
    'S4_arp_spoof_loads_pv_two_phase',
    'S5_arp_spoof_loads_pv_bss_two_phase',
)


def alert_episodes(flags, stamps):
    """Count contiguous runs of alert seconds; retain seconds and maximum length."""
    runs = streaks(np.asarray(flags, dtype=bool), np.asarray(stamps))
    durations = [int(hi - lo + 1) for lo, hi in runs]
    return {'episodes': len(runs), 'alert_seconds': int(np.sum(flags)),
            'longest_episode_seconds': max(durations, default=0)}


def per_phase(df, physics, arp):
    out = {}
    phase = df['attack_phase'].astype(str).to_numpy()
    truth = df['attack_active'].astype(bool).to_numpy()
    for name in sorted(set(phase[truth])):
        mask = (phase == name) & truth
        out[name] = {'labeled_seconds': int(mask.sum()),
                     'physics_detected_seconds': int(np.sum(physics & mask)),
                     'arp_detected_seconds': int(np.sum(arp & mask)),
                     'or_detected_seconds': int(np.sum((physics | arp) & mask))}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--model', default='smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json')
    parser.add_argument('--holds', type=int, nargs='+', default=[0, 1, 2, 3, 4, 5])
    parser.add_argument('--output')
    args = parser.parse_args()
    if not args.holds or any(h < 0 or h > 30 for h in args.holds):
        parser.error('--holds must be integers from 0 through 30')
    model = json.loads(Path(args.model).read_text())
    output = []
    with zipfile.ZipFile(args.archive) as archive:
        inventory = known_mapping(archive)
        for scenario in SCENARIOS:
            df = pd.read_csv(archive.open(f'data4cyber_dataset/{scenario}/dataset.csv'), low_memory=False)
            physics = replay(df, model)[2]
            for hold in args.holds:
                arp_report, arp = evaluate(archive, scenario, inventory, hold, return_flags=True)
                work = df
                if scenario == 'S0_benign_baseline':
                    cutoff = int(.8 * len(df))
                    work, physics_slice, arp_slice = df.iloc[cutoff:], physics[cutoff:], arp[cutoff:]
                else:
                    physics_slice, arp_slice = physics, arp
                truth = work['attack_active'].astype(bool).to_numpy()
                combined = physics_slice | arp_slice
                clean = ~truth
                stamps = pd.to_datetime(work['timestamp'], utc=True).astype('int64').to_numpy() / 1e9
                item = {'scenario': scenario, 'arp_hold_seconds': hold,
                        'physics': score(truth, physics_slice),
                        'arp': score(truth, arp_slice),
                        'combined': score(truth, combined),
                        'clean_alert_burden': alert_episodes(combined & clean, stamps),
                        'per_phase': per_phase(work, physics_slice, arp_slice),
                        'mismatched_arp_packets': arp_report['known_ip_mac_mismatch_packets'],
                        'status': 'POSTHOC_SENSITIVITY_ONLY_NOT_DEPLOYED',
                        'caveat': 'S0 has no observed ARP identity mismatches. In-scenario benign rows may neighbor attacks; no independent clean-site validation.'}
                output.append(item)
                print(json.dumps(item))
    if args.output:
        Path(args.output).write_text(''.join(json.dumps(row) + '\n' for row in output), encoding='utf8')


if __name__ == '__main__':
    main()
