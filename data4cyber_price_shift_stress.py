"""Counterfactual benign tariff-change sensitivity of the frozen S0 price lane.

Uses real held-out benign S0 price observations; only the tariff is shifted.
These shifts are synthetic, not verified tariff market events or cyberattacks.
Do not optimize the detector on this already seen public test dataset.
"""
import argparse
import json
import zipfile

import numpy as np
import pandas as pd

from data4cyber_s6_price_shift_audit import PRICE, calibrate

SHIFTS_EUR_PER_KWH = (-0.10, -0.05, -0.02, -0.01, 0.0, 0.01, 0.02, 0.05, 0.10)


def stress(price, frozen, shifts=SHIFTS_EUR_PER_KWH):
    values = np.asarray(price, dtype=float)
    observed = np.isfinite(values)
    center, scale, threshold = frozen
    if not observed.any() or scale <= 0 or threshold <= 0:
        raise ValueError('Valid observed prices and positive frozen calibration required')
    rows = []
    for shift in shifts:
        if not np.isfinite(shift):
            raise ValueError('Finite tariff shift required')
        alarms = observed & (np.abs(values + shift - center) / scale > threshold)
        rows.append({'additive_shift_eur_per_kwh': float(shift),
                     'observed_benign_seconds': int(observed.sum()),
                     'false_review_seconds': int(alarms.sum()),
                     'benign_false_review_fraction': round(float(alarms.sum() / observed.sum()), 6)})
    return rows


def run(archive):
    with archive.open('data4cyber_dataset/S0_benign_baseline/dataset.csv') as source:
        baseline = pd.read_csv(source, low_memory=False)
    policy, cutoff = calibrate(baseline)
    heldout = baseline.iloc[cutoff:]
    if bool(heldout['attack_active'].astype(bool).any()):
        raise ValueError('S0 holdout must be attack-free')
    values = pd.to_numeric(heldout[PRICE], errors='coerce').to_numpy(float)
    return {'status': 'S0_BENIGN_SYNTHETIC_TARIFF_SHIFT_NEGATIVE_CONTROL',
            'calibration_center_eur_per_kwh': round(policy[0], 6),
            'calibration_scale_eur_per_kwh': round(policy[1], 6),
            'calibration_threshold': round(policy[2], 6),
            'price_holdout_start_index': cutoff,
            'price_holdout_seconds': len(heldout),
            'results': stress(values, policy),
            'warning': 'Same topology and previously examined public S0. Artificial price offsets probe fragility only, not new attack detection, independent validation, or real-world prevalence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--output', help='Refuses to overwrite existing report')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        result = run(archive)
    content = json.dumps(result, indent=2) + '\n'
    if args.output:
        with open(args.output, 'x', encoding='utf8') as handle:
            handle.write(content)
    else:
        print(content, end='')


if __name__ == '__main__':
    main()
