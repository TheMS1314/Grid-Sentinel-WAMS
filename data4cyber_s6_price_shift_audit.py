"""S0-calibrated S6 price domain-shift negative control (NOT a causal IDS).

An intentionally simple novelty flag can appear excellent if the entire S6
scenario uses a different price regime before the first labeled attack.
"""
import argparse
import json
import zipfile

import numpy as np
import pandas as pd

from data4cyber_modbus_register_audit import score


PRICE = 'MQTT-Price-Signal.price_eur_per_kwh'


def calibrate(frame):
    n = len(frame)
    train_stop, cal_stop = int(n * .6), int(n * .8)
    price = pd.to_numeric(frame[PRICE], errors='coerce')
    train = price.iloc[:train_stop].dropna().to_numpy(float)
    cal = price.iloc[train_stop:cal_stop].dropna().to_numpy(float)
    if len(train) < 30 or len(cal) < 20:
        raise ValueError('Not enough observed S0 price samples for calibration')
    center = float(np.median(train))
    scale = max(float(np.quantile(np.abs(train - center), .9)), .001)
    threshold = float(np.quantile(np.abs(cal - center) / scale, .99))
    return (center, scale, threshold), cal_stop


def classify(frame, frozen):
    center, scale, threshold = frozen
    price = pd.to_numeric(frame[PRICE], errors='coerce').to_numpy(float)
    observed = np.isfinite(price)
    flags = observed & (np.abs(price - center) / scale > threshold)
    return flags, observed


def audit(archive):
    frames = {}
    names = ('S0_benign_baseline', 'S1_industroyer_pv', 'S2_industroyer_bss',
             'S3_arp_spoof_bss_meter_half_values', 'S4_arp_spoof_loads_pv_two_phase',
             'S5_arp_spoof_loads_pv_bss_two_phase', 'S6_mqtt_supply_chain_compromise',
             'S1_industroyer_pv_alt')
    for name in names:
        with archive.open(f'data4cyber_dataset/{name}/dataset.csv') as source:
            frames[name] = pd.read_csv(source, low_memory=False)
    frozen, holdout = calibrate(frames['S0_benign_baseline'])
    reports = []
    for name, frame in frames.items():
        if name == 'S0_benign_baseline':
            frame = frame.iloc[holdout:].copy()
        flags, observed = classify(frame, frozen)
        truth = frame['attack_active'].astype(bool).to_numpy()
        result = score(truth, flags)
        result.update(scenario=name, total_rows=len(frame),
                      observed_price_rows=int(observed.sum()),
                      observed_price_fraction=round(float(observed.mean()), 5),
                      min_observed_price=float(pd.to_numeric(frame[PRICE], errors='coerce').min()),
                      max_observed_price=float(pd.to_numeric(frame[PRICE], errors='coerce').max()),
                      benign_observed_price_rows=int((~truth & observed).sum()),
                      benign_price_alert_rows=int((~truth & flags).sum()),
                      attack_observed_price_rows=int((truth & observed).sum()))
        if truth.any():
            labels = pd.to_datetime(frame['timestamp'], utc=True)
            first_attack = int(np.flatnonzero(truth)[0])
            last_attack = int(np.flatnonzero(truth)[-1])
            alarm_before = np.flatnonzero(flags & ~truth & (np.arange(len(frame)) < first_attack))
            alarm_after = np.flatnonzero(flags & ~truth & (np.arange(len(frame)) > last_attack))
            result['first_attack_timestamp'] = labels.iloc[first_attack].isoformat()
            result['pre_attack_alert_rows'] = int(len(alarm_before))
            result['post_attack_alert_rows'] = int(len(alarm_after))
            result['pre_attack_observed_benign_rows'] = int((observed[:first_attack] & ~truth[:first_attack]).sum())
            result['post_attack_observed_benign_rows'] = int((observed[last_attack + 1:] & ~truth[last_attack + 1:]).sum())
            result['first_pre_attack_alert_seconds_ahead'] = (
                round((labels.iloc[first_attack] - labels.iloc[alarm_before[0]]).total_seconds(), 3)
                if len(alarm_before) else None)
            result['per_attack_phase'] = {
                str(phase): {'rows': int((frame['attack_phase'] == phase).sum()),
                             'flagged': int(flags[(frame['attack_phase'] == phase).to_numpy()].sum())}
                for phase in frame['attack_phase'].dropna().unique()
            }
        reports.append(result)
    return {'training_only': 'S0 chronological first 60%; threshold S0 next 20%',
            'calibrated_center': round(frozen[0], 6),
            'calibrated_scale': round(frozen[1], 6),
            'calibrated_threshold': round(frozen[2], 6),
            'reports': reports,
            'interpretation': 'Price-regime novelty is NOT authenticated MQTT attack detection. Check cross-scenario clean false-alerts, post-attack residuals and missingness. Missing values abstain.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--output')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        result = audit(archive)
    printed = json.dumps(result, indent=2) + '\n'
    print(printed, end='')
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(printed, encoding='utf8')


if __name__ == '__main__':
    main()
