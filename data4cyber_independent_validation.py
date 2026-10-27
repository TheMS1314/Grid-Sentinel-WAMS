"""Data4Cyber v3 independent-scenario audit. No data modification or grid interaction.

IsolationForest learns from chronological benign S0 only. Its threshold comes from
an entirely separate S0 calibration interval, then no test labels influence it.
The attack folders are distinct scenario campaigns, not IID independent sites.
"""
import argparse
import json
import zipfile

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import make_pipeline


def load_scenarios(path):
    with zipfile.ZipFile(path) as archive:
        members = sorted(x for x in archive.namelist() if x.endswith('/dataset.csv'))
        out = {}
        for member in members:
            name = member.split('/')[-2]
            if name.endswith('_alt'):
                continue  # explicitly outside publisher's primary S0--S6 experiment
            out[name] = pd.read_csv(archive.open(member), low_memory=False)
    return out


def physical_columns(frame, include_context=False):
    # Do not feed ground truth, clock, experiment profiles, or communications
    # sequence numbers into the model. The physical meter values are available
    # in all scenarios but may still shift under normal operating variation.
    prefixes = ('BSS-Inverter-AC-Meter.', 'Load-A-AC-Meter.',
                'Load-B-AC-Meter.', 'PV-Inverter-AC-Meter.',
                'Substation-AC-Meter.')
    cols = [c for c in frame if c.startswith(prefixes)
            and not c.endswith(('.phase_seq', '.realtime'))]
    if include_context:
        cols.extend(c for c in ('Battery-SOC-Reference.soc_value',
                                'Battery-SOC-Reported.soc_value',
                                'MQTT-Price-Signal.price_eur_per_kwh') if c in frame)
    return cols


def values(frame, cols):
    return frame[cols].apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan)


def scores(train, evaluation):
    # Independent normalization is forbidden: it would erase test anomalies.
    model = make_pipeline(SimpleImputer(strategy='median', add_indicator=False),
                          IsolationForest(n_estimators=250, max_samples=min(512, len(train)),
                                          contamination='auto', random_state=20261025,
                                          n_jobs=-1))
    model.fit(train)
    return model, lambda x: -model.decision_function(x)


def metrics(truth, preds):
    p, r, f, _ = precision_recall_fscore_support(truth, preds, average='binary',
                                                 zero_division=0)
    tn = int(np.sum((~truth) & (~preds)))
    fp = int(np.sum((~truth) & preds))
    fn = int(np.sum(truth & (~preds)))
    tp = int(np.sum(truth & preds))
    return dict(rows=int(len(truth)), positive_rows=int(truth.sum()), tp=tp, fp=fp,
                tn=tn, fn=fn, precision=round(float(p), 4),
                recall=round(float(r), 4), f1=round(float(f), 4),
                false_positive_rate=round(fp / max(1, fp + tn), 4))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--calibration-quantile', type=float, default=0.99)
    parser.add_argument('--adapt-prefix', type=int, default=0,
                        help='Optional 300-row presumed-safe scenario warmup: first 200 fit, '
                             'next 100 calibration, rest prospective test. Research only.')
    parser.add_argument('--include-context', action='store_true',
                        help='Ablation: add published MQTT price and two SOC state streams')
    args = parser.parse_args()
    scenario = load_scenarios(args.archive)
    benign = scenario['S0_benign_baseline']
    cols = physical_columns(benign, args.include_context)
    n = len(benign)
    cuts = (int(n * .6), int(n * .8))
    train = values(benign.iloc[:cuts[0]], cols)
    calibrate = values(benign.iloc[cuts[0]:cuts[1]], cols)
    _, score = scores(train, calibrate)
    threshold = float(np.quantile(score(calibrate), args.calibration_quantile))
    print(json.dumps({'protocol': 'S0 chronological first 60% train, next 20% '
                       'threshold, last 20% independent clean test; S1-S6 untouched',
                      'feature_count': len(cols), 'context_inputs': args.include_context,
                      'threshold_quantile': args.calibration_quantile,
                      'threshold': round(threshold, 6),
                      'clean_split_rows': [cuts[0], cuts[1] - cuts[0], n - cuts[1]]}))
    for name, frame in scenario.items():
        if name == 'S0_benign_baseline':
            frame = frame.iloc[cuts[1]:]
        elif args.adapt_prefix:
            if args.adapt_prefix < 100 or args.adapt_prefix >= len(frame):
                raise ValueError('Adapt prefix must be >=100 and shorter than the scenario')
            fit_end = args.adapt_prefix * 2 // 3
            warmup = frame.iloc[:args.adapt_prefix]
            if warmup['attack_active'].astype(bool).any():
                raise ValueError(f'{name}: warmup includes labeled attack activity')
            fit_x = values(warmup.iloc[:fit_end], cols)
            cal_x = values(warmup.iloc[fit_end:], cols)
            _, adapt_score = scores(fit_x, cal_x)
            adapt_threshold = float(np.quantile(adapt_score(cal_x), args.calibration_quantile))
            frame = frame.iloc[args.adapt_prefix:]
        y = frame['attack_active'].astype(bool).to_numpy()
        if args.adapt_prefix and name != 'S0_benign_baseline':
            result = adapt_score(values(frame, cols))
            pred = result > adapt_threshold
        else:
            result = score(values(frame, cols))
            pred = result > threshold
        report = metrics(y, pred)
        if len(np.unique(y)) == 2:
            report['roc_auc'] = round(float(roc_auc_score(y, result)), 4)
        # Distinguish attacking interval from an indicator of physical impact.
        report.update(scenario=name, score_p50=round(float(np.median(result)), 4),
                      score_p99=round(float(np.quantile(result, .99)), 4))
        if args.adapt_prefix and name != 'S0_benign_baseline':
            report.update(warmup_unscored_rows=args.adapt_prefix,
                          warmup_verified_benign=True,
                          threshold=round(adapt_threshold, 6))
        print(json.dumps(report))


if __name__ == '__main__':
    main()
