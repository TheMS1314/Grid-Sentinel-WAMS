"""Quantify benign alerts relative to nearby attack labels, without dropping any.

Descriptive only: temporal proximity is not proof an alert was caused by an
attack, and far-away normal samples are not an independent field data set.
"""
import numpy as np


def attribute_false_alerts(truth, alerts, unix_seconds, windows=(5.0, 30.0)):
    truth = np.asarray(truth, dtype=bool)
    alerts = np.asarray(alerts, dtype=bool)
    stamps = np.asarray(unix_seconds, dtype=float)
    if not (len(truth) == len(alerts) == len(stamps)) or not len(stamps):
        raise ValueError('Nonempty aligned arrays required')
    if not np.isfinite(stamps).all() or (np.diff(stamps) <= 0).any():
        raise ValueError('Strictly increasing finite timestamps required')
    first, second = windows
    if not (0 < first < second):
        raise ValueError('Temporal windows must be positive and increasing')
    clean = ~truth
    falsely_alerted = clean & alerts
    attack_times = stamps[truth]
    if not len(attack_times):
        return {
            'false_alert_rows_total': int(falsely_alerted.sum()),
            'attack_rows_total': 0,
            'within_5_seconds': 0,
            'between_5_and_30_seconds': 0,
            'farther_than_30_seconds': int(falsely_alerted.sum()),
            'nearest_attack_before_alert': 0,
            'nearest_attack_after_alert': 0,
            'far_clean_rows': int(clean.sum()),
            'far_clean_alert_rows': int(falsely_alerted.sum()),
            'far_clean_alert_rate': round(float(falsely_alerted.mean()), 6),
            'boundary_caveat': 'No attack labels in this run: far means no within-run attack, not independently proven clean operation.',
        }
    nearest_idx = np.searchsorted(attack_times, stamps)
    left_idx = np.clip(nearest_idx - 1, 0, len(attack_times) - 1)
    right_idx = np.clip(nearest_idx, 0, len(attack_times) - 1)
    left_distance = np.abs(stamps - attack_times[left_idx])
    right_distance = np.abs(stamps - attack_times[right_idx])
    prefer_left = left_distance <= right_distance
    dist = np.minimum(left_distance, right_distance)
    near = falsely_alerted & (dist <= first)
    intermediate = falsely_alerted & (dist > first) & (dist <= second)
    far = falsely_alerted & (dist > second)
    far_clean = clean & (dist > second)
    nearest_attack_time = np.where(prefer_left, attack_times[left_idx], attack_times[right_idx])
    return {
        'false_alert_rows_total': int(falsely_alerted.sum()),
        'attack_rows_total': int(truth.sum()),
        'within_5_seconds': int(near.sum()),
        'between_5_and_30_seconds': int(intermediate.sum()),
        'farther_than_30_seconds': int(far.sum()),
        'nearest_attack_before_alert': int((falsely_alerted & (nearest_attack_time < stamps)).sum()),
        'nearest_attack_after_alert': int((falsely_alerted & (nearest_attack_time > stamps)).sum()),
        'far_clean_rows': int(far_clean.sum()),
        'far_clean_alert_rows': int(far.sum()),
        'far_clean_alert_rate': round(float(far.sum() / far_clean.sum()), 6) if far_clean.any() else None,
        'boundary_caveat': 'Distance to attack label is descriptive, not causal. Do not exclude near-boundary alerts from primary FPR.',
    }
