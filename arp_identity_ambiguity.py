"""Deterministic synthetic ARP identity-claim ambiguity demonstration.

The same observed ARP change can represent authorized NIC maintenance or an
unauthorized impersonation. No ARP-only deterministic detector can tell them
apart without independently verified change/provenance evidence.

This is a conceptual identifiability test, NOT a Data4Cyber benchmark.
"""
import argparse
import json
from pathlib import Path


TOTAL_SECONDS = 1200
EVENT_SECONDS = tuple(range(605, 656, 5))
CHANGE_START = 600
CHANGE_END = 660


def causal_flags(total_seconds, mismatched_claim_seconds, hold_seconds):
    """Pure, causal row-level hold: events alert on [t, t+hold] inclusive."""
    if total_seconds <= 0 or not 0 <= hold_seconds <= 30:
        raise ValueError('Invalid timeline or hold duration')
    flags = [False] * total_seconds
    for when in mismatched_claim_seconds:
        if not isinstance(when, int) or not 0 <= when < total_seconds:
            raise ValueError('Claim timestamp outside simulated capture')
        for second in range(when, min(total_seconds, when + hold_seconds + 1)):
            flags[second] = True
    return flags


def audit(holds=(0, 2, 5)):
    records = []
    for hold in holds:
        flags = causal_flags(TOTAL_SECONDS, EVENT_SECONDS, hold)
        # Both physical realities have identical passive ARP observations.
        benign_truth = [False] * TOTAL_SECONDS
        attack_truth = [CHANGE_START <= t < CHANGE_END for t in range(TOTAL_SECONDS)]
        maintenance_alerts = sum(flag and not truth for flag, truth in zip(flags, benign_truth))
        spoof_detections = sum(flag and truth for flag, truth in zip(flags, attack_truth))
        records.append({
            'hold_seconds': hold,
            'observed_mismatched_claims': len(EVENT_SECONDS),
            'synthetic_maintenance_false_alert_seconds': maintenance_alerts,
            'synthetic_spoof_attack_detected_seconds': spoof_detections,
            'synthetic_attack_labeled_seconds': sum(attack_truth),
            'identical_arp_observations': True,
            'policy_status': 'DO_NOT_DEPLOY_OR_FIT_FROM_SYNTHETIC',
        })
    return {
        'status': 'SYNTHETIC_IDENTIFIABILITY_COUNTEREXAMPLE',
        'sample_seconds': TOTAL_SECONDS,
        'change_window_seconds': CHANGE_END - CHANGE_START,
        'events_every_seconds': 5,
        'records': records,
        'conclusion': 'Observed ARP sender IP/MAC claims alone cannot distinguish a legitimate network interface change from impersonation when packet observations are identical.',
        'requirement': 'Independent, authenticated inventory-change provenance and operator review are required; never auto-learn changed MACs from ARP claims.',
        'warning': 'Synthetic thought experiment. Numbers are not field F1, dataset results, or estimates of real-world attack/maintenance frequency.',
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output')
    args = p.parse_args()
    result = audit()
    print(json.dumps(result, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')


if __name__ == '__main__':
    main()
