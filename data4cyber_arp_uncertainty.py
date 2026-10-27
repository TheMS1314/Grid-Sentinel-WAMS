"""Sensitivity of zero-alert claims to the assumed independent sampling unit.

These are *conditional, one-sided exact binomial bounds*, not field-certified
confidence intervals. Shared topology, serial dependence and post-hoc detector
selection invalidate treating seconds/packets as independent deployment trials.
"""
import argparse
import json
import math
from pathlib import Path


def upper_bound_zero_events(sample_count, confidence=.95):
    """Exact one-sided upper bound for 0 successes in independent Bernoulli trials."""
    if not isinstance(sample_count, int) or sample_count <= 0:
        raise ValueError('sample_count must be a positive integer')
    if not 0 < confidence < 1:
        raise ValueError('confidence must lie strictly between 0 and 1')
    return -math.expm1(math.log1p(-confidence) / sample_count)


def summarize(rows, confidence=.95):
    chosen = [r for r in rows if r['arp_hold_seconds'] == 2]
    names = [r['scenario'] for r in chosen]
    if len(names) != 5 or len(set(names)) != 5:
        raise ValueError('Expected exactly five distinct Phase 27 negative-control scenarios')
    if any(r['arp_alert_seconds_total'] != 0 or r['known_ip_mac_mismatch_packets'] != 0 for r in chosen):
        raise ValueError('This is specifically a zero-event audit; do not use zero-event formulas otherwise')
    seconds = sum(r['clean_seconds'] for r in chosen)
    packets = sum(r['arp_packets_observed'] for r in chosen)
    if seconds <= 0 or packets <= 0:
        raise ValueError('Missing observations')
    scenarios = len(chosen)
    return {
        'status': 'ASSUMPTION_SENSITIVITY_NOT_INDEPENDENT_VALIDATION',
        'confidence': confidence,
        'observed_clean_seconds': seconds,
        'observed_arp_packets': packets,
        'observed_scenarios': scenarios,
        'observed_arp_alert_seconds': 0,
        'hypothetical_iid_per_second_upper_rate': round(upper_bound_zero_events(seconds, confidence), 8),
        'hypothetical_iid_per_packet_upper_mismatch_rate': round(upper_bound_zero_events(packets, confidence), 8),
        'hypothetical_independent_scenario_upper_event_probability': round(upper_bound_zero_events(scenarios, confidence), 8),
        'warnings': [
            'Every confidence bound is conditional on independence and representative sampling, neither demonstrated here.',
            'Five scenario captures share one research topology; seconds and ARP packets are autocorrelated.',
            'The ARP rule was designed after examining these campaigns; these are not blind deployment trials.',
            'No prospective threshold or real-world false-alarm certification can be inferred.',
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--negative-controls', default='reports/SmartGrid_Phase27_NonARP_Negative_Control_2026-10-26.jsonl')
    p.add_argument('--confidence', type=float, default=.95)
    p.add_argument('--output')
    a = p.parse_args()
    rows = [json.loads(s) for s in Path(a.negative_controls).read_text(encoding='utf8').splitlines() if s.strip()]
    result = summarize(rows, a.confidence)
    print(json.dumps(result, indent=2))
    if a.output:
        Path(a.output).write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')


if __name__ == '__main__':
    main()
