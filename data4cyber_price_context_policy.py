"""Compare security-only triage vs price-included OR, using frozen Phase36 data.

Historical leave-one-lane-out records are reused. This is a *policy design*
analysis, not new model training, blind validation, or label-confirmed intent.
"""
import argparse
import json
from pathlib import Path


def compare(research, stress):
    if research.get('research_status') != 'EXPLORATORY_POSTHOC_NOT_DEPLOYED':
        raise ValueError('Expected historical four-lane report')
    if stress.get('status') != 'S0_BENIGN_SYNTHETIC_TARIFF_SHIFT_NEGATIVE_CONTROL':
        raise ValueError('Expected isolated S0 price-offset audit')
    scenarios = research['scenarios']
    primary = [r for r in scenarios if r['scenario'].startswith(('S1_', 'S2_', 'S3_', 'S4_', 'S5_', 'S6_')) and not r['scenario'].endswith('_alt')]
    if len(primary) != 6:
        raise ValueError('Expected exactly six primary scenarios')
    results = []
    for item in primary:
        all_lanes = item['four_lane_or']
        no_price = item['leave_one_lane_out']['price_domain']
        security = no_price['without_lane']
        if any(all_lanes[key] < security[key] for key in ('tp', 'fp')):
            raise ValueError('A logical OR cannot have fewer positive rows than its ablation')
        if all_lanes['tp'] - security['tp'] != no_price['exclusive_true_positive_rows']:
            raise ValueError('Exclusive attack counts disagree with ablation')
        if all_lanes['fp'] - security['fp'] != no_price['exclusive_false_positive_rows']:
            raise ValueError('Exclusive benign counts disagree with ablation')
        results.append({'scenario': item['scenario'],
                        'full_or_f1': all_lanes['f1'], 'security_only_f1': security['f1'],
                        'full_or_tp': all_lanes['tp'], 'security_only_tp': security['tp'],
                        'full_or_fp': all_lanes['fp'], 'security_only_fp': security['fp'],
                        'price_only_attack_review_rows': no_price['exclusive_true_positive_rows'],
                        'price_only_benign_review_rows': no_price['exclusive_false_positive_rows']})
    policy_ablation = research['leave_one_lane_out_macro']['price_domain']
    if sum(r['price_only_attack_review_rows'] for r in results) != policy_ablation['exclusive_attack_rows_across_S1_S6']:
        raise ValueError('Macro price-exclusive attack counts disagree')
    if sum(r['price_only_benign_review_rows'] for r in results) != policy_ablation['exclusive_benign_alert_rows_across_S1_S6']:
        raise ValueError('Macro price-exclusive benign counts disagree')
    return {'status': 'POSTHOC_PRICE_CONTEXT_POLICY_TRADEOFF_NOT_DEPLOYED',
            'full_or_macro_f1': research['macro_F1_S1_through_S6'],
            'security_only_macro_f1': policy_ablation['macro_f1_without_lane'],
            'security_only_lanes': ['physics', 'modbus_source_hold5', 'arp_claim_hold2'],
            'price_lane_treatment': 'CONTEXT_REVIEW_ONLY_NOT_SECURITY_VERDICT',
            'price_exclusive_attack_rows_not_security_alerted': policy_ablation['exclusive_attack_rows_across_S1_S6'],
            'price_exclusive_benign_alert_rows_not_security_alerted': policy_ablation['exclusive_benign_alert_rows_across_S1_S6'],
            'scenarios': results,
            'benign_price_offset_stress': stress['results'],
            'warning': 'Security-only path loses many S6 labeled attack rows; price-only context is still surfaced, not hidden. Entire comparison uses previously examined scenarios. S0 shifted offsets are synthetic and price-lane-only; other lane response under those shifts was not replayed. No live model was changed.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research', type=Path, default=Path('smartgrid_platform/backend/model/phase36_four_lane_results.json'))
    parser.add_argument('--stress', type=Path, default=Path('reports/SmartGrid_Phase44_Price_Shift_Stress_2026-10-26.json'))
    parser.add_argument('--output', type=Path, help='Refuses overwrite')
    args = parser.parse_args()
    result = compare(json.loads(args.research.read_text()), json.loads(args.stress.read_text()))
    payload = json.dumps(result, indent=2) + '\n'
    if args.output:
        with args.output.open('x', encoding='utf8') as stream:
            stream.write(payload)
    else:
        print(payload, end='')


if __name__ == '__main__':
    main()
