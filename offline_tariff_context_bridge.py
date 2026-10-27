"""Strict read-only join between frozen four-lane replay and tariff signatures.

Never changes original replay statuses, thresholds, or model outputs. A signed
publisher's statement is not proof of honest intent or an uncompromised key.
"""
import argparse
import json
from pathlib import Path

from offline_four_lane_replay import load_hashed_json


def combine(replay_doc, signatures_doc):
    if replay_doc.get('status') != 'OFFLINE_FROZEN_POLICY_RESEARCH_ONLY':
        raise ValueError('Expected frozen four-lane replay')
    if signatures_doc.get('status') != 'OFFLINE_AUTHENTICATED_TARIFF_CONTEXT_NOT_DEPLOYED':
        raise ValueError('Expected offline tariff signature audit')
    if replay_doc.get('site_id') != signatures_doc.get('site_id'):
        raise ValueError('Site mismatch')
    replay_rows, signed_rows = replay_doc.get('records'), signatures_doc.get('records')
    if not isinstance(replay_rows, list) or not replay_rows or not isinstance(signed_rows, list) or len(replay_rows) != len(signed_rows):
        raise ValueError('One-to-one timestamp coverage is required; absent messages must abstain')
    statuses = {
        'SIGNED_PRICE_CONSISTENT_CONTEXT': 'SIGNED_BUT_NOVEL_CONTEXT',
        'SIGNED_VS_OBSERVED_PRICE_MISMATCH_REVIEW': 'PRICE_PATH_DIVERGENCE_REVIEW',
        'INVALID_SIGNATURE_REVIEW': 'UNVERIFIED_SIGNATURE_FAILURE_REVIEW',
        'REPLAY_OR_OUT_OF_ORDER_REVIEW': 'SIGNED_SEQUENCE_ANOMALY_REVIEW',
    }
    rows = []
    for replay, signed in zip(replay_rows, signed_rows):
        if replay.get('timestamp_utc') != signed.get('timestamp_utc'):
            raise ValueError('Tariff signatures and four-lane replay timestamps differ')
        flags = replay.get('lane_flags')
        if not isinstance(flags, dict) or set(flags) != {'physics', 'modbus', 'arp', 'price'}:
            raise ValueError('Four replay lane flags required')
        novel = flags['price']
        if type(novel) is not bool and novel is not None:
            raise ValueError('Price novelty flag must be true, false, or null')
        verification = signed.get('status')
        if verification not in statuses and verification not in (
                'NO_INDEPENDENT_PRICE_ABSTAIN', 'KEY_OUTSIDE_VALIDITY_ABSTAIN',
                'UNTRUSTED_SOURCE_ABSTAIN', 'UNKNOWN_KEY_ABSTAIN'):
            raise ValueError('Unsupported tariff verification status')
        if verification == 'SIGNED_PRICE_CONSISTENT_CONTEXT':
            category = 'SIGNED_BUT_NOVEL_CONTEXT' if novel is True else (
                'SIGNED_EXPECTED_CONTEXT' if novel is False else 'SIGNED_BUT_PRICE_LANE_UNOBSERVED')
        else:
            category = statuses.get(verification, 'TARIFF_PROVENANCE_ABSTAIN')
        rows.append({'timestamp_utc': replay['timestamp_utc'],
                     'four_lane_original_status': replay.get('status'),
                     'price_novelty': novel,
                     'tariff_signature_status': verification,
                     'price_context_category': category})
    return {'status': 'OFFLINE_TWO_TRACK_RESEARCH_CONTEXT_NOT_DEPLOYED',
            'site_id': replay_doc['site_id'], 'records': rows,
            'warning': 'Does not change original OR alerts. Signed price consistency never proves honest publisher intent; offline timestamps and site identity require independent provenance.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--replay-sha256', required=True)
    parser.add_argument('--tariff', type=Path, required=True)
    parser.add_argument('--tariff-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    replay, replay_hash = load_hashed_json(args.replay, args.replay_sha256, 'Four-lane replay')
    tariff, tariff_hash = load_hashed_json(args.tariff, args.tariff_sha256, 'Tariff audit')
    result = combine(replay, tariff)
    result['replay_sha256'] = replay_hash
    result['tariff_audit_sha256'] = tariff_hash
    with args.output.open('x', encoding='utf8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'rows': len(result['records'])}))


if __name__ == '__main__':
    main()
