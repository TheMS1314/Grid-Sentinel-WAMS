"""Blind-site offline replay scoring with explicit abstentions and truth hashes.

Do not interpret abstentions as benign predictions. This tool evaluates a
pre-frozen replay against separately adjudicated, hashed truth only after
predictions are committed. It cannot authenticate provenance or prove blinding.
"""
import argparse
import hashlib
import json
from pathlib import Path

from offline_four_lane_replay import parse_utc, load_hashed_json


def _bool(value, name):
    if type(value) is not bool:
        raise ValueError(f'{name} must be a boolean')
    return value


def score(replay_doc, truth_doc):
    if replay_doc.get('status') != 'OFFLINE_FROZEN_POLICY_RESEARCH_ONLY':
        raise ValueError('Expected frozen offline replay')
    if not isinstance(truth_doc, dict) or truth_doc.get('schema_version') != 1:
        raise ValueError('Truth must declare schema_version 1')
    if replay_doc.get('site_id') != truth_doc.get('site_id'):
        raise ValueError('Site IDs differ')
    if not isinstance(truth_doc.get('adjudication_reference'), str) or not truth_doc['adjudication_reference'].strip():
        raise ValueError('Independent adjudication reference required')
    predictions, labels = replay_doc.get('records'), truth_doc.get('records')
    if not isinstance(predictions, list) or not predictions or not isinstance(labels, list) or len(labels) != len(predictions):
        raise ValueError('Prediction and truth rows must be nonempty and one-to-one')
    tp = fp = tn = fn = abstain_attack = abstain_clean = 0
    previous = None
    seen = set()
    for idx, (prediction, label) in enumerate(zip(predictions, labels), 1):
        if not isinstance(prediction, dict) or not isinstance(label, dict):
            raise ValueError('Rows must be objects')
        timestamp = prediction.get('timestamp_utc')
        if timestamp != label.get('timestamp_utc'):
            raise ValueError(f'Timestamp mismatch in row {idx}')
        sec = parse_utc(timestamp)
        if previous is not None and sec <= previous:
            raise ValueError('Nonmonotonic or duplicate evaluation rows')
        previous = sec
        if timestamp in seen:
            raise ValueError('Duplicate time')
        seen.add(timestamp)
        truth = _bool(label.get('attack_active'), 'attack_active')
        state = prediction.get('status')
        positives = prediction.get('positive_lanes')
        unknowns = prediction.get('unknown_lanes')
        flags = prediction.get('lane_flags')
        if not isinstance(flags, dict) or set(flags) != {'physics', 'modbus', 'arp', 'price'}:
            raise ValueError('Four lane flags required')
        if any(type(v) is not bool and v is not None for v in flags.values()):
            raise ValueError('Lane flag values invalid')
        if positives != [k for k, v in flags.items() if v is True] or unknowns != [k for k, v in flags.items() if v is None]:
            raise ValueError('Lane flags disagree with lane lists')
        expected = ('REVIEW_UNVERIFIED' if positives else
                    'ABSTAIN_INCOMPLETE_VISIBILITY' if unknowns else 'NO_REVIEW_OBSERVED')
        if state != expected:
            raise ValueError('Status contradicts lane evidence')
        if unknowns and not positives:
            if truth:
                abstain_attack += 1
            else:
                abstain_clean += 1
        elif state == 'REVIEW_UNVERIFIED':
            tp += truth
            fp += not truth
        else:
            fn += truth
            tn += not truth
    n = len(predictions)
    decided = tp + fp + tn + fn
    def fraction(num, den):
        return None if not den else round(num / den, 6)
    return {
        'site_id': replay_doc['site_id'], 'rows': n,
        'decided_rows': decided, 'abstained_rows': abstain_attack + abstain_clean,
        'selective_coverage': fraction(decided, n),
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'abstained_attack_rows': abstain_attack, 'abstained_benign_rows': abstain_clean,
        'selective_precision': fraction(tp, tp + fp),
        'selective_recall': fraction(tp, tp + fn),
        'selective_f1': fraction(2 * tp, 2 * tp + fp + fn),
        'all_attack_recall_lower_bound': fraction(tp, tp + fn + abstain_attack),
        'all_attack_recall_upper_bound': fraction(tp + abstain_attack, tp + fn + abstain_attack),
        'alerted_benign_fraction': fraction(fp, fp + tn + abstain_clean),
        'warning': 'Research-only selective evaluation; abstentions excluded from selective F1, never counted as clean. Ground truth, collection completeness, and independent-site blinding require external verification.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', required=True, type=Path)
    parser.add_argument('--replay-sha256', required=True)
    parser.add_argument('--truth', required=True, type=Path)
    parser.add_argument('--truth-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Refusing to overwrite evaluation')
    replay_doc, replay_hash = load_hashed_json(args.replay, args.replay_sha256, 'Replay')
    truth_doc, truth_hash = load_hashed_json(args.truth, args.truth_sha256, 'Independent labels')
    if 'frozen_policy_sha256' not in replay_doc or 'observations_sha256' not in replay_doc:
        raise ValueError('Replay lacks frozen policy/observation hash commitments')
    result = score(replay_doc, truth_doc)
    result.update({'replay_sha256': replay_hash, 'truth_sha256': truth_hash,
                   'frozen_policy_sha256': replay_doc['frozen_policy_sha256'],
                   'observations_sha256': replay_doc['observations_sha256'],
                   'adjudication_reference': truth_doc['adjudication_reference']})
    with args.output.open('x', encoding='utf8') as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
        handle.write('\n')
    print(json.dumps({'output': str(args.output), 'selective_coverage': result['selective_coverage']}))


if __name__ == '__main__':
    main()
