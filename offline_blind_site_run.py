"""Two-stage offline blind-site research evaluation: freeze predictions, then score.

Stage 1 never opens truth labels. Stage 2 refuses any changed inputs, policy,
observations, prediction, or seal. This is reproducibility plumbing, not proof
of independently adjudicated truth, actual site separation, or honest blinding.
"""
import argparse
import hashlib
import json
from pathlib import Path

from offline_four_lane_replay import load_frozen_policy, replay, load_hashed_json
from offline_observation_ingest import from_events, read_frozen_jsonl
from offline_selective_validation import score


def encode(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('utf8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_exclusive(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data)


def prepare(policy_path, policy_hash, events_path, events_hash, output_directory):
    destination = Path(output_directory)
    if destination.exists():
        raise FileExistsError('Refusing to reuse/overwrite a prior blind run directory')
    policy, verified_policy_hash = load_frozen_policy(policy_path, policy_hash)
    events, verified_events_hash = read_frozen_jsonl(events_path, events_hash)
    rows = from_events(policy['site_id'], events)
    observations = {'schema_version': 1, 'mode': 'research_only', 'site_id': policy['site_id'],
                    'source_events_sha256': verified_events_hash,
                    'frozen_policy_sha256': verified_policy_hash, 'records': rows}
    observation_bytes = encode(observations)
    prediction = replay(policy, rows)
    prediction['frozen_policy_sha256'] = verified_policy_hash
    prediction['observations_sha256'] = digest(observation_bytes)
    prediction_bytes = encode(prediction)
    seal = {'protocol_version': 1, 'site_id': policy['site_id'],
            'policy_sha256': verified_policy_hash, 'events_sha256': verified_events_hash,
            'observations_sha256': digest(observation_bytes),
            'replay_sha256': digest(prediction_bytes),
            'commitment': 'Prepared without opening attack truth; independently verify timing and custody.'}
    # All required validation happens before any output is created.
    destination.mkdir(parents=False, exist_ok=False)
    write_exclusive(destination / 'observations.json', observation_bytes)
    write_exclusive(destination / 'replay.json', prediction_bytes)
    write_exclusive(destination / 'seal.json', encode(seal))
    return seal


def unblind(directory, seal_hash, truth_path, truth_hash, output_path):
    directory = Path(directory).resolve()
    result_path = Path(output_path).resolve()
    if result_path.exists():
        raise FileExistsError('Refusing to overwrite previous score')
    # Restrict result files to a committed, known set within this directory.
    seal, verified_seal_hash = load_hashed_json(directory / 'seal.json', seal_hash, 'Prediction seal')
    if seal.get('protocol_version') != 1:
        raise ValueError('Invalid seal schema')
    observations, observation_hash = load_hashed_json(directory / 'observations.json', seal['observations_sha256'], 'Observations')
    replay_doc, replay_hash = load_hashed_json(directory / 'replay.json', seal['replay_sha256'], 'Replay')
    if observations.get('source_events_sha256') != seal['events_sha256']:
        raise ValueError('Event commitment mismatch')
    if observations.get('frozen_policy_sha256') != seal['policy_sha256']:
        raise ValueError('Policy commitment mismatch')
    if replay_doc.get('frozen_policy_sha256') != seal['policy_sha256'] or replay_doc.get('observations_sha256') != observation_hash:
        raise ValueError('Replay commitment mismatch')
    if replay_doc.get('site_id') != seal.get('site_id') or observations.get('site_id') != seal.get('site_id'):
        raise ValueError('Sealed site mismatch')
    if replay_doc.get('records') is None or observations.get('records') is None:
        raise ValueError('Records missing')
    if [v.get('timestamp_utc') for v in replay_doc['records']] != [v.get('timestamp_utc') for v in observations['records']]:
        raise ValueError('Replay-observation alignment mismatch')
    # Only now do we open independent attack truth.
    truth, verified_truth_hash = load_hashed_json(truth_path, truth_hash, 'Independent labels')
    result = score(replay_doc, truth)
    result.update({'prediction_seal_sha256': verified_seal_hash,
                   'frozen_policy_sha256': seal['policy_sha256'],
                   'events_sha256': seal['events_sha256'],
                   'observations_sha256': observation_hash,
                   'replay_sha256': replay_hash,
                   'truth_sha256': verified_truth_hash,
                   'adjudication_reference': truth['adjudication_reference']})
    write_exclusive(result_path, encode(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    first = sub.add_parser('prepare', help='Freeze replay with no truth-label input')
    first.add_argument('--policy', type=Path, required=True)
    first.add_argument('--policy-sha256', required=True)
    first.add_argument('--events', type=Path, required=True)
    first.add_argument('--events-sha256', required=True)
    first.add_argument('--directory', type=Path, required=True)
    second = sub.add_parser('unblind', help='Only after externally recording seal SHA-256')
    second.add_argument('--directory', type=Path, required=True)
    second.add_argument('--seal-sha256', required=True)
    second.add_argument('--truth', type=Path, required=True)
    second.add_argument('--truth-sha256', required=True)
    second.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        print(json.dumps(prepare(args.policy, args.policy_sha256, args.events,
                                 args.events_sha256, args.directory), indent=2))
    else:
        print(json.dumps(unblind(args.directory, args.seal_sha256, args.truth,
                                 args.truth_sha256, args.output), indent=2))


if __name__ == '__main__':
    main()
