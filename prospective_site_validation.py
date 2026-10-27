"""Strict, frozen, site-held-out evaluation of timestamped defender predictions.

Only evaluates exported predictions. Never trains, tunes thresholds, or interacts
with networks. Manifest and CSV formats are documented in the Phase 33 report.
"""
import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = {'timestamp_utc', 'attack_active', 'alert', 'event_id'}


def confined_path(root, relative_name):
    relative = Path(relative_name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Referenced path must remain inside evaluation directory')
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError('Referenced path escapes evaluation directory')
    return resolved


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def binary(value):
    if value not in ('0', '1'):
        raise ValueError('Labels/alerts must be exactly 0 or 1')
    return value == '1'


def ratio(a, b):
    return None if not b else round(a / b, 6)


def validate_manifest(doc):
    if doc.get('protocol_version') != 1:
        raise ValueError('Unsupported protocol_version')
    if not doc.get('frozen_model_sha256') or len(doc['frozen_model_sha256']) != 64:
        raise ValueError('Frozen model SHA256 required')
    if not isinstance(doc.get('frozen_model_path'), str) or not doc['frozen_model_path']:
        raise ValueError('Frozen model file path required for hash verification')
    if not doc.get('frozen_policy') or not isinstance(doc['frozen_policy'], dict):
        raise ValueError('Nonempty frozen_policy required')
    training = doc.get('training_site_ids')
    if not isinstance(training, list) or not training or len(set(training)) != len(training):
        raise ValueError('Explicit, unique training_site_ids required')
    runs = doc.get('evaluation_runs')
    if not isinstance(runs, list) or not runs:
        raise ValueError('At least one held-out evaluation_run required')
    ids = set()
    for run in runs:
        for field in ('run_id', 'site_id', 'csv_path', 'csv_sha256', 'provenance_reference'):
            if not isinstance(run.get(field), str) or not run[field].strip():
                raise ValueError(f'{field} is mandatory for each run')
        if run['run_id'] in ids:
            raise ValueError('Duplicate run_id')
        ids.add(run['run_id'])
        if run['site_id'] in training:
            raise ValueError('Training-site overlap: not an independent-site test')
        if len(run['csv_sha256']) != 64:
            raise ValueError('CSV SHA256 must be 64 hex characters')
        seconds = run.get('sample_seconds')
        if isinstance(seconds, bool) or not isinstance(seconds, (float, int)) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError('Positive finite sample_seconds required')


def evaluate(manifest_path):
    manifest_path = Path(manifest_path).resolve()
    doc = json.loads(manifest_path.read_text(encoding='utf-8'))
    validate_manifest(doc)
    model_path = confined_path(manifest_path.parent, doc['frozen_model_path'])
    if sha256(model_path).lower() != doc['frozen_model_sha256'].lower():
        raise ValueError('Frozen model checksum mismatch')
    results = []
    for run in doc['evaluation_runs']:
        data_path = confined_path(manifest_path.parent, run['csv_path'])
        if sha256(data_path).lower() != run['csv_sha256'].lower():
            raise ValueError(f"CSV checksum mismatch: {run['run_id']}")
        tp = fp = tn = fn = 0
        events = defaultdict(list)
        first_event_seen = {}
        first_event_alert = {}
        previous_time = None
        previous_false_alert = False
        false_alert_episodes = 0
        sample_seconds = run['sample_seconds']
        with data_path.open(newline='', encoding='utf-8') as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames):
                raise ValueError(f'Missing CSV headers: {REQUIRED - set(reader.fieldnames or [])}')
            for row in reader:
                stamp = row['timestamp_utc']
                if not stamp.endswith('Z'):
                    raise ValueError('UTC timestamps must end in Z')
                try:
                    instant = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                except ValueError as err:
                    raise ValueError('Invalid ISO8601 timestamp') from err
                if instant.tzinfo is None or instant.utcoffset().total_seconds() != 0:
                    raise ValueError('UTC timestamps required')
                if previous_time is not None:
                    gap = (instant - previous_time).total_seconds()
                    if gap <= 0:
                        raise ValueError('Timestamps must be strictly increasing')
                    if gap > sample_seconds * 1.5:
                        raise ValueError('Missing observations: time gap exceeds sample_seconds tolerance')
                previous_time = instant
                truth, alert = binary(row['attack_active']), binary(row['alert'])
                event = row['event_id'].strip()
                if truth and not event:
                    raise ValueError('Attack rows need a stable event_id')
                if not truth and event:
                    raise ValueError('Benign rows cannot have an event_id')
                tp += truth and alert
                fp += not truth and alert
                tn += not truth and not alert
                fn += truth and not alert
                false_alert = bool(not truth and alert)
                if false_alert and not previous_false_alert:
                    false_alert_episodes += 1
                previous_false_alert = false_alert
                if truth:
                    events[event].append(alert)
                    first_event_seen.setdefault(event, instant)
                    if alert:
                        first_event_alert.setdefault(event, instant)
        if previous_time is None:
            raise ValueError('Empty evaluation CSV')
        detected = sum(any(values) for values in events.values())
        clean_hours = (tn + fp) * run['sample_seconds'] / 3600
        event_latency = sorted(round((first_event_alert[e] - first_event_seen[e]).total_seconds(), 6)
                               for e in first_event_alert)
        results.append({
            'run_id': run['run_id'], 'site_id': run['site_id'],
            'rows': tp + fp + tn + fn, 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
            'f1': ratio(2 * tp, 2 * tp + fp + fn),
            'clean_hours': round(clean_hours, 6),
            'false_alert_seconds': round(fp * run['sample_seconds'], 6),
            'false_alerted_samples_per_clean_hour': ratio(fp, clean_hours),
            'false_alert_episodes': false_alert_episodes,
            'false_alert_episodes_per_clean_hour': ratio(false_alert_episodes, clean_hours),
            'attack_events': len(events), 'detected_events': detected,
            'event_detection_rate': ratio(detected, len(events)),
            'first_detection_latency_seconds': event_latency,
            'provenance_reference': run['provenance_reference'],
        })
    return {
        'protocol_version': 1, 'manifest_sha256': sha256(manifest_path),
        'frozen_model_sha256': doc['frozen_model_sha256'],
        'frozen_policy': doc['frozen_policy'], 'held_out_site_count': len({x['site_id'] for x in results}),
        'evaluation_run_count': len(results), 'runs': results,
        'interpretation': 'Site-level descriptive audit only. Provenance and labels require independent human verification; never infer performance from fixture tests.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', help='Optional results JSON; parent directory must exist')
    args = parser.parse_args()
    result = json.dumps(evaluate(args.manifest), indent=2, sort_keys=True) + '\n'
    if args.output:
        target = Path(args.output)
        if target.exists():
            raise ValueError('Refusing to overwrite existing evaluation output')
        target.write_text(result, encoding='utf-8')
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
