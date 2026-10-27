"""Convert independently frozen *offline* JSONL events to four-lane replay rows.

This is a schema adapter, not packet capture, attack attribution or sensor
authentication. A coverage declaration must be supplied for each lane/second;
silence is never interpreted as a clean network. No external dependencies.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from offline_four_lane_replay import LANES, parse_utc, replay

MAX_EVENTS = 500000
MAX_SECONDS = 86400
MAX_LINE_BYTES = 16384


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f'Duplicate JSON field: {key}')
        obj[key] = value
    return obj


def read_frozen_jsonl(path, digest):
    raw = Path(path).read_bytes()
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdefABCDEF' for c in digest):
        raise ValueError('A precommitted 64-character input SHA-256 is required')
    actual = hashlib.sha256(raw).hexdigest()
    if digest.lower() != actual:
        raise ValueError('Offline event input hash mismatch')
    events = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if len(line) > MAX_LINE_BYTES:
            raise ValueError(f'Line {line_number} exceeds size limit')
        if not line.strip():
            raise ValueError(f'Blank line {line_number} is ambiguous')
        if line_number > MAX_EVENTS:
            raise ValueError('Too many input records')
        try:
            event = json.loads(line, object_pairs_hook=unique_object,
                               parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON constant')))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f'Invalid JSONL line {line_number}: {exc}') from exc
        if not isinstance(event, dict):
            raise ValueError(f'Line {line_number} must be an object')
        events.append(event)
    if not events:
        raise ValueError('Empty offline event file')
    return events, actual


def second_key(stamp):
    epoch = parse_utc(stamp)
    if int(epoch) != epoch:
        raise ValueError('Each event timestamp must align to a UTC second')
    return int(epoch)


def from_events(site_id, events):
    """Require one coverage heartbeat per lane/second in a bounded interval."""
    if not isinstance(site_id, str) or not site_id.strip():
        raise ValueError('site_id required')
    bins = {}
    first = last = None
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict) or event.get('site_id') != site_id:
            raise ValueError(f'Event {index} has missing/mismatched site_id')
        time = second_key(event.get('timestamp_utc'))
        first = time if first is None else min(first, time)
        last = time if last is None else max(last, time)
        if last - first + 1 > MAX_SECONDS:
            raise ValueError('Offline interval exceeds one day')
        bucket = bins.setdefault(time, {'coverage': {}, 'physics': [], 'price': [], 'modbus': [], 'arp': []})
        kind = event.get('kind')
        if kind == 'coverage':
            if set(event) != {'timestamp_utc', 'site_id', 'kind', 'lane', 'observed'}:
                raise ValueError('Coverage record fields differ from strict schema')
            lane = event['lane']
            if lane not in LANES or type(event['observed']) is not bool or lane in bucket['coverage']:
                raise ValueError('Invalid or duplicate coverage declaration')
            bucket['coverage'][lane] = event['observed']
        else:
            mapping = {'physics_review': ('physics', {'timestamp_utc', 'site_id', 'kind', 'review'}),
                       'price': ('price', {'timestamp_utc', 'site_id', 'kind', 'eur_per_kwh'}),
                       'modbus_write': ('modbus', {'timestamp_utc', 'site_id', 'kind', 'source_ip'}),
                       'arp_claim': ('arp', {'timestamp_utc', 'site_id', 'kind', 'sender_ip', 'sender_mac'})}
            if kind not in mapping:
                raise ValueError(f'Unsupported event kind {kind!r}')
            lane, fields = mapping[kind]
            if set(event) != fields:
                raise ValueError(f'Unexpected fields in {kind}')
            bucket[lane].append(event)
    rows = []
    for time in range(first, last + 1):
        bucket = bins.get(time, {'coverage': {}, 'physics': [], 'price': [], 'modbus': [], 'arp': []})
        visibility = {lane: bucket['coverage'].get(lane, False) for lane in LANES}
        for lane in LANES:
            if bucket[lane] and not visibility[lane]:
                raise ValueError(f'{lane} event without affirmative coverage')
        if visibility['physics'] and len(bucket['physics']) != 1:
            raise ValueError('Observed physics requires exactly one value per second')
        if visibility['price'] and len(bucket['price']) != 1:
            raise ValueError('Observed price requires exactly one value per second')
        if bucket['physics'] and type(bucket['physics'][0]['review']) is not bool:
            raise ValueError('Physics review must be boolean')
        price = bucket['price'][0]['eur_per_kwh'] if bucket['price'] else None
        # Validate numeric, IP and MAC formats using the replay engine below.
        rows.append({'timestamp_utc': datetime.fromtimestamp(time, timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
                     'observable': visibility,
                     'physics_review': bucket['physics'][0]['review'] if bucket['physics'] else None,
                     'price_eur_per_kwh': price,
                     'modbus_writes': [{'source_ip': item['source_ip']} for item in bucket['modbus']],
                     'arp_claims': [{'sender_ip': item['sender_ip'], 'sender_mac': item['sender_mac']} for item in bucket['arp']]})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--events-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True, help='Non-overwriting normalized observations JSON')
    args = parser.parse_args()
    from offline_four_lane_replay import load_frozen_policy
    policy, policy_digest = load_frozen_policy(args.policy, args.policy_sha256)
    events, events_digest = read_frozen_jsonl(args.events, args.events_sha256)
    rows = from_events(policy['site_id'], events)
    replay(policy, rows)  # Validate all rows and causal replay semantics before writing.
    output = {'schema_version': 1, 'mode': 'research_only', 'site_id': policy['site_id'],
              'source_events_sha256': events_digest, 'frozen_policy_sha256': policy_digest,
              'records': rows}
    if args.output.exists():
        raise FileExistsError('Refusing to overwrite normalized observations')
    # Exclusive creation prevents race-based overwrite.
    with args.output.open('x', encoding='utf8') as stream:
        json.dump(output, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'rows': len(rows),
                      'observations_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
