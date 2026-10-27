"""Read-only, causal four-signal triage on normalized offline observations.

Not an IDS deployment or authenticated intrusion proof. The physics flag must
come from a separately frozen meter detector. Modbus IPs and ARP MAC claims
are unverified observations; independently authenticated provenance is needed
before operational conclusions. No packet capture, commands, or network I/O.
"""
import argparse
import hashlib
import ipaddress
import json
import math
from datetime import datetime
from pathlib import Path

LANES = ('physics', 'modbus', 'arp', 'price')


def normalized_mac(value):
    if not isinstance(value, str) or len(value.split(':')) != 6 or any(
            len(pair) != 2 or any(c not in '0123456789abcdefABCDEF' for c in pair)
            for pair in value.split(':')):
        raise ValueError('ARP MAC must be colon-delimited hex pairs')
    return value.lower()


def parse_utc(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('Timestamp must be ISO8601 UTC ending Z')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Malformed timestamp') from exc
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError('Timestamp must use UTC')
    return parsed.timestamp()


def validate_policy(policy):
    if policy.get('schema_version') != 1 or policy.get('mode') != 'research_only':
        raise ValueError('Policy must explicitly declare research_only schema v1')
    if not isinstance(policy.get('site_id'), str) or not policy['site_id'].strip():
        raise ValueError('A nonblank site_id is required')
    modbus = policy.get('allowed_modbus_sources')
    arp = policy.get('expected_arp_mappings')
    if not isinstance(modbus, list) or not modbus or not isinstance(arp, dict) or not arp:
        raise ValueError('Nonempty fixed Modbus and ARP inventories required')
    for ip in modbus:
        ipaddress.ip_address(ip)
    for ip, mac in arp.items():
        ipaddress.ip_address(ip)
        normalized_mac(mac)
    price = policy.get('frozen_price_rule')
    if not isinstance(price, dict):
        raise ValueError('Frozen price rule required')
    for key in ('center', 'scale', 'threshold'):
        number = price.get(key)
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number):
            raise ValueError(f'Finite frozen price {key} required')
    if price['scale'] <= 0 or price['threshold'] <= 0:
        raise ValueError('Positive frozen price scale/threshold required')
    holds = policy.get('hold_seconds')
    if not isinstance(holds, dict) or set(holds) != {'modbus', 'arp'}:
        raise ValueError('Explicit Modbus and ARP hold_seconds required')
    for value in holds.values():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0 <= value <= 30):
            raise ValueError('Hold durations must be between 0 and 30 seconds')
    if not isinstance(policy.get('inventory_provenance_reference'), str) or not policy['inventory_provenance_reference'].strip():
        raise ValueError('Inventory provenance reference is mandatory; human verification still required')


def explicit_flag(value, label):
    if value is None or isinstance(value, bool):
        return value
    raise ValueError(f'{label} must be true, false, or null')


def observed(value, label):
    if not isinstance(value, bool):
        raise ValueError(f'{label} observability must be explicitly true or false')
    return value


def replay(policy, rows):
    validate_policy(policy)
    if not isinstance(rows, list) or not rows:
        raise ValueError('At least one observation row is required')
    last_event = {'modbus': None, 'arp': None}
    previous_time = None
    output = []
    allowed = set(policy['allowed_modbus_sources'])
    known = {ip: mac.lower() for ip, mac in policy['expected_arp_mappings'].items()}
    price_policy = policy['frozen_price_rule']
    for row in rows:
        stamp = parse_utc(row.get('timestamp_utc'))
        if previous_time is not None:
            gap = stamp - previous_time
            if gap <= 0:
                raise ValueError('Rows must be strictly increasing in time')
            if gap > 1.5:
                # Persistence may not leap across a missing interval.
                last_event = {'modbus': None, 'arp': None}
        previous_time = stamp
        visibility = row.get('observable')
        if not isinstance(visibility, dict) or set(visibility) != set(LANES):
            raise ValueError('All four lane observability flags must be explicit')
        coverage = {name: observed(visibility[name], name) for name in LANES}
        physics = explicit_flag(row.get('physics_review'), 'physics_review')
        if coverage['physics'] and physics is None:
            raise ValueError('Observed physics requires a reviewed boolean')
        if not coverage['physics'] and physics is not None:
            raise ValueError('Unobserved physics must be null')
        flags = {'physics': physics if coverage['physics'] else None}

        for name, key in (('modbus', 'modbus_writes'), ('arp', 'arp_claims')):
            events = row.get(key)
            if not isinstance(events, list):
                raise ValueError(f'{key} must be an explicit list')
            if not coverage[name] and events:
                raise ValueError(f'{key} cannot contain events without coverage')
            if name == 'modbus':
                triggered = False
                unknown_claim = False
                for item in events:
                    source = item.get('source_ip') if isinstance(item, dict) else None
                    ipaddress.ip_address(source)
                    if source not in allowed:
                        triggered = True
            else:
                triggered = False
                unknown_claim = False
                for item in events:
                    if not isinstance(item, dict):
                        raise ValueError('Malformed ARP claim')
                    source_ip, source_mac = item.get('sender_ip'), item.get('sender_mac')
                    ipaddress.ip_address(source_ip)
                    source_mac = normalized_mac(source_mac)
                    if source_ip not in known:
                        unknown_claim = True
                    elif source_mac != known[source_ip]:
                        triggered = True
            if triggered:
                last_event[name] = stamp
            if not coverage[name]:
                last_event[name] = None
            # If observation coverage is absent, do not carry prior flags into
            # a new claim; an unseen lane must abstain, even during hold time.
            held = (last_event[name] is not None and
                    stamp - last_event[name] <= policy['hold_seconds'][name])
            flags[name] = (True if held else None if unknown_claim else False) if coverage[name] else None

        price = row.get('price_eur_per_kwh')
        if coverage['price'] and (isinstance(price, bool) or not isinstance(price, (float, int)) or not math.isfinite(price)):
            raise ValueError('Observed price must be finite numeric')
        if not coverage['price'] and price is not None:
            raise ValueError('Unobserved price must be null')
        flags['price'] = (abs(price - price_policy['center']) / price_policy['scale'] >
                          price_policy['threshold']) if coverage['price'] else None
        positives = [name for name, flag in flags.items() if flag is True]
        unknown = [name for name, flag in flags.items() if flag is None]
        status = ('REVIEW_UNVERIFIED' if positives else
                  'ABSTAIN_INCOMPLETE_VISIBILITY' if unknown else 'NO_REVIEW_OBSERVED')
        output.append({'timestamp_utc': row['timestamp_utc'], 'status': status,
                       'positive_lanes': positives, 'unknown_lanes': unknown,
                       'lane_flags': flags,
                       'boundary': 'Passive claims are not authenticated attacks; never actuate grid controls.'})
    return {'status': 'OFFLINE_FROZEN_POLICY_RESEARCH_ONLY',
            'site_id': policy['site_id'], 'records': output,
            'warning': 'No online learning, no attack claims, no sensor/device actions. Source inventories and tariff origin require independent verification.'}


def load_hashed_json(path, expected_sha256, label):
    data = Path(path).read_bytes()
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(
            character not in '0123456789abcdefABCDEF' for character in expected_sha256):
        raise ValueError(f'A valid 64-character {label} SHA-256 is required')
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256.lower():
        raise ValueError(f'{label} hash mismatch: evaluation refused')
    return json.loads(data), digest


def load_frozen_policy(path, expected_sha256):
    policy, digest = load_hashed_json(path, expected_sha256, 'Frozen policy')
    validate_policy(policy)
    return policy, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True, help='Digest independently frozen before evaluating new data')
    parser.add_argument('--observations', type=Path, required=True, help='JSON with records list')
    parser.add_argument('--observations-sha256', required=True, help='Digest independently committed before unblinding')
    parser.add_argument('--output', type=Path, help='Refuses overwrite of existing results')
    args = parser.parse_args()
    policy, digest = load_frozen_policy(args.policy, args.policy_sha256)
    observations, input_digest = load_hashed_json(args.observations, args.observations_sha256, 'Observations')
    records = observations['records']
    result = replay(policy, records)
    result['frozen_policy_sha256'] = digest
    result['observations_sha256'] = input_digest
    content = json.dumps(result, indent=2) + '\n'
    if args.output:
        if args.output.exists():
            raise FileExistsError('Refusing to overwrite prior evaluation results')
        args.output.write_text(content, encoding='utf8')
    else:
        print(content, end='')


if __name__ == '__main__':
    main()
