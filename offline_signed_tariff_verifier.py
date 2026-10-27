"""Offline Ed25519 tariff provenance audit; no MQTT, PKI or grid I/O.

The verifier checks that frozen signed statements came from the *public keys*
in a separately approved site policy, then compares against independently
observed prices. It does not attest that keys are truly owned by a utility,
that the signer is uncompromised, or that live collection is complete.
"""
import argparse
import base64
import binascii
import json
import math
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from offline_four_lane_replay import load_hashed_json, parse_utc

SIGNED_FIELDS = ('schema_version', 'site_id', 'publisher_id', 'key_id',
                 'sequence', 'timestamp_utc', 'price_eur_per_kwh')


def decode_base64(value, size, label):
    if not isinstance(value, str):
        raise ValueError(f'{label} must be base64 text')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f'Malformed {label} base64') from exc
    if len(raw) != size:
        raise ValueError(f'{label} must be exactly {size} bytes')
    return raw


def canonical(signed):
    if not isinstance(signed, dict) or set(signed) != set(SIGNED_FIELDS):
        raise ValueError('Signed tariff statement has an unexpected schema')
    if signed.get('schema_version') != 1:
        raise ValueError('Signed statement schema_version must be 1')
    for field in ('site_id', 'publisher_id', 'key_id'):
        if not isinstance(signed[field], str) or not signed[field].strip():
            raise ValueError(f'Nonblank {field} required')
    sequence = signed['sequence']
    if type(sequence) is not int or sequence < 0:
        raise ValueError('Nonnegative integer sequence required')
    parse_utc(signed['timestamp_utc'])
    price = signed['price_eur_per_kwh']
    if type(price) not in (int, float) or not math.isfinite(price):
        raise ValueError('Finite signed price required')
    return json.dumps(signed, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf8')


def validate_policy(policy):
    if not isinstance(policy, dict) or policy.get('schema_version') != 1 or policy.get('mode') != 'research_only':
        raise ValueError('Frozen research-only policy v1 required')
    for name in ('site_id', 'publisher_id', 'key_provenance_reference'):
        if not isinstance(policy.get(name), str) or not policy[name].strip():
            raise ValueError(f'{name} must identify independently approved site/publisher/key custody')
    keys = policy.get('trusted_keys')
    if not isinstance(keys, dict) or not keys:
        raise ValueError('Nonempty trusted_keys required')
    validated = {}
    for key_id, record in keys.items():
        if not isinstance(key_id, str) or not key_id.strip() or not isinstance(record, dict) or set(record) != {'public_key_b64', 'not_before_utc', 'not_after_utc'}:
            raise ValueError('Malformed keyring entry')
        start, end = parse_utc(record['not_before_utc']), parse_utc(record['not_after_utc'])
        if end <= start:
            raise ValueError('Key validity interval must increase')
        keybytes = decode_base64(record['public_key_b64'], 32, 'Ed25519 public key')
        validated[key_id] = (Ed25519PublicKey.from_public_bytes(keybytes), start, end)
    return validated


def validate_checkpoint(policy, checkpoint):
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
            'schema_version', 'site_id', 'publisher_id', 'last_authenticated_sequence',
            'last_authenticated_timestamp_utc'}:
        raise ValueError('Exact prior replay checkpoint schema required')
    if checkpoint['schema_version'] != 1 or checkpoint['site_id'] != policy['site_id'] or checkpoint['publisher_id'] != policy['publisher_id']:
        raise ValueError('Checkpoint site/publisher mismatch')
    sequence = checkpoint['last_authenticated_sequence']
    if type(sequence) is not int or sequence < 0:
        raise ValueError('Prior checkpoint sequence must be nonnegative integer')
    timestamp = parse_utc(checkpoint['last_authenticated_timestamp_utc'])
    return sequence, timestamp


def verify(policy, messages, prior_checkpoint=None):
    keyring = validate_policy(policy)
    if not isinstance(messages, list) or not messages:
        raise ValueError('Nonempty message list required')
    last_sequence, last_authenticated_timestamp = (
        validate_checkpoint(policy, prior_checkpoint) if prior_checkpoint is not None else (None, None))
    last_timestamp = last_authenticated_timestamp
    last_authenticated_stamp_text = (prior_checkpoint['last_authenticated_timestamp_utc']
                                     if prior_checkpoint is not None else None)
    rows = []
    for row in messages:
        if not isinstance(row, dict) or set(row) != {'signed', 'signature_b64', 'observed_price_eur_per_kwh'}:
            raise ValueError('Each message needs signed, signature_b64, observed_price_eur_per_kwh only')
        signed = row['signed']
        payload = canonical(signed)
        stamp = parse_utc(signed['timestamp_utc'])
        if last_timestamp is not None and stamp <= last_timestamp:
            raise ValueError('Messages must be strictly increasing in UTC time')
        last_timestamp = stamp
        observed_price = row['observed_price_eur_per_kwh']
        if observed_price is not None and (type(observed_price) not in (int, float) or not math.isfinite(observed_price)):
            raise ValueError('Observed price must be finite or null')
        signature = decode_base64(row['signature_b64'], 64, 'Ed25519 signature')
        seq = signed['sequence']
        if signed['site_id'] != policy['site_id'] or signed['publisher_id'] != policy['publisher_id']:
            status = 'UNTRUSTED_SOURCE_ABSTAIN'
        elif signed['key_id'] not in keyring:
            status = 'UNKNOWN_KEY_ABSTAIN'
        else:
            key, start, end = keyring[signed['key_id']]
            if not (start <= stamp < end):
                status = 'KEY_OUTSIDE_VALIDITY_ABSTAIN'
            else:
                try:
                    key.verify(signature, payload)
                except InvalidSignature:
                    status = 'INVALID_SIGNATURE_REVIEW'
                else:
                    if last_sequence is not None and seq <= last_sequence:
                        status = 'REPLAY_OR_OUT_OF_ORDER_REVIEW'
                    elif observed_price is None:
                        status = 'NO_INDEPENDENT_PRICE_ABSTAIN'
                    elif abs(signed['price_eur_per_kwh'] - observed_price) > 1e-6:
                        status = 'SIGNED_VS_OBSERVED_PRICE_MISMATCH_REVIEW'
                    else:
                        status = 'SIGNED_PRICE_CONSISTENT_CONTEXT'
                    # Only authenticated statements advance sequence, even if
                    # observed price differs or is unavailable.
                    if last_sequence is None or seq > last_sequence:
                        last_sequence = seq
                        last_authenticated_stamp_text = signed['timestamp_utc']
        rows.append({'timestamp_utc': signed['timestamp_utc'], 'key_id': signed['key_id'],
                     'sequence': seq, 'status': status,
                     'warning': 'Signed data is not proof of benign intent or uncompromised key custody.'})
    return {'status': 'OFFLINE_AUTHENTICATED_TARIFF_CONTEXT_NOT_DEPLOYED',
            'site_id': policy['site_id'], 'publisher_id': policy['publisher_id'],
            'records': rows,
            'replay_checkpoint_mode': ('EXTERNALLY_SUPPLIED_PRIOR_CHECKPOINT' if prior_checkpoint is not None
                                      else 'BATCH_ONLY_NO_RESTART_REPLAY_ASSURANCE'),
            'proposed_next_checkpoint': (
                {'schema_version': 1, 'site_id': policy['site_id'], 'publisher_id': policy['publisher_id'],
                 'last_authenticated_sequence': last_sequence,
                 'last_authenticated_timestamp_utc': last_authenticated_stamp_text}
                if last_sequence is not None else None),
            'warning': 'Ed25519 checks bytes against policy keys only. An externally frozen, authenticated checkpoint is needed across runs. Key provenance, revocation, independent observation, secure clock and utility approval are not established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--messages', type=Path, required=True)
    parser.add_argument('--messages-sha256', required=True)
    parser.add_argument('--prior-checkpoint', type=Path, help='Prior trusted checkpoint, externally committed before this batch')
    parser.add_argument('--prior-checkpoint-sha256', help='Required with prior checkpoint; checksum alone does not prove custody')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    policy, policy_hash = load_hashed_json(args.policy, args.policy_sha256, 'Tariff policy')
    messages, message_hash = load_hashed_json(args.messages, args.messages_sha256, 'Tariff messages')
    if bool(args.prior_checkpoint) != bool(args.prior_checkpoint_sha256):
        parser.error('Both --prior-checkpoint and --prior-checkpoint-sha256 are required together')
    checkpoint = None
    if args.prior_checkpoint:
        checkpoint, checkpoint_hash = load_hashed_json(args.prior_checkpoint,
                                                       args.prior_checkpoint_sha256, 'Prior replay checkpoint')
    result = verify(policy, messages['records'], prior_checkpoint=checkpoint)
    result['policy_sha256'] = policy_hash
    result['messages_sha256'] = message_hash
    if checkpoint is not None:
        result['prior_checkpoint_sha256'] = checkpoint_hash
    with args.output.open('x', encoding='utf8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'records': len(result['records'])}))


if __name__ == '__main__':
    main()
