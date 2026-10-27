"""Ephemeral-key synthetic cryptographic tests; not utility field evidence."""
import base64
import copy
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offline_signed_tariff_verifier import canonical, verify


def make_key():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                           format=serialization.PublicFormat.Raw)
    return key, base64.b64encode(public).decode()


def message(key, sec, sequence, price=0.15, observed=None, key_id='key1'):
    signed = {'schema_version': 1, 'site_id': 'synthetic-site', 'publisher_id': 'synthetic-publisher',
              'key_id': key_id, 'sequence': sequence,
              'timestamp_utc': f'2026-10-26T00:00:{sec:02d}Z', 'price_eur_per_kwh': price}
    return {'signed': signed,
            'signature_b64': base64.b64encode(key.sign(canonical(signed))).decode(),
            'observed_price_eur_per_kwh': price if observed is None else observed}


def policy(key1, key2=None):
    keys = {'key1': {'public_key_b64': key1[1], 'not_before_utc': '2026-10-25T00:00:00Z',
                     'not_after_utc': '2026-10-26T00:00:10Z'}}
    if key2:
        keys['key2'] = {'public_key_b64': key2[1], 'not_before_utc': '2026-10-26T00:00:10Z',
                        'not_after_utc': '2026-11-01T00:00:00Z'}
    return {'schema_version': 1, 'mode': 'research_only', 'site_id': 'synthetic-site',
            'publisher_id': 'synthetic-publisher', 'key_provenance_reference': 'fictional-human-approved-fixture',
            'trusted_keys': keys}


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.k1 = make_key()
        self.k2 = make_key()

    def test_signed_price_matches_independent_observation(self):
        result = verify(policy(self.k1), [message(self.k1[0], 1, 1)])
        self.assertEqual(result['records'][0]['status'], 'SIGNED_PRICE_CONSISTENT_CONTEXT')

    def test_tampering_detected_but_not_called_confirmed_attack(self):
        good = message(self.k1[0], 1, 1)
        good['signed']['price_eur_per_kwh'] = 0.25
        result = verify(policy(self.k1), [good])
        self.assertEqual(result['records'][0]['status'], 'INVALID_SIGNATURE_REVIEW')

    def test_signed_price_divergence_and_no_observation(self):
        a = message(self.k1[0], 1, 1, observed=0.99)
        b = message(self.k1[0], 2, 2)
        b['observed_price_eur_per_kwh'] = None
        statuses = [r['status'] for r in verify(policy(self.k1), [a, b])['records']]
        self.assertEqual(statuses, ['SIGNED_VS_OBSERVED_PRICE_MISMATCH_REVIEW',
                                    'NO_INDEPENDENT_PRICE_ABSTAIN'])

    def test_replay_sequence_after_key_rotation(self):
        result = verify(policy(self.k1, self.k2), [message(self.k1[0], 1, 8),
                         message(self.k2[0], 10, 9, key_id='key2'),
                         message(self.k2[0], 11, 7, key_id='key2')])
        self.assertEqual([r['status'] for r in result['records']],
                         ['SIGNED_PRICE_CONSISTENT_CONTEXT', 'SIGNED_PRICE_CONSISTENT_CONTEXT',
                          'REPLAY_OR_OUT_OF_ORDER_REVIEW'])

    def test_outdated_key_and_unknown_publisher_abstain(self):
        expired = message(self.k1[0], 11, 1)
        unknown = message(self.k1[0], 12, 2)
        unknown['signed']['publisher_id'] = 'other'
        statuses = [r['status'] for r in verify(policy(self.k1), [expired, unknown])['records']]
        self.assertEqual(statuses, ['KEY_OUTSIDE_VALIDITY_ABSTAIN', 'UNTRUSTED_SOURCE_ABSTAIN'])

    def test_wrong_key_and_nonfinite_values_refused(self):
        unknown = message(self.k1[0], 1, 1, key_id='key2')
        self.assertEqual(verify(policy(self.k1), [unknown])['records'][0]['status'],
                         'UNKNOWN_KEY_ABSTAIN')
        broken = message(self.k1[0], 1, 1)
        broken['observed_price_eur_per_kwh'] = float('nan')
        with self.assertRaisesRegex(ValueError, 'finite'):
            verify(policy(self.k1), [broken])

    def test_duplicate_time_and_invalid_key_material_refused(self):
        rows = [message(self.k1[0], 1, 1), message(self.k1[0], 1, 2)]
        with self.assertRaisesRegex(ValueError, 'strictly increasing'):
            verify(policy(self.k1), rows)
        invalid_policy = policy(self.k1)
        invalid_policy['trusted_keys']['key1']['public_key_b64'] = 'not base64!'
        with self.assertRaisesRegex(ValueError, 'base64'):
            verify(invalid_policy, [rows[0]])

    def test_cross_run_replay_needs_prior_checkpoint(self):
        first = verify(policy(self.k1), [message(self.k1[0], 1, 8)])
        self.assertEqual(first['replay_checkpoint_mode'], 'BATCH_ONLY_NO_RESTART_REPLAY_ASSURANCE')
        prior = first['proposed_next_checkpoint']
        self.assertEqual(prior['last_authenticated_sequence'], 8)
        second = verify(policy(self.k1), [message(self.k1[0], 2, 8)], prior_checkpoint=prior)
        self.assertEqual(second['records'][0]['status'], 'REPLAY_OR_OUT_OF_ORDER_REVIEW')
        self.assertEqual(second['proposed_next_checkpoint'], prior)
        next_batch = verify(policy(self.k1), [message(self.k1[0], 2, 9)], prior_checkpoint=prior)
        self.assertEqual(next_batch['records'][0]['status'], 'SIGNED_PRICE_CONSISTENT_CONTEXT')
        self.assertEqual(next_batch['proposed_next_checkpoint']['last_authenticated_sequence'], 9)

    def test_external_checkpoint_cannot_switch_site_or_go_back_in_time(self):
        prior = verify(policy(self.k1), [message(self.k1[0], 1, 8)])['proposed_next_checkpoint']
        mismatch = copy.deepcopy(prior)
        mismatch['site_id'] = 'another-site'
        with self.assertRaisesRegex(ValueError, 'Checkpoint site'):
            verify(policy(self.k1), [message(self.k1[0], 2, 9)], prior_checkpoint=mismatch)
        with self.assertRaisesRegex(ValueError, 'strictly increasing'):
            verify(policy(self.k1), [message(self.k1[0], 1, 9)], prior_checkpoint=prior)

    def test_compromised_signer_is_observationally_indistinguishable(self):
        # The same signed statement could be an approved tariff change or a
        # compromised-key publisher's malicious output. Labels are hidden.
        statement = message(self.k1[0], 1, 1, price=0.90)
        approved_change = verify(policy(self.k1), [copy.deepcopy(statement)])
        compromised_signer = verify(policy(self.k1), [copy.deepcopy(statement)])
        self.assertEqual(approved_change['records'], compromised_signer['records'])
        self.assertEqual(approved_change['records'][0]['status'], 'SIGNED_PRICE_CONSISTENT_CONTEXT')


if __name__ == '__main__':
    unittest.main()
