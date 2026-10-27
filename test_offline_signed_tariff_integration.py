"""Synthetic end-to-end compatibility of ingestion, replay, signatures, bridge."""
import unittest
import base64

from offline_observation_ingest import from_events
from offline_four_lane_replay import replay
from offline_signed_tariff_verifier import verify, canonical
from offline_tariff_context_bridge import combine
from test_offline_observation_ingest import covered, event
from test_offline_four_lane_replay import POLICY
from test_offline_signed_tariff_verifier import make_key, message, policy


class FullPipelineTests(unittest.TestCase):
    def lab_signature_fixture(self, key, seconds):
        lab_policy = policy(key)
        lab_policy['site_id'] = 'lab-example'
        messages = []
        for sec, sequence, price, observed in seconds:
            item = message(key[0], sec, sequence, price=price, observed=observed)
            item['signed']['site_id'] = 'lab-example'
            item['signature_b64'] = base64.b64encode(key[0].sign(canonical(item['signed']))).decode()
            messages.append(item)
        return lab_policy, messages

    def test_signed_price_novelty_remains_context_not_attack_verdict(self):
        key = make_key()
        events = covered(0) + covered(1)
        for item in events:
            if item['kind'] == 'price' and item['timestamp_utc'].endswith(':00Z'):
                item['eur_per_kwh'] = 4.0
        normalized = from_events('lab-example', events)
        fusion = replay(POLICY, normalized)
        signer_policy, statements = self.lab_signature_fixture(key, [(0, 1, 4.0, 4.0), (1, 2, 0.0, 0.0)])
        tariff = verify(signer_policy, statements)
        joined = combine(fusion, tariff)['records']
        self.assertEqual(joined[0]['price_context_category'], 'SIGNED_BUT_NOVEL_CONTEXT')
        self.assertEqual(joined[0]['four_lane_original_status'], 'REVIEW_UNVERIFIED')
        self.assertEqual(joined[1]['price_context_category'], 'SIGNED_EXPECTED_CONTEXT')

    def test_independent_price_mismatch_remains_unverified_review(self):
        key = make_key()
        fusion = replay(POLICY, [{'timestamp_utc': '2026-10-26T00:00:01Z',
                                 'observable': dict.fromkeys(('physics','modbus','arp','price'), True),
                                 'physics_review': False, 'modbus_writes': [], 'arp_claims': [],
                                 'price_eur_per_kwh': 4.0}])
        signer_policy, statements = self.lab_signature_fixture(key, [(1, 1, 0.0, 4.0)])
        signed = verify(signer_policy, statements)
        record = combine(fusion, signed)['records'][0]
        self.assertEqual(record['price_context_category'], 'PRICE_PATH_DIVERGENCE_REVIEW')
        self.assertEqual(record['price_novelty'], True)


if __name__ == '__main__':
    unittest.main()
