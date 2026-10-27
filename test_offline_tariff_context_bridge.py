"""Synthetic evidence-join tests; no deployed signed publisher."""
import copy
import unittest

from offline_four_lane_replay import replay
from offline_tariff_context_bridge import combine
from test_offline_four_lane_replay import POLICY, row


def fixture():
    observations = [row(0, price_eur_per_kwh=4.), row(1)]
    replay_doc = replay(POLICY, observations)
    signed_doc = {'status': 'OFFLINE_AUTHENTICATED_TARIFF_CONTEXT_NOT_DEPLOYED',
                  'site_id': POLICY['site_id'],
                  'records': [{'timestamp_utc': observations[0]['timestamp_utc'],
                               'status': 'SIGNED_PRICE_CONSISTENT_CONTEXT'},
                              {'timestamp_utc': observations[1]['timestamp_utc'],
                               'status': 'INVALID_SIGNATURE_REVIEW'}]}
    return replay_doc, signed_doc


class BridgeTests(unittest.TestCase):
    def test_signed_but_novel_is_context_not_intrusion(self):
        original, signatures = fixture()
        result = combine(original, signatures)
        self.assertEqual(result['records'][0]['price_context_category'], 'SIGNED_BUT_NOVEL_CONTEXT')
        self.assertEqual(result['records'][1]['price_context_category'], 'UNVERIFIED_SIGNATURE_FAILURE_REVIEW')
        self.assertEqual(result['records'][0]['four_lane_original_status'], 'REVIEW_UNVERIFIED')

    def test_rejects_coverage_and_site_mismatch(self):
        original, signatures = fixture()
        signatures['site_id'] = 'other'
        with self.assertRaisesRegex(ValueError, 'Site mismatch'):
            combine(original, signatures)
        original, signatures = fixture()
        signatures['records'].pop()
        with self.assertRaisesRegex(ValueError, 'One-to-one'):
            combine(original, signatures)

    def test_rejects_mismatched_timestamps(self):
        original, signatures = fixture()
        signatures['records'][0]['timestamp_utc'] = '2026-10-26T00:00:55Z'
        with self.assertRaisesRegex(ValueError, 'timestamps differ'):
            combine(original, signatures)


if __name__ == '__main__':
    unittest.main()
