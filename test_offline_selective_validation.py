"""Synthetic selective-evaluation tests, not independently measured accuracy."""
import copy
import unittest

from offline_four_lane_replay import replay
from offline_selective_validation import score
from test_offline_four_lane_replay import POLICY, row


def fixture():
    observations = [row(0), row(1, modbus_writes=[{'source_ip': '192.0.2.99'}]),
                    row(2, observable={'physics': False, 'modbus': False, 'arp': False, 'price': False},
                        physics_review=None, price_eur_per_kwh=None),
                    row(3), row(4, physics_review=None, price_eur_per_kwh=None,
                                observable={'physics': False, 'modbus': False, 'arp': False, 'price': False})]
    predictions = replay(POLICY, observations)
    truth = {'schema_version': 1, 'site_id': 'lab-example',
             'adjudication_reference': 'illustrative-synthetic-labels-only',
             'records': [{'timestamp_utc': item['timestamp_utc'], 'attack_active': flag}
                         for item, flag in zip(observations, (False, True, True, True, False))]}
    return predictions, truth


class SelectiveTests(unittest.TestCase):
    def test_denominators_and_abstention_bounds(self):
        predictions, truth = fixture()
        result = score(predictions, truth)
        self.assertEqual((result['tp'], result['fp'], result['tn'], result['fn']), (1, 0, 1, 1))
        self.assertEqual((result['abstained_attack_rows'], result['abstained_benign_rows']), (1, 1))
        self.assertEqual(result['selective_coverage'], 0.6)
        self.assertEqual(result['selective_f1'], 0.666667)
        self.assertEqual(result['all_attack_recall_lower_bound'], 0.333333)
        self.assertEqual(result['all_attack_recall_upper_bound'], 0.666667)

    def test_rejects_site_and_timestamp_mismatch(self):
        predictions, truth = fixture()
        truth['site_id'] = 'other'
        with self.assertRaisesRegex(ValueError, 'Site IDs'):
            score(predictions, truth)
        predictions, truth = fixture()
        truth['records'][1]['timestamp_utc'] = '2026-10-26T00:00:59Z'
        with self.assertRaisesRegex(ValueError, 'Timestamp mismatch'):
            score(predictions, truth)

    def test_refuses_inconsistent_status_and_forged_lanes(self):
        predictions, truth = fixture()
        predictions['records'][2]['status'] = 'NO_REVIEW_OBSERVED'
        with self.assertRaisesRegex(ValueError, 'contradicts'):
            score(predictions, truth)
        predictions, truth = fixture()
        predictions['records'][1]['positive_lanes'] = []
        with self.assertRaisesRegex(ValueError, 'disagree'):
            score(predictions, truth)

    def test_rejects_truth_without_independent_reference(self):
        predictions, truth = fixture()
        truth['adjudication_reference'] = ''
        with self.assertRaisesRegex(ValueError, 'adjudication'):
            score(predictions, truth)

    def test_rejects_boolean_like_truth_and_row_loss(self):
        predictions, truth = fixture()
        truth['records'][0]['attack_active'] = 0
        with self.assertRaisesRegex(ValueError, 'boolean'):
            score(predictions, truth)
        predictions, truth = fixture()
        truth['records'].pop()
        with self.assertRaisesRegex(ValueError, 'one-to-one'):
            score(predictions, truth)


if __name__ == '__main__':
    unittest.main()
