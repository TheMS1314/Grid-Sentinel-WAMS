"""Synthetic software tests, never evidence of attack detection performance."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from offline_four_lane_replay import replay, load_frozen_policy, load_hashed_json


POLICY = {
    'schema_version': 1, 'mode': 'research_only', 'site_id': 'lab-example',
    'allowed_modbus_sources': ['192.0.2.10'],
    'expected_arp_mappings': {'192.0.2.50': '02:00:00:00:00:01'},
    'inventory_provenance_reference': 'human-verified-demo-change-log',
    'frozen_price_rule': {'center': 0.0, 'scale': 1.0, 'threshold': 3.0},
    'hold_seconds': {'modbus': 5, 'arp': 2},
}


def row(second, **changes):
    result = {'timestamp_utc': f'2026-10-26T00:00:{second:02d}Z',
              'observable': {'physics': True, 'modbus': True, 'arp': True, 'price': True},
              'physics_review': False, 'modbus_writes': [], 'arp_claims': [],
              'price_eur_per_kwh': 0.0}
    result.update(changes)
    return result


class OfflineFusionTests(unittest.TestCase):
    def test_causal_holds_expire_and_gaps_reset(self):
        flagged = row(1, modbus_writes=[{'source_ip': '192.0.2.99'}],
                      arp_claims=[{'sender_ip': '192.0.2.50', 'sender_mac': '02:00:00:00:00:02'}],
                      price_eur_per_kwh=4.0)
        result = replay(POLICY, [row(0), flagged, row(2), row(4), row(6), row(7), row(12)])
        data = result['records']
        self.assertEqual(data[0]['status'], 'NO_REVIEW_OBSERVED')
        self.assertEqual(set(data[1]['positive_lanes']), {'modbus', 'arp', 'price'})
        self.assertEqual(set(data[2]['positive_lanes']), {'modbus', 'arp'})
        # A two-second missing observation gap resets previous state.
        self.assertEqual(data[3]['positive_lanes'], [])
        self.assertEqual(data[-1]['status'], 'NO_REVIEW_OBSERVED')

    def test_missing_visibility_abstains_instead_of_silent_clean(self):
        entry = row(0, physics_review=None, price_eur_per_kwh=None,
                    observable={'physics': False, 'modbus': True, 'arp': True, 'price': False})
        result = replay(POLICY, [entry])['records'][0]
        self.assertEqual(result['status'], 'ABSTAIN_INCOMPLETE_VISIBILITY')
        self.assertEqual(set(result['unknown_lanes']), {'physics', 'price'})

    def test_visibility_dropout_clears_prior_hold(self):
        fired = row(0, modbus_writes=[{'source_ip': '192.0.2.99'}])
        obscured = row(1, observable={'physics': True, 'modbus': False, 'arp': True, 'price': True})
        clear = row(2)
        result = replay(POLICY, [fired, obscured, clear])['records']
        self.assertIsNone(result[1]['lane_flags']['modbus'])
        self.assertFalse(result[2]['lane_flags']['modbus'])

    def test_unmapped_arp_claim_abstains_and_bad_mac_rejects(self):
        unknown = row(0, arp_claims=[{
            'sender_ip': '192.0.2.77', 'sender_mac': '02:00:00:00:00:77'}])
        record = replay(POLICY, [unknown])['records'][0]
        self.assertEqual(record['status'], 'ABSTAIN_INCOMPLETE_VISIBILITY')
        self.assertIn('arp', record['unknown_lanes'])
        malformed = row(0, arp_claims=[{
            'sender_ip': '192.0.2.50', 'sender_mac': 'invalid'}])
        with self.assertRaisesRegex(ValueError, 'colon-delimited'):
            replay(POLICY, [malformed])

    def test_partial_coverage_keeps_unverified_alert_not_attack_claim(self):
        entry = row(0, physics_review=None,
                    observable={'physics': False, 'modbus': True, 'arp': True, 'price': True},
                    modbus_writes=[{'source_ip': '192.0.2.99'}])
        result = replay(POLICY, [entry])['records'][0]
        self.assertEqual(result['status'], 'REVIEW_UNVERIFIED')
        self.assertIn('physics', result['unknown_lanes'])

    def test_rejects_live_mode_and_policy_drift(self):
        drift = copy.deepcopy(POLICY)
        drift['mode'] = 'active_control'
        with self.assertRaisesRegex(ValueError, 'research_only'):
            replay(drift, [row(0)])
        drift = copy.deepcopy(POLICY)
        drift['hold_seconds']['modbus'] = 60
        with self.assertRaisesRegex(ValueError, 'Hold durations'):
            replay(drift, [row(0)])

    def test_rejects_unobserved_packets_and_nonfinite_tariffs(self):
        entry = row(0, observable={'physics': True, 'modbus': False, 'arp': True, 'price': True},
                    modbus_writes=[{'source_ip': '192.0.2.99'}])
        with self.assertRaisesRegex(ValueError, 'without coverage'):
            replay(POLICY, [entry])
        with self.assertRaisesRegex(ValueError, 'finite numeric'):
            replay(POLICY, [row(0, price_eur_per_kwh=float('nan'))])

    def test_time_order_and_missing_provenance_rejected(self):
        with self.assertRaisesRegex(ValueError, 'increasing'):
            replay(POLICY, [row(2), row(1)])
        drift = copy.deepcopy(POLICY)
        drift.pop('inventory_provenance_reference')
        with self.assertRaisesRegex(ValueError, 'provenance'):
            replay(drift, [row(0)])

    def test_cli_frozen_policy_hash_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text(json.dumps(POLICY), encoding='utf8')
            good = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(load_frozen_policy(path, good)[1], good)
            path.write_text(json.dumps({**POLICY, 'hold_seconds': {'modbus': 7, 'arp': 2}}))
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                load_frozen_policy(path, good)

    def test_observation_hash_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'observations.json'
            path.write_text(json.dumps({'records': [row(0)]}), encoding='utf8')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(load_hashed_json(path, digest, 'Observations')[1], digest)
            path.write_text(json.dumps({'records': [row(1)]}), encoding='utf8')
            with self.assertRaisesRegex(ValueError, 'Observations hash mismatch'):
                load_hashed_json(path, digest, 'Observations')


if __name__ == '__main__':
    unittest.main()
