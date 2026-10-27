"""Synthetic pipeline tests; these do not establish field detection accuracy."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from offline_observation_ingest import from_events, read_frozen_jsonl
from offline_four_lane_replay import replay
from test_offline_four_lane_replay import POLICY


def event(second, kind, **data):
    return {'timestamp_utc': f'2026-10-26T00:00:{second:02d}Z',
            'site_id': 'lab-example', 'kind': kind, **data}


def covered(second, *, modbus=True, arp=True, physics=True, price=True):
    rows = [event(second, 'coverage', lane=k, observed=v) for k, v in
            [('physics', physics), ('modbus', modbus), ('arp', arp), ('price', price)]]
    if physics:
        rows.append(event(second, 'physics_review', review=False))
    if price:
        rows.append(event(second, 'price', eur_per_kwh=0.0))
    return rows


class IngestTests(unittest.TestCase):
    def test_full_observation_and_held_event(self):
        events = covered(0) + [event(0, 'modbus_write', source_ip='192.0.2.99')] + covered(1)
        rows = from_events('lab-example', events)
        self.assertEqual(len(rows), 2)
        flags = replay(POLICY, rows)['records']
        self.assertEqual(flags[0]['positive_lanes'], ['modbus'])
        self.assertEqual(flags[1]['positive_lanes'], ['modbus'])

    def test_missing_second_abstains_and_clears_modbus_hold(self):
        events = covered(0) + [event(0, 'modbus_write', source_ip='192.0.2.99')] + covered(2)
        rows = from_events('lab-example', events)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]['observable'], dict.fromkeys(('physics','modbus','arp','price'), False))
        output = replay(POLICY, rows)['records']
        self.assertEqual(output[1]['status'], 'ABSTAIN_INCOMPLETE_VISIBILITY')
        self.assertFalse(output[2]['lane_flags']['modbus'])

    def test_visibility_absence_does_not_mean_clean(self):
        rows = from_events('lab-example', covered(0, price=False))
        self.assertIn('price', replay(POLICY, rows)['records'][0]['unknown_lanes'])

    def test_missing_value_rejected(self):
        events = [e for e in covered(0) if e['kind'] != 'price']
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            from_events('lab-example', events)

    def test_no_event_without_coverage(self):
        events = covered(0, modbus=False) + [event(0, 'modbus_write', source_ip='192.0.2.99')]
        with self.assertRaisesRegex(ValueError, 'without affirmative'):
            from_events('lab-example', events)

    def test_duplicate_heartbeat_rejected(self):
        events = covered(0)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            from_events('lab-example', events + [events[0]])

    def test_event_site_and_unknown_kind_rejected(self):
        with self.assertRaisesRegex(ValueError, 'site_id'):
            from_events('lab-example', [event(0, 'price', site_id='other', eur_per_kwh=0)])
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            from_events('lab-example', [event(0, 'switch_command')])

    def test_invalid_values_rejected_by_replay(self):
        events = covered(0) + [event(0, 'arp_claim', sender_ip='192.0.2.50', sender_mac='bad')]
        with self.assertRaisesRegex(ValueError, 'MAC'):
            replay(POLICY, from_events('lab-example', events))

    def test_input_hash_and_duplicate_fields_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'events.jsonl'
            target.write_text('{"a":1,"a":2}\n')
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                read_frozen_jsonl(target, digest)
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                read_frozen_jsonl(target, '0' * 64)

    def test_seconds_and_duration_limits(self):
        with self.assertRaisesRegex(ValueError, 'align'):
            from_events('lab-example', [{**event(0, 'coverage', lane='arp', observed=False),
                                          'timestamp_utc': '2026-10-26T00:00:00.5Z'}])
        later = {**event(0, 'coverage', lane='arp', observed=False),
                 'timestamp_utc': '2026-10-28T00:00:00Z'}
        with self.assertRaisesRegex(ValueError, 'one day'):
            from_events('lab-example', covered(0) + [later])


if __name__ == '__main__':
    unittest.main()
