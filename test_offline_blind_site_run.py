"""Synthetic two-stage blind workflow tests; NOT new research performance."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from offline_blind_site_run import prepare, unblind
from test_offline_four_lane_replay import POLICY
from test_offline_observation_ingest import covered, event


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TwoStageTests(unittest.TestCase):
    def setup_files(self, directory):
        policy = directory / 'policy.json'
        policy.write_text(json.dumps(POLICY))
        events = covered(0) + [event(0, 'modbus_write', source_ip='192.0.2.99')] + covered(1)
        eventfile = directory / 'events.jsonl'
        eventfile.write_text(''.join(json.dumps(line) + '\n' for line in events))
        run = directory / 'frozen_run'
        seal = prepare(policy, sha(policy), eventfile, sha(eventfile), run)
        truth = directory / 'truth.json'
        truth.write_text(json.dumps({'schema_version': 1, 'site_id': POLICY['site_id'],
                                     'adjudication_reference': 'synthetic-fixture',
                                     'records': [{'timestamp_utc': f'2026-10-26T00:00:0{i}Z',
                                                  'attack_active': bool(i)} for i in range(2)]}))
        return policy, eventfile, run, truth, seal

    def test_two_stage_full_workflow_and_nonoverwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            policy, eventfile, run, truth, seal = self.setup_files(directory)
            self.assertFalse((run / 'score.json').exists())
            output = directory / 'score.json'
            result = unblind(run, sha(run / 'seal.json'), truth, sha(truth), output)
            self.assertEqual(result['rows'], 2)
            self.assertEqual(result['tp'], 1)
            self.assertEqual(result['fp'], 1)
            self.assertEqual(result['replay_sha256'], seal['replay_sha256'])
            with self.assertRaisesRegex(FileExistsError, 'overwrite'):
                unblind(run, sha(run / 'seal.json'), truth, sha(truth), output)
            with self.assertRaisesRegex(FileExistsError, 'reuse'):
                prepare(policy, sha(policy), eventfile, sha(eventfile), run)

    def test_seal_and_replay_tamper_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            _, _, run, truth, _ = self.setup_files(directory)
            seal_hash = sha(run / 'seal.json')
            replay_file = run / 'replay.json'
            replay_file.write_text(replay_file.read_text().replace('REVIEW_UNVERIFIED', 'NO_REVIEW_OBSERVED'))
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                unblind(run, seal_hash, truth, sha(truth), directory / 'result.json')

    def test_seal_itself_tampered_and_truth_hash_wrong(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            _, _, run, truth, _ = self.setup_files(directory)
            seal_hash = sha(run / 'seal.json')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                unblind(run, seal_hash, truth, '0' * 64, directory / 'result.json')
            seal_file = run / 'seal.json'
            seal_file.write_text(seal_file.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                unblind(run, seal_hash, truth, sha(truth), directory / 'result.json')

    def test_policy_hash_and_truth_site_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            policy, eventfile, run, truth, _ = self.setup_files(directory)
            mismatched = directory / 'different_run'
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                prepare(policy, 'f' * 64, eventfile, sha(eventfile), mismatched)
            self.assertFalse(mismatched.exists())
            truth_doc = json.loads(truth.read_text())
            truth_doc['site_id'] = 'wrong'
            truth.write_text(json.dumps(truth_doc))
            with self.assertRaisesRegex(ValueError, 'Site IDs'):
                unblind(run, sha(run / 'seal.json'), truth, sha(truth), directory / 'score.json')


if __name__ == '__main__':
    unittest.main()
