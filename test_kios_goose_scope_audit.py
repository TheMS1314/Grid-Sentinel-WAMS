import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from kios_goose_scope_audit import FILES, count_vlan_goose, evaluate


def vlan_goose_packet():
    return b'\\xff' * 6 + b'\\x00' * 6 + b'\\x81\\x00' + b'\\x00\\x01' + b'\\x88\\xb8' + b'payload'


class KiosGooseScopeTests(unittest.TestCase):
    def test_publisher_fingerprints_fixed(self):
        self.assertEqual(len(FILES), 4)
        self.assertEqual(sum(v[1] == 'attack' for v in FILES.values()), 2)
        self.assertTrue(all(len(v[2]) == 32 for v in FILES.values()))

    def test_vlan_encapsulation_goose_counted(self):
        self.assertEqual(count_vlan_goose([(0, vlan_goose_packet())]), 1)

    def test_non_goose_frame_not_mistaken_for_goose(self):
        ethernet = b'\\xff' * 12 + b'\\x08\\x06' + b'payload'
        self.assertEqual(count_vlan_goose([(0, ethernet)]), 0)

    def test_missing_source_capture_blocks_scoring(self):
        with TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                evaluate(Path(directory))

    def test_mismatched_publisher_source_blocks_scoring(self):
        with TemporaryDirectory() as directory:
            first = next(iter(FILES))
            (Path(directory) / first).write_bytes(b'not the Zenodo file')
            with self.assertRaisesRegex(ValueError, 'MD5 mismatch'):
                evaluate(Path(directory))


if __name__ == '__main__':
    unittest.main()
