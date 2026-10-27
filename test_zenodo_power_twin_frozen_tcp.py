import unittest
from unittest.mock import patch

import dpkt

from zenodo_power_twin_frozen_tcp import (
    FROZEN_MAX_TCP_DEST_PORTS, PUBLISHER_MD5, score_reader, evaluate,
)


def packet(dport, flags=dpkt.tcp.TH_SYN):
    tcp = dpkt.tcp.TCP(sport=40000, dport=dport, flags=flags)
    ip = dpkt.ip.IP(p=dpkt.ip.IP_PROTO_TCP, src=b'\\x0a\\x00\\x00\\x01',
                    dst=b'\\x0a\\x00\\x00\\x02', data=tcp)
    eth = dpkt.ethernet.Ethernet(
        src=b'\\x00' * 6, dst=b'\\x01' * 6,
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


class IndependentPowerTwinTests(unittest.TestCase):
    def test_rule_is_frozen_before_third_domain(self):
        self.assertEqual(FROZEN_MAX_TCP_DEST_PORTS, 2)
        self.assertEqual(PUBLISHER_MD5, '5c9e8e5f51813831084c0e11cbe0d50b')

    def test_flags_only_multiport_syn_without_ack(self):
        result = score_reader([(0, packet(80)), (1, packet(81)),
                               (2, packet(82)), (60, packet(82))])
        self.assertEqual(result['reviewed_windows'], 1)
        self.assertEqual(result['review_episodes'], 1)
        self.assertEqual(result['nonempty_windows'], 2)

    def test_no_flag_for_ack_only_or_two_ports(self):
        result = score_reader([(0, packet(80, dpkt.tcp.TH_ACK)),
                               (1, packet(81, dpkt.tcp.TH_ACK)),
                               (2, packet(82, dpkt.tcp.TH_ACK)),
                               (60, packet(22)), (61, packet(23))])
        self.assertEqual(result['reviewed_windows'], 0)

    def test_counts_noncontiguous_flag_episodes(self):
        frames = [(0, packet(80)), (1, packet(81)), (2, packet(82)),
                  (180, packet(80)), (181, packet(81)), (182, packet(82))]
        self.assertEqual(score_reader(frames)['review_episodes'], 2)

    def test_empty_capture_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Empty capture'):
            score_reader([])

    def test_rejects_wrong_publisher_digest(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'bad.pcapng'
            file.write_bytes(b'not the publisher capture')
            with self.assertRaisesRegex(ValueError, 'MD5 mismatch'):
                evaluate(file)


if __name__ == '__main__':
    unittest.main()
