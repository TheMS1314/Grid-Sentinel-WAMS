"""Publisher integrity and packet-to-policy observation tests."""
import socket
import unittest

import dpkt

from cyber4ot_independent_modbus_probe import ATTACKS, BENIGN, PUBLISHER_MD5, modbus_frame


def packet(source_ip, port, mac):
    ip = dpkt.ip.IP(src=socket.inet_aton(source_ip), dst=socket.inet_aton("192.168.127.21"),
                    p=6, ttl=64)
    ip.data = dpkt.tcp.TCP(sport=12345, dport=port, data=b"payload")
    eth = dpkt.ethernet.Ethernet(src=bytes.fromhex(mac.replace(":", "")),
                                 dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


class Cyber4OTTests(unittest.TestCase):
    def test_publisher_digest_fixed(self):
        self.assertEqual(PUBLISHER_MD5, "55510cbb43d8af72a69dfbcd6940daa5")

    def test_only_modbus_endpoint_frames_scored(self):
        self.assertEqual(modbus_frame(packet("192.168.127.126", 502, "52:5d:c9:36:7e:c6")),
                         ("192.168.127.126", "52:5d:c9:36:7e:c6", True))
        self.assertIsNone(modbus_frame(packet("192.168.127.126", 80, "52:5d:c9:36:7e:c6")))

    def test_invalid_frames_ignored(self):
        self.assertIsNone(modbus_frame(b"not-an-ethernet-frame"))

    def test_distinct_capture_vantage(self):
        self.assertEqual(BENIGN, (70, 71))
        self.assertNotIn(83, ATTACKS)
        self.assertIn(90, ATTACKS)


if __name__ == "__main__":
    unittest.main()
