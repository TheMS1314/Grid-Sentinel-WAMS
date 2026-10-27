import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import dpkt

from external_capture_acceptance import run


def tcp_frame(port, flags=dpkt.tcp.TH_SYN):
    tcp = dpkt.tcp.TCP(sport=40000, dport=port, flags=flags)
    ip = dpkt.ip.IP(p=6, src=bytes.fromhex("0a000001"),
                    dst=bytes.fromhex("0a000002"), data=tcp)
    frame = dpkt.ethernet.Ethernet(src=bytes(6), dst=bytes([1]) * 6,
                                  type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(frame)


class ExternalCaptureAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def capture(self, name, packets):
        buffer = io.BytesIO()
        with dpkt.pcap.Writer(buffer) as writer:
            for second, port in packets:
                writer.writepkt(tcp_frame(port), ts=second)
        raw = buffer.getvalue()
        (self.root / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def evaluate(self, entries):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"schema_version": 1, "captures": entries}))
        return run(manifest, self.root)

    def test_in_scope_capture_review_and_benign_unscored_hours(self):
        attack = self.capture("scan.pcap", [(1, 80), (2, 81), (3, 82)])
        benign = self.capture("normal.pcap", [(1, 502), (121, 502)])
        result = self.evaluate([{**attack, "truth": "attack", "family": "tcp_scan",
                                 "tcp_scan_in_scope": True},
                                {**benign, "truth": "benign", "family": "normal",
                                 "tcp_scan_in_scope": False}])
        self.assertEqual(result["in_scope_attack_capture_review_fraction"], 1.0)
        self.assertEqual(result["benign_review_episodes"], 0)
        self.assertIsNone(result["benign_episodes_per_24_verified_hours"])

    def test_unsupported_attack_abstains(self):
        attack = self.capture("goose.pcap", [(1, 502), (121, 502)])
        result = self.evaluate([{**attack, "truth": "attack", "family": "goose",
                                 "tcp_scan_in_scope": False}])
        self.assertEqual(result["unsupported_attack_captures_abstained"], 1)
        self.assertIsNone(result["in_scope_attack_capture_review_fraction"])

    def test_benign_duration_rate_requires_source_proof(self):
        benign = self.capture("normal.pcap", [(1, 502), (121, 502)])
        result = self.evaluate([{**benign, "truth": "benign", "family": "normal",
                                 "tcp_scan_in_scope": False, "verified_benign_seconds": 120}])
        self.assertEqual(result["benign_episodes_per_24_verified_hours"], 0.0)
        self.assertFalse(result["benign_24h_target_assessable"])

    def test_refuses_wrong_sha256(self):
        attack = self.capture("scan.pcap", [(1, 80)])
        attack["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.evaluate([{**attack, "truth": "attack", "family": "tcp_scan",
                            "tcp_scan_in_scope": True}])

    def test_refuses_path_escape(self):
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            self.evaluate([{"path": "../outside.pcap", "sha256": "0" * 64,
                            "truth": "benign", "family": "normal",
                            "tcp_scan_in_scope": False}])

    def test_refuses_false_benign_coverage(self):
        benign = self.capture("normal.pcap", [(1, 502), (121, 502)])
        with self.assertRaisesRegex(ValueError, "exceeds"):
            self.evaluate([{**benign, "truth": "benign", "family": "normal",
                            "tcp_scan_in_scope": False, "verified_benign_seconds": 10000}])

    def test_refuses_duplicate_capture(self):
        cap = self.capture("normal.pcap", [(1, 502)])
        entry = {**cap, "truth": "benign", "family": "normal", "tcp_scan_in_scope": False}
        with self.assertRaisesRegex(ValueError, "Repeated"):
            self.evaluate([entry, entry])


if __name__ == "__main__":
    unittest.main()
