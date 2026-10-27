import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import dpkt

from external_event_time_blind_eval import FROZEN_POLICY, evaluate


def packet(port, flags=dpkt.tcp.TH_SYN):
    tcp = dpkt.tcp.TCP(sport=40000, dport=port, flags=flags)
    ip = dpkt.ip.IP(p=6, src=bytes([10,0,0,1]), dst=bytes([10,0,0,2]), data=tcp)
    return bytes(dpkt.ethernet.Ethernet(src=bytes(6), dst=bytes([1])*6,
                                        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


class BlindEventTimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self, points):
        raw = io.BytesIO()
        writer = dpkt.pcap.Writer(raw)
        for second, port in points:
            writer.writepkt(packet(port), ts=second)
        content = raw.getvalue()
        writer.close()
        (self.root / "cap.pcap").write_bytes(content)
        return {"path":"cap.pcap", "sha256":hashlib.sha256(content).hexdigest()}

    def run_eval(self, capture):
        manifest = {"schema_version":2, "frozen_rule":FROZEN_POLICY, "captures":[capture]}
        file = self.root/"manifest.json"
        file.write_text(json.dumps(manifest))
        return evaluate(file, self.root)

    def test_hits_event_and_measures_bucket_completion(self):
        cap = self.source([(0,502),(20,80),(21,81),(22,82),(120,502)])
        result = self.run_eval({**cap,
            "events":[{"start_seconds":19,"end_seconds":40,"family":"tcp_scan","in_scope":True}],
            "benign_intervals":[{"start_seconds":60,"end_seconds":120}]})
        self.assertEqual(result["in_scope_event_hits"],1)
        self.assertEqual(result["event_latency_upper_bound_seconds"],[41.0])
        self.assertEqual(result["benign_review_episodes"],0)

    def test_unsupported_attack_abstains(self):
        cap = self.source([(0,502),(120,502)])
        result = self.run_eval({**cap,"events":[
            {"start_seconds":10,"end_seconds":20,"family":"goose","in_scope":False}],
            "benign_intervals":[]})
        self.assertEqual(result["unsupported_events_abstained"],1)
        self.assertIsNone(result["in_scope_event_recall"])

    def test_missed_in_scope_event(self):
        cap = self.source([(0,502),(120,502)])
        result = self.run_eval({**cap,"events":[
            {"start_seconds":10,"end_seconds":30,"family":"tcp_scan","in_scope":True}],
            "benign_intervals":[]})
        self.assertEqual(result["in_scope_event_misses"],1)
        self.assertEqual(result["in_scope_event_recall"],0.0)

    def test_refuses_overlapping_labels(self):
        cap = self.source([(0,502),(120,502)])
        with self.assertRaisesRegex(ValueError,"overlap"):
            self.run_eval({**cap, "events":[
                {"start_seconds":5,"end_seconds":25,"family":"tcp_scan","in_scope":True}],
                "benign_intervals":[{"start_seconds":20,"end_seconds":60}]})

    def test_refuses_unverified_capture(self):
        cap = self.source([(0,502),(120,502)])
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            self.run_eval({**cap,"sha256":"0"*64,"events":[],"benign_intervals":[]})

    def test_no_false_alarm_denominator_without_benign_labels(self):
        cap = self.source([(0,80),(1,81),(2,82),(120,502)])
        result = self.run_eval({**cap,"events":[],"benign_intervals":[]})
        self.assertIsNone(result["benign_episodes_per_24h"])
        self.assertFalse(result["benign_24h_target_assessable"])


if __name__ == "__main__":
    unittest.main()
