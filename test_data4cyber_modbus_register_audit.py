import socket
import unittest

from data4cyber_modbus_register_audit import decode_write, score


class FakeTCP:
    dport = 502

    def __init__(self, data):
        self.data = data


class FakeIP:
    src = socket.inet_aton('192.0.2.10')
    dst = socket.inet_aton('192.0.2.20')


class RegisterAuditTests(unittest.TestCase):
    def test_decode_complete_modbus_write(self):
        # MBAP transaction 1, protocol 0, length 6, unit 2, FC6, register 0x0102.
        data = bytes.fromhex('000100000006020601020005')
        self.assertEqual(decode_write(FakeIP(), FakeTCP(data)),
                         ('192.0.2.10', '192.0.2.20', 6, 2, 258))

    def test_reject_nonwrites_and_truncated_pdus(self):
        good = bytes.fromhex('000100000006020601020005')
        self.assertIsNone(decode_write(FakeIP(), FakeTCP(good[:-2])))
        self.assertIsNone(decode_write(FakeIP(), FakeTCP(good[:7] + b'\x03' + good[8:])))

    def test_scores_are_disjoint_and_do_not_invent_precision(self):
        import numpy as np
        truth = np.array([False, False, True, True])
        alert = np.array([False, True, False, True])
        result = score(truth, alert)
        self.assertEqual((result['tp'], result['fp'], result['fn'], result['tn']), (1, 1, 1, 1))
        self.assertEqual(result['f1'], 0.5)


if __name__ == '__main__':
    unittest.main()
