"""Synthetic packet fixtures: no network access or device control."""
import io
import socket
import struct
import unittest

import dpkt

from data4cyber_passive_modbus_audit import packets,WRITE_CODES


def pcapng_fixture(code,src='192.168.1.20',dst='192.168.1.88'):
    pdu=struct.pack('>HHHBB',1,0,6,3,code)+b'\x00\x01\x00\x02'
    transport=dpkt.tcp.TCP(sport=45123,dport=502,seq=1,flags=dpkt.tcp.TH_PUSH, data=pdu)
    network=dpkt.ip.IP(src=socket.inet_aton(src),dst=socket.inet_aton(dst),
                       p=dpkt.ip.IP_PROTO_TCP,ttl=64,data=transport)
    network.len=len(network)
    frame=dpkt.ethernet.Ethernet(src=b'\x11'*6,dst=b'\x22'*6,
                                type=dpkt.ethernet.ETH_TYPE_IP,data=network)
    handle=io.BytesIO()
    writer=dpkt.pcapng.Writer(handle)
    writer.writepkt(bytes(frame),ts=1720000000.2)
    return io.BytesIO(handle.getvalue())


class PassiveProtocolTest(unittest.TestCase):
    def test_modbus_write_source_decoding(self):
        decoded=list(packets(pcapng_fixture(16)))
        self.assertEqual(len(decoded),1)
        self.assertEqual(decoded[0]['source'],'192.168.1.20')
        self.assertEqual(decoded[0]['destination'],'192.168.1.88')
        self.assertEqual(decoded[0]['function_code'],16)
        self.assertIn(decoded[0]['function_code'],WRITE_CODES)

    def test_modbus_read_not_write(self):
        decoded=list(packets(pcapng_fixture(3)))
        self.assertEqual(len(decoded),1)
        self.assertNotIn(decoded[0]['function_code'],WRITE_CODES)

    def test_authorized_write_does_not_flag(self):
        allowed={'192.168.1.11'}
        one=list(packets(pcapng_fixture(16,src='192.168.1.11')))
        two=list(packets(pcapng_fixture(16,src='192.168.1.20')))
        self.assertFalse(any(p['source'] not in allowed for p in one))
        self.assertTrue(any(p['source'] not in allowed for p in two))


if __name__=='__main__':unittest.main()
