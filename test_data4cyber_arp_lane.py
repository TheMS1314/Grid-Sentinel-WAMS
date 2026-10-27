"""Passive ARP fixture tests with zero network or packet transmission."""
import io
import socket
import unittest

import dpkt

from data4cyber_passive_arp_audit import read_arp


class MemoryArchive:
    def __init__(self,source):self.source=source
    def open(self,path):return io.BytesIO(self.source)


def fixture(source_ip,source_mac):
    arp=dpkt.arp.ARP(
        hrd=1,pro=dpkt.ethernet.ETH_TYPE_IP,hln=6,pln=4,op=2,
        sha=bytes.fromhex(source_mac.replace(':','')),
        spa=socket.inet_aton(source_ip),
        tha=bytes.fromhex('00133b9d008d'),
        tpa=socket.inet_aton('192.168.1.11'),
    )
    frame=dpkt.ethernet.Ethernet(src=arp.sha,dst=b'\xff'*6,
                                 type=dpkt.ethernet.ETH_TYPE_ARP,data=arp)
    memory=io.BytesIO()
    writer=dpkt.pcapng.Writer(memory)
    writer.writepkt(bytes(frame),ts=1720000012.2)
    return MemoryArchive(memory.getvalue())


class ARPTest(unittest.TestCase):
    known={'192.168.1.11':{'00:13:3b:9d:00:8d'}}

    def test_legitimate_claim(self):
        rows=list(read_arp(fixture('192.168.1.11','00:13:3b:9d:00:8d'),'S0'))
        self.assertEqual(len(rows),1)
        self.assertIn(rows[0][2],self.known[rows[0][1]])

    def test_spoofed_claim_is_discrepant(self):
        rows=list(read_arp(fixture('192.168.1.11','98:e7:43:a2:c7:b1'),'S5'))
        self.assertEqual(len(rows),1)
        self.assertNotIn(rows[0][2],self.known[rows[0][1]])
        self.assertEqual(rows[0][3],2)


if __name__=='__main__':unittest.main()
