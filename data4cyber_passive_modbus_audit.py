"""Read-only Data4Cyber packet-level Modbus visibility audit.

Extracts only TCP/502 transaction metadata from public pcapng archives. No
traffic transmission, no control commands, and no learned attack signatures.
The offline decoder is intentionally conservative about fragmented TCP PDUs.
"""
import argparse
import collections
import json
import socket
import struct
import zipfile

import dpkt
import numpy as np
import pandas as pd


WRITE_CODES={5,6,15,16,22,23}
READ_CODES={1,2,3,4}


def packets(pcap_stream):
    read=dpkt.pcapng.Reader(pcap_stream)
    for stamp,buf in read:
        try:
            packet=dpkt.ethernet.Ethernet(buf)
            ip=packet.data
            if not isinstance(ip,(dpkt.ip.IP,dpkt.ip6.IP6)):continue
            tcp=ip.data
            if not isinstance(tcp,dpkt.tcp.TCP) or 502 not in (tcp.sport,tcp.dport):continue
            data=bytes(tcp.data)
            # One MBAP PDU at the start of a segment. TCP segmentation can
            # hide additional PDUs; these counts must be treated as minima.
            code=None; unit=None
            if len(data)>=8:
                protocol=int.from_bytes(data[2:4],'big')
                length=int.from_bytes(data[4:6],'big')
                if protocol==0 and 2<=length<=253:
                    code=data[7]
                    unit=data[6]
            yield {
                'timestamp':float(stamp),
                'source':socket.inet_ntop(socket.AF_INET6 if isinstance(ip,dpkt.ip6.IP6) else socket.AF_INET,ip.src),
                'destination':socket.inet_ntop(socket.AF_INET6 if isinstance(ip,dpkt.ip6.IP6) else socket.AF_INET,ip.dst),
                'source_port':tcp.sport,
                'destination_port':tcp.dport,
                'function_code':code,
                'unit_id':unit,
                'payload_bytes':len(data),
            }
        except (ValueError,IndexError,dpkt.UnpackError,socket.error):
            continue


def summarize(archive,member,labels):
    observations=[]
    with archive.open(member) as handle:
        for item in packets(handle):observations.append(item)
    code_counts=collections.Counter(str(p['function_code']) for p in observations)
    writes=[p for p in observations if p['function_code'] in WRITE_CODES and p['destination_port']==502]
    sources=collections.Counter(f"{p['source']} → {p['destination']}" for p in writes)
    packet_seconds=np.array([p['timestamp'] for p in writes])
    timestamps=pd.to_datetime(labels['timestamp'],utc=True).astype('int64').to_numpy()/1e9
    phases=labels['attack_phase'].fillna('unknown').astype(str).to_numpy()
    truth=labels['attack_active'].astype(bool).to_numpy()
    if len(packet_seconds):
        assigned=np.searchsorted(timestamps,packet_seconds,side='left')
        assigned=np.clip(assigned,0,len(timestamps)-1)
        previous=np.clip(assigned-1,0,len(timestamps)-1)
        assigned=np.where(np.abs(packet_seconds-timestamps[previous])<np.abs(packet_seconds-timestamps[assigned]),previous,assigned)
        close=np.abs(packet_seconds-timestamps[assigned])<=0.55
        assigned=assigned[close]
    else:assigned=np.array([],dtype=int)
    phase_writes=collections.Counter(phases[assigned])
    return {
        'scenario':member.split('/')[-2],
        'modbus_502_packets':len(observations),
        'payload_starts_decode_as_modbus':sum(p['function_code'] is not None for p in observations),
        'function_code_histogram':dict(code_counts),
        'write_requests_total':len(writes),
        'write_requests_aligned_1hz':len(assigned),
        'write_requests_during_attack_activity':int(truth[assigned].sum()),
        'write_requests_during_benign_activity':int((~truth[assigned]).sum()),
        'write_requests_per_phase':dict(phase_writes),
        'top_write_src_to_dst':sources.most_common(10),
        'limitations':'Only MBAP at TCP segment start; no reassembly, signature, authorization policy or malicious-packet attribution.',
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--scenarios',nargs='+',default=['S0_benign_baseline','S1_industroyer_pv','S2_industroyer_bss','S6_mqtt_supply_chain_compromise'])
    parser.add_argument('--output')
    args=parser.parse_args()
    reports=[]
    with zipfile.ZipFile(args.archive) as archive:
        for scenario in args.scenarios:
            prefix=f'data4cyber_dataset/{scenario}/'
            df=pd.read_csv(archive.open(prefix+'dataset.csv'),low_memory=False,usecols=['timestamp','attack_active','attack_phase'])
            report=summarize(archive,prefix+'network_tap.pcapng',df)
            reports.append(report)
            print(json.dumps(report))
    if args.output:
        from pathlib import Path
        Path(args.output).write_text('\n'.join(json.dumps(x) for x in reports)+'\n',encoding='utf8')


if __name__=='__main__':main()
