"""Offline MQTT publish visibility audit; no payloads stored or commands sent."""
import argparse
import collections
import json
import socket
import zipfile
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd


def mqtt_publish(payload):
    if not payload or payload[0]>>4 !=3:return None
    # Fixed header remaining-length field (variable length integer).
    size=0;multiplier=1;cursor=1
    while cursor<len(payload) and cursor<=4:
        byte=payload[cursor];cursor+=1
        size+=(byte&127)*multiplier
        multiplier*=128
        if not byte&128:break
    else:return None
    if cursor+2>len(payload):return None
    topic_size=int.from_bytes(payload[cursor:cursor+2],'big');cursor+=2
    if cursor+topic_size>len(payload):return None
    try:topic=payload[cursor:cursor+topic_size].decode('utf8')
    except UnicodeDecodeError:return None
    if any(ord(ch)<32 for ch in topic):return None
    return topic


def audit(archive,scenario):
    prefix=f'data4cyber_dataset/{scenario}/'
    df=pd.read_csv(archive.open(prefix+'dataset.csv'),low_memory=False,usecols=['timestamp','attack_active','attack_phase'])
    stamps=pd.to_datetime(df['timestamp'],utc=True).astype('int64').to_numpy()/1e9
    packets_count=0;publishes=[]
    reader=dpkt.pcapng.Reader(archive.open(prefix+'network_tap.pcapng'))
    for timestamp,buf in reader:
        try:
            p=dpkt.ethernet.Ethernet(buf).data
            if not isinstance(p,(dpkt.ip.IP,dpkt.ip6.IP6)):continue
            tcp=p.data
            if not isinstance(tcp,dpkt.tcp.TCP) or not ({1883,8883}&{tcp.sport,tcp.dport}):continue
            packets_count+=1
            if tcp.dport!=1883:continue
            topic=mqtt_publish(bytes(tcp.data))
            if topic is None:continue
            ip=socket.inet_ntop(socket.AF_INET6 if isinstance(p,dpkt.ip6.IP6) else socket.AF_INET,p.src)
            publishes.append((float(timestamp),ip,topic))
        except (ValueError,IndexError,dpkt.UnpackError,socket.error):continue
    source_count=collections.Counter(item[1] for item in publishes)
    topics=collections.Counter(item[2] for item in publishes)
    phases=collections.Counter()
    if publishes:
        secs=np.array([x[0] for x in publishes]);ids=np.searchsorted(stamps,secs,side='left')
        ids=np.clip(ids,0,len(stamps)-1)
        previous=np.clip(ids-1,0,len(stamps)-1)
        ids=np.where(abs(secs-stamps[previous])<abs(secs-stamps[ids]),previous,ids)
        valid=abs(secs-stamps[ids])<=.55
        for i in ids[valid]:phases[str(df['attack_phase'].iloc[i])]+=1
    return {'scenario':scenario,'mqtt_port_packets':packets_count,
            'decoded_publish_segment_starts':len(publishes),
            'source_publish_counts':dict(source_count),
            'topic_counts':dict(topics),
            'phase_publish_counts':dict(phases),
            'limits':'Partial TCP segment starts only, not reassembled MQTT streams; no authenticated publisher or signed tariff baseline.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--scenarios',nargs='+',default=['S0_benign_baseline','S6_mqtt_supply_chain_compromise'])
    parser.add_argument('--output')
    args=parser.parse_args()
    rows=[]
    with zipfile.ZipFile(args.archive) as archive:
        for name in args.scenarios:
            row=audit(archive,name);print(json.dumps(row));rows.append(row)
    if args.output:Path(args.output).write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf8')


if __name__=='__main__':main()
