"""Offline Data4Cyber ARP origin consistency audit (no packet transmission).

Checks IP→MAC claims visible in public pcapng against the S0 published role
inventory. Not cryptographic authentication; can miss ARP poisoning entirely
depending on capture vantage, spoofing route and observed traffic.
"""
import argparse
import collections
import json
import socket
import zipfile
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd

from smartgrid_phase22_reliability import streaks


def known_mapping(archive):
    name='data4cyber_dataset/S0_benign_baseline/ip_device_mapping.csv'
    table=pd.read_csv(archive.open(name))
    known={}
    for _,row in table.iterrows():
        ip=str(row['ip']).strip();raw=str(row['mac_addresses'])
        if ip=='nan' or raw=='nan':continue
        addresses={x.strip().lower() for x in raw.replace(';',',').split(',') if x.strip()}
        if addresses:known[ip]=addresses
    return known


def read_arp(archive,scenario):
    path=f'data4cyber_dataset/{scenario}/network_tap.pcapng'
    with archive.open(path) as handle:
        for ts,buf in dpkt.pcapng.Reader(handle):
            try:
                frame=dpkt.ethernet.Ethernet(buf)
                if frame.type!=dpkt.ethernet.ETH_TYPE_ARP:continue
                arp=frame.data
                if not isinstance(arp,dpkt.arp.ARP) or len(arp.spa)!=4 or len(arp.sha)!=6:continue
                yield float(ts),socket.inet_ntoa(arp.spa),arp.sha.hex(':'),int(arp.op)
            except (ValueError,dpkt.UnpackError,socket.error):continue


def evaluate(archive,scenario,mapping,hold_seconds=0,return_flags=False):
    prefix=f'data4cyber_dataset/{scenario}/'
    df=pd.read_csv(archive.open(prefix+'dataset.csv'),usecols=['timestamp','attack_active','attack_phase'])
    stamps=pd.to_datetime(df['timestamp'],utc=True).astype('int64').to_numpy()/1e9
    truth=df['attack_active'].astype(bool).to_numpy()
    records=list(read_arp(archive,scenario))
    mismatches=[(ts,ip,mac,op) for ts,ip,mac,op in records if ip in mapping and mac not in mapping[ip]]
    counts=collections.Counter((ip,mac) for _,ip,mac,_ in mismatches)
    flag=np.zeros(len(df),bool)
    valid_count=0
    if mismatches:
        times=np.array([r[0] for r in mismatches])
        indices=np.searchsorted(stamps,times,side='left')
        indices=np.clip(indices,0,len(stamps)-1)
        prior=np.clip(indices-1,0,len(stamps)-1)
        indices=np.where(abs(stamps[prior]-times)<abs(stamps[indices]-times),prior,indices)
        valid=abs(stamps[indices]-times)<=.55
        valid_count=int(valid.sum())
        flag[indices[valid]]=True
        if hold_seconds:
            for ts in times[valid]:flag[(stamps>=ts-.55)&(stamps<=ts+hold_seconds)]=True
    tp=int((truth&flag).sum());fp=int((~truth&flag).sum())
    fn=int((truth&~flag).sum());tn=int((~truth&~flag).sum())
    episodes=streaks(truth,stamps)
    phase={}
    for phase_name,group in df.groupby('attack_phase'):
        mask=(df['attack_phase']==phase_name).to_numpy()&truth
        if mask.any():phase[str(phase_name)]={'rows':int(mask.sum()),'alert_rows':int((mask&flag).sum())}
    result={
        'scenario':scenario,'known_inventory_ips':len(mapping),
        'arp_packets_observed':len(records),
        'known_ip_mac_mismatch_packets':len(mismatches),
        'mismatch_packets_aligned_1hz':valid_count,
        'top_mismatched_claims':[{'ip':ip,'claimed_mac':mac,'packets':n} for (ip,mac),n in counts.most_common(10)],
        'hold_seconds':hold_seconds,'tp':tp,'fp':fp,'fn':fn,'tn':tn,
        'row_f1':round(2*tp/max(1,2*tp+fp+fn),5),
        'row_recall':round(tp/max(1,tp+fn),5),
        'clean_fpr':round(fp/max(1,fp+tn),5),
        'activity_episodes':len(episodes),'episodes_with_alert':sum(bool(flag[lo:hi+1].any()) for lo,hi in episodes),
        'phase_breakdown':phase,
        'warning':'Unverified ARP observations, not authenticated sender identity; unknown IPs ignored. Dataset and attack family already inspected.',
    }
    return (result,flag) if return_flags else result


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    a.add_argument('--scenarios',nargs='+',default=['S0_benign_baseline','S3_arp_spoof_bss_meter_half_values','S4_arp_spoof_loads_pv_two_phase','S5_arp_spoof_loads_pv_bss_two_phase'])
    a.add_argument('--hold-seconds',type=int,default=0,choices=(0,5,30))
    a.add_argument('--output')
    args=a.parse_args()
    with zipfile.ZipFile(args.archive) as z:
        mapping=known_mapping(z)
        reports=[evaluate(z,name,mapping,args.hold_seconds) for name in args.scenarios]
    for result in reports:print(json.dumps(result))
    if args.output:Path(args.output).write_text('\n'.join(json.dumps(r) for r in reports)+'\n',encoding='utf8')


if __name__=='__main__':main()
