"""Offline unauthorized Modbus writer-source policy benchmark (research only).

Anomaly policy is derived from S0 *role mapping* and S0 passive write-source
inventory, never from attack labels. IP addresses are spoofable and do not
constitute cryptographic source authentication. Never sends Modbus traffic.
"""
import argparse
import collections
import io
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from data4cyber_passive_modbus_audit import WRITE_CODES,packets
from smartgrid_phase22_reliability import streaks


def authorized_from_inventory(archive):
    prefix='data4cyber_dataset/S0_benign_baseline/'
    metadata=pd.read_csv(archive.open(prefix+'ip_device_mapping.csv'))
    controller=metadata.loc[metadata['role'].astype(str).str.contains('management_system',case=False),'ip']
    ips=set(controller.dropna().astype(str))
    if not ips:raise ValueError('No management-system IP found in S0 role mapping')
    return sorted(ips)


def events(archive,prefix):
    with archive.open(prefix+'network_tap.pcapng') as stream:
        for item in packets(stream):
            if item['destination_port']!=502 or item['function_code'] not in WRITE_CODES:continue
            yield item


def score_scenario(archive,scenario,authorized,hold_seconds=0,return_alerts=False):
    prefix=f'data4cyber_dataset/{scenario}/'
    df=pd.read_csv(archive.open(prefix+'dataset.csv'),low_memory=False,usecols=['timestamp','attack_active','attack_phase'])
    stamps=pd.to_datetime(df['timestamp'],utc=True).astype('int64').to_numpy()/1e9
    truth=df['attack_active'].astype(bool).to_numpy()
    unauthorized=[x for x in events(archive,prefix) if x['source'] not in authorized]
    write_times=np.array([x['timestamp'] for x in unauthorized],dtype=float)
    alert=np.zeros(len(df),bool)
    in_capture=np.zeros(len(unauthorized),bool)
    assigned=np.empty(0,dtype=int)
    if len(write_times):
        ix=np.searchsorted(stamps,write_times,side='left')
        ix=np.clip(ix,0,len(stamps)-1)
        previous=np.clip(ix-1,0,len(stamps)-1)
        ix=np.where(abs(write_times-stamps[previous])<abs(write_times-stamps[ix]),previous,ix)
        valid=abs(write_times-stamps[ix])<=.55
        in_capture=valid
        assigned=ix[valid]
        alert[assigned]=True
        if hold_seconds:
            for ts in write_times[valid]:
                alert[(stamps>=ts-.55)&(stamps<=ts+hold_seconds)]=True
    tp=int(np.sum(truth&alert));fp=int(np.sum(~truth&alert))
    fn=int(np.sum(truth&~alert));tn=int(np.sum(~truth&~alert))
    episodes=streaks(truth,stamps)
    first_delays=[];episode_hits=0
    for start,stop in episodes:
        match=np.flatnonzero(alert[start:stop+1])
        if len(match):
            episode_hits+=1
            first_delays.append(round(float(stamps[start+match[0]]-stamps[start]),3))
    phase_counts={}
    for phase,sub in df.groupby('attack_phase'):
        mask=(df['attack_phase']==phase).to_numpy()&truth
        if not mask.any():continue
        phase_counts[str(phase)]={
            'activity_rows':int(mask.sum()),
            'alert_rows':int(np.sum(alert&mask)),
            'recall':round(float(np.mean(alert[mask])),5),
        }
    unknown_sources=collections.Counter(x['source'] for x in unauthorized)
    result={
        'scenario':scenario,'allowed_modbus_write_source_ips':authorized,
        'suspicious_write_requests':len(unauthorized),
        'suspicious_write_sources':dict(unknown_sources),
        'requests_aligned_to_1hz':int(in_capture.sum()),
        'hold_seconds':hold_seconds,
        'tp':tp,'fp':fp,'fn':fn,'tn':tn,
        'activity_row_recall':round(tp/max(1,tp+fn),5),
        'activity_row_precision':round(tp/max(1,tp+fp),5),
        'clean_row_fpr':round(fp/max(1,fp+tn),5),
        'activity_episodes':len(episodes),
        'episodes_with_alarm':episode_hits,
        'first_alert_lag_seconds':first_delays,
        'per_attack_phase':phase_counts,
        'boundary':'IP role mismatch flags a command-source anomaly, not an authenticated attacker or unsafe command; traffic might be spoofed, NATed or authorized by site policy.',
    }
    return (result,alert) if return_alerts else result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    p.add_argument('--scenarios',nargs='+',default=['S0_benign_baseline','S1_industroyer_pv','S2_industroyer_bss','S3_arp_spoof_bss_meter_half_values','S4_arp_spoof_loads_pv_two_phase','S5_arp_spoof_loads_pv_bss_two_phase','S6_mqtt_supply_chain_compromise','S1_industroyer_pv_alt'])
    p.add_argument('--hold-seconds',type=int,default=0,choices=(0,5,30),help='Exploratory persistence sensitivity; 0 is direct event evidence. Do not select after inspecting evaluation outcomes for a confirmatory claim.')
    p.add_argument('--output')
    args=p.parse_args()
    reports=[]
    with zipfile.ZipFile(args.archive) as archive:
        allowed=authorized_from_inventory(archive)
        for scenario in args.scenarios:
            result=score_scenario(archive,scenario,allowed,args.hold_seconds)
            print(json.dumps(result))
            reports.append(result)
    if args.output:
        Path(args.output).write_text('\n'.join(json.dumps(x) for x in reports)+'\n',encoding='utf8')


if __name__=='__main__':main()
