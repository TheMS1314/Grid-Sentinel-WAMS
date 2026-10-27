"""Within-run, posthoc ARP identity vs physics vs simple fusion evaluation."""
import argparse
import json
import zipfile
from pathlib import Path

import pandas as pd

from data4cyber_passive_arp_audit import evaluate,known_mapping
from data4cyber_two_lane_benchmark import score
from smartgrid_phase22_reliability import replay


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    p.add_argument('--model',default='smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json')
    p.add_argument('--hold-seconds',type=int,default=0,choices=(0,5,30))
    p.add_argument('--output')
    a=p.parse_args()
    model=json.loads(Path(a.model).read_text())
    reports=[]
    with zipfile.ZipFile(a.archive) as z:
        known=known_mapping(z)
        for scenario in ['S0_benign_baseline','S3_arp_spoof_bss_meter_half_values',
                         'S4_arp_spoof_loads_pv_two_phase','S5_arp_spoof_loads_pv_bss_two_phase']:
            df=pd.read_csv(z.open(f'data4cyber_dataset/{scenario}/dataset.csv'),low_memory=False)
            physics=replay(df,model)[2]
            arp_report,arp=evaluate(z,scenario,known,a.hold_seconds,return_flags=True)
            if scenario=='S0_benign_baseline':
                start=int(.8*len(df));df=df.iloc[start:];physics=physics[start:];arp=arp[start:]
            truth=df['attack_active'].astype(bool).to_numpy()
            result={
                'scenario':scenario,'hold_seconds':a.hold_seconds,
                'physics':score(truth,physics),
                'arp_source_consistency':score(truth,arp),
                'two_lane_or':score(truth,physics|arp),
                'mismatched_arp_packets':arp_report['known_ip_mac_mismatch_packets'],
                'per_phase':{},
                'warning':'ARP IP/MAC mismatch is NOT authenticated source identity. Architecture selected after inspecting the same attack campaigns.',
            }
            if scenario!='S0_benign_baseline':
                for phase in sorted(set(df.loc[df['attack_active'].astype(bool),'attack_phase'].astype(str))):
                    mask=(df['attack_phase'].astype(str)==phase).to_numpy()
                    result['per_phase'][phase]={
                        'labeled_rows':int(mask.sum()),
                        'physics_alert_rows':int((physics&mask).sum()),
                        'arp_alert_rows':int((arp&mask).sum()),
                        'or_alert_rows':int(((physics|arp)&mask).sum()),
                    }
            reports.append(result);print(json.dumps(result))
    if a.output:Path(a.output).write_text('\n'.join(json.dumps(x) for x in reports)+'\n',encoding='utf8')


if __name__=='__main__':main()
