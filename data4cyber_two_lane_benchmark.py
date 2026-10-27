"""Compare fixed physics vs S0-role-bound Modbus policy vs OR fusion.

Posthoc investigation on exposed attack scenarios, not a new blind test.
No labels fit either model. This is a read-only experiment, not deployed.
"""
import argparse
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from data4cyber_modbus_allowlist_benchmark import authorized_from_inventory,score_scenario
from smartgrid_phase22_reliability import replay


def score(truth,pred):
    tp=int(np.sum(truth&pred));fp=int(np.sum(~truth&pred))
    fn=int(np.sum(truth&~pred));tn=int(np.sum(~truth&~pred))
    return {'tp':tp,'fp':fp,'fn':fn,'tn':tn,
            'precision':round(tp/max(1,tp+fp),5),
            'recall':round(tp/max(1,tp+fn),5),
            'f1':round(2*tp/max(1,2*tp+fp+fn),5),
            'clean_fpr':round(fp/max(1,fp+tn),5)}


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    a.add_argument('--model',default='smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json')
    a.add_argument('--output')
    args=a.parse_args()
    model=json.loads(Path(args.model).read_text())
    reports=[]
    with zipfile.ZipFile(args.archive) as archive:
        authorized=authorized_from_inventory(archive)
        names=['S0_benign_baseline','S1_industroyer_pv','S2_industroyer_bss',
               'S3_arp_spoof_bss_meter_half_values','S4_arp_spoof_loads_pv_two_phase',
               'S5_arp_spoof_loads_pv_bss_two_phase','S6_mqtt_supply_chain_compromise',
               'S1_industroyer_pv_alt']
        for name in names:
            prefix=f'data4cyber_dataset/{name}/'
            df=pd.read_csv(archive.open(prefix+'dataset.csv'),low_memory=False)
            truth=df['attack_active'].astype(bool).to_numpy()
            physics=replay(df,model)[2]
            protocol_report,protocol=score_scenario(archive,name,authorized,return_alerts=True)
            if name=='S0_benign_baseline':
                begin=int(.8*len(df))
                truth=truth[begin:];physics=physics[begin:];protocol=protocol[begin:]
            result={
                'scenario':name,
                'physics':score(truth,physics),
                'unexpected_modbus_writer':score(truth,protocol),
                'two_lane_or':score(truth,physics|protocol),
                'unexpected_write_count':protocol_report['suspicious_write_requests'],
                'warning':'Exploratory within Data4Cyber; packet source IP is not authenticated. No blind transfer claim.',
            }
            print(json.dumps(result));reports.append(result)
    if args.output:
        Path(args.output).write_text('\n'.join(json.dumps(x) for x in reports)+'\n',encoding='utf8')


if __name__=='__main__':main()
