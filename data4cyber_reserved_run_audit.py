"""Apply fixed Phase 16/17 detectors to Data4Cyber S1-alt, excluded earlier.

This is a separate Modbus attack run, NOT an independent grid/site or MITM
replication. Evaluated as recorded without refitting on its measurements.
"""
import argparse
import json
import zipfile
import numpy as np
import pandas as pd
from data4cyber_independent_validation import physical_columns,values,scores,metrics
from data4cyber_physics_invariants import meter_invariants,sustain


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    a=p.parse_args()
    with zipfile.ZipFile(a.archive) as z:
        root='data4cyber_dataset/'
        s0=pd.read_csv(z.open(root+'S0_benign_baseline/dataset.csv'))
        alt=pd.read_csv(z.open(root+'S1_industroyer_pv_alt/dataset.csv'))
    n=len(s0);fitend=int(.6*n);calend=int(.8*n)
    cols=physical_columns(s0)
    _,if_score=scores(values(s0.iloc[:fitend],cols),values(s0.iloc[fitend:calend],cols))
    if_threshold=float(np.quantile(if_score(values(s0.iloc[fitend:calend],cols)),.99))
    inv=meter_invariants(s0)
    train=inv.iloc[:fitend];cal=inv.iloc[fitend:calend]
    center=train.median();scale=(train-center).abs().quantile(.9).clip(lower=.0005)
    peak=lambda frame:((frame-center).abs()/scale).max(axis=1).fillna(0).to_numpy(float)
    local_threshold=float(np.quantile(peak(cal),.99))
    label=alt['attack_active'].astype(bool).to_numpy()
    anomaly=if_score(values(alt,cols))>if_threshold
    physics=sustain(peak(meter_invariants(alt))>local_threshold,alt,3)
    for name,pred in [('S0_meter_isolation_forest',anomaly),
                      ('S0_three_phase_integrity_3rows',physics),
                      ('unvalidated_OR',anomaly|physics)]:
        print(json.dumps({'test':'S1_alt_reserved_run','detector':name,
                          'no_alt_fit':True,'no_alt_threshold_tuning':True,
                          **metrics(label,pred)}))


if __name__=='__main__':main()
