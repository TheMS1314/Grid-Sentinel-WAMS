"""Per-phase root-cause audit of frozen meter identities; no parameter fitting."""
import argparse
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from smartgrid_phase22_reliability import replay


def scores_by_identity(df, model):
    residual={}
    for device in model['required_devices']:
        p=pd.to_numeric(df[f'{device}.p_sum3'],errors='coerce').to_numpy(float)
        s=pd.to_numeric(df[f'{device}.s_sum3'],errors='coerce').to_numpy(float)
        denom=np.maximum(model['relative_denominator_floor'],np.maximum(np.abs(p),np.abs(s)))
        for q in 'pqs':
            total=pd.to_numeric(df[f'{device}.{q}_sum3'],errors='coerce').to_numpy(float)
            phases=np.sum(np.vstack([pd.to_numeric(df[f'{device}.{q}ln{i}'],errors='coerce').to_numpy(float)
                                       for i in (1,2,3)]),axis=0)
            name=f'{device}.sum_{q}'
            residual[name]=np.abs(np.abs(total-phases)/denom-model['center'][name])/model['scale'][name]
    return pd.DataFrame(residual)


def analyze(df,model,name):
    valid,raw,review,_=replay(df,model)
    values=scores_by_identity(df,model)
    report=[]
    for phase,sub in df.groupby('attack_phase',sort=True):
        ids=sub.index.to_numpy()
        activity=bool(sub['attack_active'].astype(bool).any())
        if not activity:continue
        row_hits=(values.loc[ids] >model['threshold'])
        counts=row_hits.sum(axis=0).sort_values(ascending=False)
        ordered=[{'identity':key,'raw_threshold_rows':int(value)}
                 for key,value in counts.head(5).items() if value]
        report.append({
          'scenario':name,'phase':str(phase),'rows':len(ids),
          'review_rows':int(review[ids].sum()),
          'rows_any_identity_threshold':int(raw[ids].sum()),
          'valid_rows':int(valid[ids].sum()),
          'review_rate':round(float(review[ids].mean()),5),
          'top_triggered_identities':ordered,
          'note':'labels denote attack activity; top feature is inconsistent channel, not attacker attribution',
        })
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    p.add_argument('--model',default='smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json')
    p.add_argument('--output')
    args=p.parse_args()
    model=json.loads(Path(args.model).read_text())
    results=[]
    with zipfile.ZipFile(args.archive) as archive:
        paths=sorted(x for x in archive.namelist() if x.endswith('/dataset.csv') and
                     x.split('/')[-2].startswith(tuple(f'S{i}_' for i in range(1,7))))
        for path in paths:
            frame=pd.read_csv(archive.open(path),low_memory=False)
            frame.index=range(len(frame))
            results.extend(analyze(frame,model,path.split('/')[-2]))
    for row in results:print(json.dumps(row))
    if args.output:
        Path(args.output).write_text('\n'.join(json.dumps(row) for row in results)+'\n',encoding='utf8')


if __name__=='__main__': main()
