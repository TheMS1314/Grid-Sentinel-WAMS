"""Frozen-model replay audit with episodes, lag and synthetic invariance probes.

No parameters are fitted to the tested S1--S6 scenarios. All reported datasets
and attack labels are publisher-provided; the selected feature head is posthoc.
"""
import argparse
import json
import math
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd


def wilson(k, n, z=1.96):
    if not n:
        return [None, None]
    p = k / n
    d = 1 + z*z/n
    a = (p + z*z/(2*n))/d
    b = z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [round(max(0,a-b), 5),round(min(1,a+b), 5)]


def streaks(mask, times):
    """Contiguous true intervals, broken on >1.5s or invalid time gaps."""
    groups=[]
    start=None
    for i,flag in enumerate(mask):
        gap = i and (not np.isfinite(times[i]-times[i-1]) or
                     times[i]-times[i-1] > 1.5 or times[i]-times[i-1] <= 0)
        if start is not None and (not flag or gap):
            groups.append((start,i-1))
            start=None
        if flag and start is None:start=i
    if start is not None:groups.append((start,len(mask)-1))
    return groups


def replay(df, model):
    devices=model['required_devices']
    keys=[f'{d}.{field}' for d in devices for field in model['required_fields']]
    values=df.reindex(columns=keys).apply(pd.to_numeric,errors='coerce')
    valid=np.isfinite(values.to_numpy(dtype=float)).all(axis=1)
    valid &= (values.abs()<=1e12).all(axis=1).to_numpy()
    features={}
    for d in devices:
        p=values[f'{d}.p_sum3'].to_numpy(float)
        q=values[f'{d}.q_sum3'].to_numpy(float)
        s=values[f'{d}.s_sum3'].to_numpy(float)
        denom=np.maximum(model['relative_denominator_floor'],np.maximum(abs(p),abs(s)))
        for qty in ['p','q','s']:
            total=values[f'{d}.{qty}_sum3'].to_numpy(float)
            phase=sum(values[f'{d}.{qty}ln{i}'].to_numpy(float) for i in [1,2,3])
            features[f'{d}.sum_{qty}']=abs(total-phase)/denom
    scores=np.stack([abs(features[k]-model['center'][k])/model['scale'][k]
                     for k in model['features']])
    row_score=np.nanmax(np.where(np.isfinite(scores),scores,-np.inf),axis=0)
    raw=(row_score>model['threshold'])&valid
    stamps=pd.to_datetime(df['timestamp'],utc=True,errors='coerce')
    seconds=stamps.astype('int64').to_numpy()/1e9
    seconds[stamps.isna().to_numpy()]=np.nan
    if np.any(~np.isfinite(seconds)):
        raise ValueError('Invalid source dataset timestamp')
    confirmed=np.zeros(len(df),bool)
    n=0
    for i,hit in enumerate(raw):
        if i and (seconds[i]-seconds[i-1]<=0 or seconds[i]-seconds[i-1] >model['largest_tolerated_gap_seconds']):
            n=0
        n=n+1 if hit else 0
        confirmed[i]=n>=model['confirmation_consecutive_1hz_rows']
    return valid,raw,confirmed,seconds


def report(name,df,model):
    valid,raw,pred,seconds=replay(df,model)
    truth=df['attack_active'].astype(bool).to_numpy()
    tp=int(np.sum(pred&truth));fp=int(np.sum(pred&~truth))
    fn=int(np.sum(~pred&truth));tn=int(np.sum(~pred&~truth))
    truth_eps=streaks(truth,seconds)
    alarm_eps=streaks(pred&~truth,seconds)
    lags=[];hit_episodes=0
    episode_details=[]
    for lo,hi in truth_eps:
        found=np.flatnonzero(pred[lo:hi+1])
        delay=round(float(seconds[lo+found[0]]-seconds[lo]),3) if len(found) else None
        if len(found):
            hit_episodes+=1
            lags.append(delay)
        episode_details.append({'start':str(df['timestamp'].iloc[lo]),
                                'activity_rows':hi-lo+1,
                                'phase_labels':sorted(df['attack_phase'].iloc[lo:hi+1].dropna().astype(str).unique().tolist()) if 'attack_phase' in df else [],
                                'alarm_rows':int(pred[lo:hi+1].sum()),
                                'detected':bool(len(found)),
                                'first_alert_lag_s':delay})
    clean_seconds=float(np.sum(~truth))
    phases={}
    if 'attack_phase' in df:
        phase_column=df['attack_phase'].fillna('unlabeled').astype(str).to_numpy()
        for phase in sorted(set(phase_column[truth])):
            mask=truth&(phase_column==phase)
            phases[phase]={'labeled_rows':int(mask.sum()),
                           'review_rows':int(np.sum(pred&mask)),
                           'row_recall':round(float(np.mean(pred[mask])),5)}
    return {
        'scenario':name,'rows':len(df),'labeled_attack_rows':int(truth.sum()),
        'invalid_rows':int(np.sum(~valid)),
        'invalid_rows_during_attack_activity':int(np.sum(~valid&truth)),
        'invalid_rows_during_benign_activity':int(np.sum(~valid&~truth)),
        'tp':tp,'fp':fp,'fn':fn,'tn':tn,
        'row_recall':round(tp/max(1,tp+fn),5),
        'row_precision':round(tp/max(1,tp+fp),5),
        'row_f1':round(2*tp/max(1,2*tp+fp+fn),5),
        'row_recall_wilson_95':wilson(tp,tp+fn),
        'clean_row_fpr':round(fp/max(1,fp+tn),5),
        'clean_row_fpr_wilson_95':wilson(fp,fp+tn),
        'attack_episodes':len(truth_eps),'detected_attack_episodes':hit_episodes,
        'attack_episode_recall':round(hit_episodes/max(1,len(truth_eps)),5),
        'attack_episode_details':episode_details,
        'attack_phase_breakdown':phases,
        'false_alarm_episodes':len(alarm_eps),
        'false_episodes_per_clean_hour':round(len(alarm_eps)*3600/max(1,clean_seconds),3),
        'median_first_alert_lag_s':round(float(np.median(lags)),3) if lags else None,
        'longest_false_alarm_episode_rows':max([hi-lo+1 for lo,hi in alarm_eps],default=0),
        'notes':'posthoc selected feature family; attack_active labels are activity, not sample compromise',
    }


def synthetic_probes(model):
    """Explicitly bounded numeric counterexamples, never genuine attack labels."""
    devices=model['required_devices']
    times=pd.date_range('2026-01-01',periods=8,freq='s',tz='UTC')
    data=[]
    for t in times:
        row={'timestamp':t.isoformat(),'attack_active':False}
        for d in devices:
            for qty,total in [('p',3000.),('q',300.),('s',3030.)]:
                row[f'{d}.{qty}_sum3']=total
                for i in [1,2,3]:row[f'{d}.{qty}ln{i}']=total/3
        data.append(row)
    frame=pd.DataFrame(data)
    _,_,clean,_=replay(frame,model)
    one=frame.copy()
    key=f'{devices[0]}.p_sum3'
    one.loc[2:,key]*=1.5
    _,_,isolated,_=replay(one,model)
    coherent=frame.copy()
    coherent.loc[2:,key]*=1.5
    for i in [1,2,3]:coherent.loc[2:,f'{devices[0]}.pln{i}']*=1.5
    _,_,coherent_alarm,_=replay(coherent,model)
    missing=frame.copy();missing.loc[3,f'{devices[0]}.pln1']=np.nan
    valid,_,missing_alarm,_=replay(missing,model)
    return {
      'scenario':'SYNTHETIC_COUNTEREXAMPLES_NOT_REAL_ATTACKS',
      'clean_review_rows':int(clean.sum()),
      'isolated_total_change_review_rows':int(isolated.sum()),
      'coherent_total_and_phases_review_rows':int(coherent_alarm.sum()),
      'missing_measurement_abstention_rows':int((~valid).sum()),
      'missing_measurement_review_rows':int(missing_alarm.sum()),
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    parser.add_argument('--model',default='smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json')
    parser.add_argument('--output',help='Optional machine-readable JSONL results file')
    args=parser.parse_args()
    model=json.loads(Path(args.model).read_text())
    lines=[]
    def emit(obj):
        line=json.dumps(obj,allow_nan=False)
        lines.append(line)
        print(line)
    emit({'study':'Phase22 frozen-model temporal and uncertainty audit',
          'model_id':model['model_id'],'threshold':model['threshold'],
          'selection':'posthoc from previously inspected Data4Cyber; NOT blind validation'})
    with zipfile.ZipFile(args.archive) as archive:
        members=sorted(x for x in archive.namelist() if x.endswith('/dataset.csv')
                       and not x.split('/')[-2].endswith('_alt'))
        for member in members:
            name=member.split('/')[-2]
            frame=pd.read_csv(archive.open(member),low_memory=False)
            if name.startswith('S0_'):
                frame=frame.iloc[int(.8*len(frame)):].reset_index(drop=True)
            emit(report(name,frame,model))
    emit(synthetic_probes(model))
    if args.output:
        Path(args.output).write_text('\n'.join(lines)+'\n',encoding='utf-8')


if __name__=='__main__': main()
