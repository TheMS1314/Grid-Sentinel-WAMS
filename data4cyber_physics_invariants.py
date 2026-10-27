"""Exploratory algebraic and cross-meter integrity checks on Data4Cyber v3.

No learned attack signatures. Calibration comes solely from chronological S0.
This was developed after examining Phase 16 outcome and is not a blind result.
"""
import argparse
import json
import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge
from sklearn.metrics import roc_auc_score
from data4cyber_independent_validation import load_scenarios,metrics

DEVICES = ['BSS-Inverter-AC-Meter','Load-A-AC-Meter','Load-B-AC-Meter',
           'PV-Inverter-AC-Meter','Substation-AC-Meter']


def meter_invariants(df,include_apparent=False):
    """Dimensionless self-consistency residuals, not network topology WLS."""
    ans={}
    for d in DEVICES:
        a=lambda k:pd.to_numeric(df[f'{d}.{k}'],errors='coerce').to_numpy(float)
        p,q,s=a('p_sum3'),a('q_sum3'),a('s_sum3')
        pl=a('pln1')+a('pln2')+a('pln3')
        ql=a('qln1')+a('qln2')+a('qln3')
        sl=a('sln1')+a('sln2')+a('sln3')
        # epsilon protects near-zero channels where ratios are unstable.
        denom=np.maximum(200.,np.maximum(np.abs(p),np.abs(s)))
        ans[d+'.sum_p']=np.abs(p-pl)/denom
        ans[d+'.sum_q']=np.abs(q-ql)/denom
        ans[d+'.sum_s']=np.abs(s-sl)/denom
        # For unbalanced 3-phase circuits, total S != sqrt(P_total^2+Q_total^2).
        # Excluded by default: it is contextual, not a strict physical law.
        if include_apparent:
            ans[d+'.apparent_context']=np.abs(s-np.hypot(p,q))/denom
    return pd.DataFrame(ans,index=df.index).replace([np.inf,-np.inf],np.nan)


def aggregate_frame(df):
    return pd.DataFrame({d:pd.to_numeric(df[f'{d}.p_sum3'],errors='coerce') for d in DEVICES},index=df.index)


def robust_peak(train,cal,test,q):
    center=train.median()
    scale=(train-center).abs().quantile(.9).clip(lower=.0005)
    # Identical train-only normalization, no test-specific centering.
    score=lambda frame:(np.abs((frame-center)/scale)).max(axis=1).fillna(0).to_numpy(float)
    th=float(np.quantile(score(cal),q))
    return score(test),th


def sustain(mask, frame, run_length):
    if run_length<=1:return mask
    times=pd.to_datetime(frame['timestamp'],utc=True,errors='coerce')
    gaps=times.diff().dt.total_seconds().to_numpy(float)
    out=np.zeros(len(mask),dtype=bool)
    run=0
    for i,detected in enumerate(mask):
        if i and (not np.isfinite(gaps[i]) or gaps[i]<=0 or gaps[i]>1.5):
            run=0
        run=(run+1) if detected else 0
        out[i]=run>=run_length
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    p.add_argument('--quantile',type=float,default=.99)
    p.add_argument('--head',choices=['local','balance','both'],default='both')
    p.add_argument('--confirm-rows',type=int,default=1,
                   help='Causal consecutive 1Hz rows to confirm; default raw flag')
    p.add_argument('--include-apparent-context',action='store_true',
                   help='Exploratory non-equality magnitude contextual residual')
    a=p.parse_args()
    datasets=load_scenarios(a.archive)
    base=datasets['S0_benign_baseline']
    n=len(base);train_end=int(.6*n);cal_end=int(.8*n)
    # Learned steady-state power-balance proxy: coefficients from clean only,
    # explicitly not power-flow state estimation or fixed Kirchhoff topology.
    balance0=aggregate_frame(base)
    sources=DEVICES[:-1]
    target=DEVICES[-1]
    source_train=balance0[sources].iloc[:train_end].ffill().fillna(0)
    target_train=balance0[target].iloc[:train_end].ffill().fillna(0)
    regression=Ridge(alpha=100.,random_state=None).fit(source_train,target_train)
    def balance_residual(frame):
        v=aggregate_frame(frame)
        prediction=regression.predict(v[sources].ffill().fillna(0))
        y=v[target].to_numpy(float)
        # A single residual that can be fitted on clean S0 and transferred.
        return pd.DataFrame({'substation_balance_proxy':np.abs(y-prediction)/10000},index=frame.index)
    def all_features(frame):
        parts=[]
        if a.head in ('local','both'):
            parts.append(meter_invariants(frame,a.include_apparent_context))
        if a.head in ('balance','both'):parts.append(balance_residual(frame))
        return pd.concat(parts,axis=1)
    x0=all_features(base)
    fit=x0.iloc[:train_end];cal=x0.iloc[train_end:cal_end]
    print(json.dumps({'head':a.head,'features':len(fit.columns),
                      'clean_train':train_end,'clean_calibration':cal_end-train_end,
                      'clean_test':n-cal_end,'threshold_quantile':a.quantile,
                      'confirm_rows':a.confirm_rows,
                      'balance_coefficients':{j:round(float(v),4) for j,v in zip(sources,regression.coef_)},
                      'warning':'posthoc exploratory architecture, only clean S0 calibration'}))
    for name,frame in datasets.items():
        if name=='S0_benign_baseline': frame=frame.iloc[cal_end:]
        score,threshold=robust_peak(fit,cal,all_features(frame),a.quantile)
        truth=frame.attack_active.astype(bool).to_numpy()
        confirmed=sustain(score>threshold,frame,a.confirm_rows)
        report=metrics(truth,confirmed)
        if truth.any() and (~truth).any():
            report['roc_auc']=round(float(roc_auc_score(truth,score)),4)
        report.update(scenario=name,head=a.head,threshold=round(threshold,4))
        print(json.dumps(report))


if __name__=='__main__':main()
