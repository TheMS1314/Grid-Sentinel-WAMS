"""COCOON pv_2_3: published-network active power conservation audit.

Uses recorded power snapshots and the known feeder layout; no PHIL data or
attack labels are claimed. Synthetic sensor injections are math-only trials.
"""
import argparse
import json
import re
import zipfile
import numpy as np
import pandas as pd


BRANCH1 = ['P_POIMV_MV0101','P_LV0101','P_LV0102','P_LV0103']
BRANCH2 = ['P_POIMV_MV0201','P_LV0201','P_LV0202','P_LV0203']
JUNCTION = ['P_POI_POIMV','P_POIMV_MV0101','P_POIMV_MV0201']
INPUTS=sorted(set(BRANCH1+BRANCH2+JUNCTION))


def load(path):
    records=[]
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.endswith('/measurements.json'):continue
            p=json.load(z.open(name))
            std=json.load(z.open(name.replace('measurements.json','std_2.json')))
            m=re.search(r'pv_2_3_(\d\d\d)_([\d_]+)_pf_(\w+)/',name)
            if not m:raise ValueError(f'Unexpected operating-point label: {name}')
            if not set(INPUTS).issubset(p) or not set(INPUTS).issubset(std):
                raise ValueError('Required active-power measurements or uncertainty fields missing')
            records.append({'path':name,'case_id':m.group(1)+'_'+m.group(2),
                            'power_factor':m.group(3),'measurement':p,'std_2':std})
    return sorted(records,key=lambda r:r['path'])


def scores(record):
    p=record['measurement'];s=record['std_2']
    residual=[sum(p[x] for x in BRANCH1),sum(p[x] for x in BRANCH2),
              p[JUNCTION[0]]-p[JUNCTION[1]]-p[JUNCTION[2]]]
    # Relative to author's uncertainty field as an empirical normalization
    # only: `std_2` semantics must be verified before treating these as z-scores.
    normalizer=[sum(abs(s[x]) for x in BRANCH1),
                sum(abs(s[x]) for x in BRANCH2),
                sum(abs(s[x]) for x in JUNCTION)]
    return np.array([abs(v)/max(1e-6,t) for v,t in zip(residual,normalizer)])


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--archive',default='COCOON_PV23_measurements.zip')
    a.add_argument('--fixed-multiplier',type=float,
                   help='Exploratory conservative multiplier on summed uncertainty fields; '
                        'evaluates without learned clean-calibration threshold')
    args=a.parse_args()
    records=load(args.archive)
    # Reserve all pf=100pos as one entirely untouched measurement-condition
    # test group; train/calibrate on pf=090neg, then assess pf=090pos as second
    # cross-regime control. Case times are shared across these operating modes.
    train=[r for r in records if r['power_factor']=='090neg']
    check=[r for r in records if r['power_factor']=='090pos']
    test=[r for r in records if r['power_factor']=='100pos']
    if not train or not check or not test:
        raise ValueError('Expected all three power-factor groups')
    tr=np.array([scores(r) for r in train]);ca=np.array([scores(r) for r in check]);te=np.array([scores(r) for r in test])
    # Threshold on *clean calibration regime* only; test pf100 remains held-out.
    thresholds=np.quantile(ca,.99,axis=0)
    if args.fixed_multiplier is not None:
        thresholds=np.full(3,args.fixed_multiplier)
    base=te>thresholds
    print(json.dumps({'protocol':'pf090neg inspect/train, pf090pos clean calibration, '
                       'pf100pos unseen clean test; no attack labels or test threshold tuning',
                      'records':len(records),'counts':[len(train),len(check),len(test)],
                      'three_feeder_balance_thresholds':thresholds.round(4).tolist(),
                      'fixed_multiplier':args.fixed_multiplier,
                      'train_median_residuals':np.median(tr,axis=0).round(4).tolist(),
                      'test_median_residuals':np.median(te,axis=0).round(4).tolist(),
                      'control_flagged_snapshots':int(np.any(base,axis=1).sum()),
                      'control_rate':round(float(np.any(base,axis=1).mean()),4)}))
    rng=np.random.default_rng(20261025)
    # One-vulnerable-measurement FDI perturbation: selected meter target among
    # all 9 independently published active-power inputs, varying the amplitude.
    for factor in [.05,.1,.2,.4]:
        flags=[]
        eligible=0
        for r in test:
            for target in INPUTS:
                manipulated=dict(r)
                manipulated['measurement']=dict(r['measurement'])
                orig=float(manipulated['measurement'][target])
                # Use additive shift relative to typical network branch/base
                # amplitude, otherwise near-zero P makes attacks trivial.
                manipulated['measurement'][target]=orig+factor*max(abs(orig),.01)
                clean_control=not np.any(scores(r)>thresholds)
                eligible+=int(clean_control)
                additional=bool(np.any(scores(manipulated)>thresholds) and clean_control)
                flags.append(additional)
        print(json.dumps({'attack':'synthetic single P measurement additive change',
                          'amplitude':factor,'attack_trials':len(flags),
                          'additional_clean_pair_detected':int(sum(flags)),
                          'clean_control_eligible_trials':eligible,
                          'detection_given_clean_control':round(sum(flags)/max(1,eligible),4),
                          'detection_fraction':round(float(np.mean(flags)),4),
                          'independent_real_attack_F1':None}))
    # Coordinated stealth test: alter inverter 1 and matching feeder subtotal
    # by equal and opposite additive amounts, preserving local feeder balance.
    stealth=[]
    for r in test:
        changed=dict(r); changed['measurement']=dict(r['measurement'])
        amount=.2*max(abs(changed['measurement']['P_LV0101']),.01)
        changed['measurement']['P_LV0101']+=amount
        changed['measurement']['P_POIMV_MV0101']-=amount
        # This changes the junction: simultaneously adjust upstream POI to
        # maintain all three conservation equalities exactly.
        changed['measurement']['P_POI_POIMV']-=amount
        stealth.append(bool(np.any(scores(changed)>thresholds) and
                            not np.any(scores(r)>thresholds)))
    print(json.dumps({'attack':'synthetic coordinated conservation-preserving 3-P modification',
                      'attack_trials':len(stealth),
                      'additional_clean_pair_detected':int(sum(stealth)),
                      'detection_fraction':round(float(np.mean(stealth)),4),
                      'interpretation':'conservation-only detector cannot identify graph-consistent compromises'}))


if __name__=='__main__':main()
