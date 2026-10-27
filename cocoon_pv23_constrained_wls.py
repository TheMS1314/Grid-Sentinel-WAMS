"""Limited 9-P-channel WLS projection onto 3 feeder-balance constraints.

This is a linear KCL-constrained weighted measurement correction, NOT full
nonlinear AC bus-voltage state estimation, LNR testing, or production FDII.
"""
import argparse
import json
import numpy as np
from cocoon_pv23_topology_balance import load,INPUTS,BRANCH1,BRANCH2,JUNCTION


def constraint_matrix():
    matrix=np.zeros((3,len(INPUTS)))
    for key in BRANCH1:matrix[0,INPUTS.index(key)]=1
    for key in BRANCH2:matrix[1,INPUTS.index(key)]=1
    matrix[2,INPUTS.index(JUNCTION[0])]=1
    for key in JUNCTION[1:]:matrix[2,INPUTS.index(key)]=-1
    assert np.linalg.matrix_rank(matrix)==3
    return matrix


def projection(record,c,variance_mode='as_variance'):
    power=np.array([record['measurement'][x] for x in INPUTS],float)
    uncertainty=np.array([max(1e-12,abs(record['std_2'][x])) for x in INPUTS],float)
    variance=uncertainty if variance_mode=='as_variance' else uncertainty**2
    variance=np.maximum(variance,1e-12)
    cdct=(c*variance)@c.T
    innovation=c@power
    lagrange=np.linalg.solve(cdct,innovation)
    corrected_delta=variance*(c.T@lagrange)
    adjusted=power-corrected_delta
    standardized=np.abs(corrected_delta)/np.sqrt(variance)
    weighted_residual=float(np.sqrt(max(0.,innovation@lagrange)))
    return weighted_residual,standardized,float(np.linalg.norm(c@adjusted))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='COCOON_PV23_measurements.zip')
    p.add_argument('--variance-mode',choices=['as_variance','as_std'],default='as_variance')
    args=p.parse_args()
    records=load(args.archive)
    c=constraint_matrix()
    regimes={label:[r for r in records if r['power_factor']==label]
             for label in ['090neg','090pos','100pos']}
    def group_values(group):return np.array([projection(r,c,args.variance_mode)[0] for r in group])
    training=group_values(regimes['090neg']);calibration=group_values(regimes['090pos'])
    independent=group_values(regimes['100pos'])
    th=float(np.quantile(calibration,.99))
    print(json.dumps({'model':'linear KCL-constrained weighted projection, NOT full AC WLS',
                      'variance_mode_assumed':args.variance_mode,
                      'constraint_rank':int(np.linalg.matrix_rank(c)),
                      'input_P_channels':len(INPUTS),'clean_per_regime':100,
                      'threshold_q99_calibration_only':round(th,5),
                      'heldout_clean_false_alerts':int((independent>th).sum()),
                      'heldout_clean_total':len(independent),
                      'heldout_clean_fpr':round(float((independent>th).mean()),4),
                      'note':'Measurement uncertainty file semantics and true AC losses '
                             'are not verified; detector is posthoc exploratory.'}))
    for amplitude in [.05,.1,.2,.4]:
        clean_ok=0;detect=0;rank_correct=0;projection_error=[]
        for record in regimes['100pos']:
            clean_score=projection(record,c,args.variance_mode)[0]
            for i,target in enumerate(INPUTS):
                changed=dict(record);changed['measurement']=dict(record['measurement'])
                original=float(record['measurement'][target]);
                changed['measurement'][target]+=amplitude*max(abs(original),.01)
                score,attribution,err=projection(changed,c,args.variance_mode)
                projection_error.append(err)
                if clean_score>th:continue
                clean_ok+=1
                if score>th:
                    detect+=1
                    rank_correct+=int(np.argmax(attribution)==i)
        print(json.dumps({'synthetic_single_sensor_P_fraction':amplitude,
                          'total_trials':900,'eligible_unflagged_clean_control':clean_ok,
                          'new_detected':detect,
                          'conditional_detection_rate':round(detect/max(1,clean_ok),4),
                          'top1_attribution_correct_when_detected':round(rank_correct/max(1,detect),4),
                          'max_post_projection_KCL_residual':round(max(projection_error),9),
                          'real_attack_F1':None}))


if __name__=='__main__':main()
