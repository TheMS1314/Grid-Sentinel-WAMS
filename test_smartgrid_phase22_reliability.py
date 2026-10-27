"""Offline replay assertions, including strict parity with the API engine."""
import json
import unittest
from pathlib import Path
import sys

import pandas as pd

from smartgrid_phase22_reliability import replay, synthetic_probes, wilson, streaks
from smartgrid_phase23_failure_attribution import scores_by_identity

sys.path.insert(0,str(Path(__file__).resolve().parent/'smartgrid_platform'/'backend'))
from app.detector_engine import assess  # noqa: E402


MODEL=json.loads(Path('smartgrid_platform/backend/model/smartgrid_meter_integrity_model.json').read_text())


class ReliabilityTest(unittest.TestCase):
    def test_confidence_interval_boundaries(self):
        self.assertEqual(wilson(0,0),[None,None])
        self.assertEqual(wilson(0,100)[0],0)
        self.assertEqual(wilson(100,100)[1],1)

    def test_episode_gap_breaks(self):
        self.assertEqual(streaks([True,True,True,False,True],[0.,1.,5.,6.,7.]),[(0,1),(2,2),(4,4)])

    def test_deliberate_coherent_counterexample(self):
        result=synthetic_probes(MODEL)
        self.assertGreater(result['isolated_total_change_review_rows'],0)
        self.assertEqual(result['coherent_total_and_phases_review_rows'],0)
        self.assertEqual(result['missing_measurement_abstention_rows'],1)

    def test_replay_parity(self):
        rows=[]
        for i in range(8):
            row={'timestamp':f'2026-01-01T00:00:{i:02d}+00:00','attack_active':False}
            for dev in MODEL['required_devices']:
                for qty,total in [('p',3000.),('q',300.),('s',3030.)]:
                    row[f'{dev}.{qty}_sum3']=total
                    for phase in (1,2,3):row[f'{dev}.{qty}ln{phase}']=total/3
            if i>=2:row[MODEL['required_devices'][0]+'.p_sum3']*=1.5
            rows.append(row)
        frame=pd.DataFrame(rows)
        _,_,replayed,_=replay(frame,MODEL)
        input_rows=[{'timestamp':r['timestamp'],**{f'{dev}.{field}':r[f'{dev}.{field}']
                     for dev in MODEL['required_devices'] for field in MODEL['required_fields']}}
                    for r in rows]
        engine=assess(input_rows,MODEL)
        direct=[r['status']=='LOCAL_PHYSICS_REVIEW' for r in engine['rows']]
        self.assertEqual(direct,replayed.tolist())

    def test_feature_decomposition_matches_replay(self):
        frame=pd.DataFrame([{**{'timestamp':'2026-01-01T00:00:00+00:00', 'attack_active':False},
                             **{f'{device}.{quantity}_sum3':total for device in MODEL['required_devices']
                                for quantity,total in [('p',3000.),('q',300.),('s',3030.)]},
                             **{f'{device}.{quantity}ln{i}':total/3 for device in MODEL['required_devices']
                                for quantity,total in [('p',3000.),('q',300.),('s',3030.)]
                                for i in (1,2,3)}}])
        raw=replay(frame,MODEL)[1]
        decomposed=(scores_by_identity(frame,MODEL)>MODEL['threshold']).any(axis=1).to_numpy()
        self.assertEqual(raw.tolist(),decomposed.tolist())


if __name__=='__main__':unittest.main()
