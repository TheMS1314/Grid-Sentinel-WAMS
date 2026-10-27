"""Recompute published COCOON pv_2_3 smart-attack detection-rate summaries.

These JSONs contain the authors' ALREADY-COMPUTED predictions, not independent
test inputs to our detector. Therefore never label them our model results.
"""
import argparse
import json
import zipfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',default='COCOON_PV23_smart_attacks.zip')
    args=p.parse_args()
    with zipfile.ZipFile(args.archive) as z:
        for name in ['with_MV','wo_MV','with_PSM']:
            a=json.load(z.open('Smart attacks/data/detection_'+name+'.json'))
            by_band={}
            all_flags=[]
            for band,cases in a.items():
                flags=[bool(f) for entry in cases.values() for f in entry['Detection']]
                if len(cases)!=10 or len(flags)!=200:
                    raise ValueError(f'Unexpected author experiment cardinality: {name} {band}')
                by_band[band]={'positive_simulations':sum(flags),'total_simulations':len(flags),
                               'positive_rate':round(sum(flags)/len(flags),4)}
                all_flags.extend(flags)
            print(json.dumps({'publisher_result_only':True,'sensor_configuration':name,
                              'simulations':len(all_flags),
                              'detected_simulations':sum(all_flags),
                              'detection_rate':round(sum(all_flags)/len(all_flags),4),
                              'by_attack_magnitude_percentage':by_band,
                              'disclaimer':'This is a reaggregation of the data authors published. '
                                           'It is not our independent WLS implementation, '
                                           'cross-site accuracy, or measured operational recall.'}))


if __name__=='__main__':main()
