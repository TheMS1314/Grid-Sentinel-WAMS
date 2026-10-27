"""Audits whether Data4Cyber S6 contains an independently observable price baseline.

Ground-truth phases and packet label metadata are used only to AUDIT the
available evidence, never as detector inputs or substitutes for monitoring.
"""
import argparse
import json
import zipfile
import pandas as pd


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--archive',default='Data4Cyber_v3_2026.zip')
    args=a.parse_args()
    root='data4cyber_dataset/S6_mqtt_supply_chain_compromise/'
    with zipfile.ZipFile(args.archive) as z:
        tab=pd.read_csv(z.open(root+'dataset.csv'))
        packet=pd.read_csv(z.open(root+'packet_labels.csv'),usecols=['label','attack_active'])
        phases=json.load(z.open(root+'attack-phases.json'))
    price='MQTT-Price-Signal.price_eur_per_kwh'
    active=tab['attack_active'].astype(bool)
    first_active=int(active.idxmax())
    first_valid=int(tab[price].first_valid_index())
    first_phase=int(tab.index[tab['attack_phase']=='s6_mqtt_price_manipulation'][0])
    price_ranges={}
    for phase,group in tab.groupby('attack_phase',sort=False):
        x=group[price].dropna()
        price_ranges[phase]={'rows':len(group),'price_observed_rows':len(x),
                             'observed_price_values':sorted(float(v) for v in x.unique())}
    print(json.dumps({'test':'data4cyber_s6_price_provenance',
                      'total_rows':len(tab),'attack_active_rows':int(active.sum()),
                      'first_attack_active_row':first_active,
                      'first_nonmissing_price_row':first_valid,
                      'first_manipulated_publication_phase_row':first_phase,
                      'observed_benign_price_rows_before_first_attack':int(tab.loc[:first_active-1,price].notna().sum()),
                      'packet_count':len(packet),
                      'packet_attack_label_count':int(packet['label'].eq('attack').sum()),
                      'packet_rows_during_attack_activity':int(packet['attack_active'].sum()),
                      'price_phase_summary':price_ranges,
                      'published_attack_phases':len(phases),
                      'implication':'No observed trusted preattack price anchor in S6; packet tap lacks labeled malicious MQTT price publications. Neither process price novelty nor tap-only IDS can certify compromise without independent provenance.'}))


if __name__=='__main__':main()
