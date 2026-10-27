"""One-command reproducibility smoke test and honest research-readiness gate.

The gate is intentionally stringent: a strong narrow detector must not be
reported as a complete multi-family cyber-physical protection system.
"""
import argparse
import json
import subprocess
import sys


CASES={
    'data4_reserved': ['data4cyber_reserved_run_audit.py'],
    'data4_s6_observability': ['data4cyber_observability_audit.py'],
    'data4_strict_physics': ['data4cyber_physics_invariants.py','--head','local','--confirm-rows','3'],
    'cocoon_pv_topology': ['cocoon_pv23_topology_balance.py','--fixed-multiplier','3'],
    'cocoon_constrained_weighted_projection': ['cocoon_pv23_constrained_wls.py'],
    'cocoon_publisher_reference': ['cocoon_pv23_published_smart_audit.py'],
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--strict',action='store_true',help='Exit with nonzero code if any readiness criteria fail')
    args=p.parse_args()
    runs={}
    for name,command in CASES.items():
        try:
            result=subprocess.run([sys.executable,'-B',*command],capture_output=True,
                                  text=True,timeout=120,check=True)
            lines=[json.loads(x) for x in result.stdout.splitlines() if x.strip()]
            runs[name]={'reproduced':bool(lines),'rows':lines}
        except (subprocess.SubprocessError,ValueError,json.JSONDecodeError) as exc:
            runs[name]={'reproduced':False,'error':str(exc)}
    reproducible=all(x['reproduced'] for x in runs.values())
    strict=next((x for x in runs['data4_strict_physics'].get('rows',[]) if x.get('scenario','').startswith('S4_')),None)
    reserve=next((x for x in runs['data4_reserved'].get('rows',[]) if x.get('detector')=='S0_three_phase_integrity_3rows'),None)
    s6=runs['data4_s6_observability'].get('rows',[{}])[0]
    topology=next((x for x in runs['cocoon_pv_topology'].get('rows',[]) if x.get('amplitude')==.2),None)
    quality={
        'scripts_reproduce':reproducible,
        'narrow_S4_MITM_demonstrated':strict is not None and strict['f1']>=.95,
        'separate_synthetic_P_balance_demonstrated':topology is not None and topology['detection_fraction']>=.95,
        'reserved_Modbus_generalization_sufficient':reserve is not None and reserve['f1']>=.8,
        'MQTT_authentic_price_available_preattack':s6.get('observed_benign_price_rows_before_first_attack',0)>0,
        # The following require independent evidence not provided by these files.
        'independent_blind_MITM_replication':False,
        'COCOON_PHIL_verified_attack_windows_and_network_model':False,
        'independent_protected_anchor_provenance':False,
        'multi_site_prospective_low_false_alarm_rate':False,
        'validated_full_AC_WLS_state_estimator':False,
    }
    status={'assessment':'RESEARCH_COMPLETE' if all(quality.values()) else 'RESEARCH_INCOMPLETE',
            'reproducibility_checks_passed':sum(v['reproduced'] for v in runs.values()),
            'reproducibility_checks_total':len(runs),
            'readiness_checks_passed':sum(quality.values()),
            'readiness_checks_total':len(quality),
            'readiness_checks':quality,
            'warning':'These gates are a reproducible quality checklist, not a percentage '
                      'estimate of time/effort remaining or an operational safety certification.'}
    print(json.dumps(status,indent=2))
    if args.strict and status['assessment']!='RESEARCH_COMPLETE':sys.exit(2)


if __name__=='__main__':main()
