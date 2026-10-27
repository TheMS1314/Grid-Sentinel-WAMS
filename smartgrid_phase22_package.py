"""Build a reproducible source release without raw research data or secrets."""
import hashlib
import zipfile
from pathlib import Path


BASE=Path(__file__).resolve().parent
ROOT='GridSentinel_Phase64_2026-10-27'
OUTPUT=BASE/'GridSentinel_Phase64_Codespaces_Ready_2026-10-27.zip'
RESEARCH_SCRIPTS=[
 'smartgrid_phase22_reliability.py','test_smartgrid_phase22_reliability.py',
 'smartgrid_phase23_failure_attribution.py',
 'data4cyber_passive_modbus_audit.py',
 'data4cyber_modbus_allowlist_benchmark.py',
 'data4cyber_two_lane_benchmark.py',
 'data4cyber_passive_mqtt_audit.py',
 'test_data4cyber_protocol_lane.py',
 'data4cyber_passive_arp_audit.py',
 'data4cyber_arp_two_lane_benchmark.py',
 'test_data4cyber_arp_lane.py',
 'data4cyber_arp_policy_sweep.py','test_data4cyber_arp_policy.py',
 'data4cyber_arp_negative_control.py','test_data4cyber_arp_negative_control.py',
 'data4cyber_arp_uncertainty.py','test_data4cyber_arp_uncertainty.py',
 'arp_identity_ambiguity.py','test_arp_identity_ambiguity.py',
 'prospective_site_validation.py','test_prospective_site_validation.py',
 'data4cyber_modbus_register_audit.py','test_data4cyber_modbus_register_audit.py',
 'data4cyber_s6_price_shift_audit.py','test_data4cyber_s6_price_shift_audit.py',
 'data4cyber_four_lane_fusion.py','test_data4cyber_four_lane_fusion.py',
 'data4cyber_temporal_false_alerts.py','test_data4cyber_temporal_false_alerts.py',
 'offline_four_lane_replay.py','test_offline_four_lane_replay.py',
 'offline_observation_ingest.py','test_offline_observation_ingest.py',
 'offline_selective_validation.py','test_offline_selective_validation.py',
 'offline_blind_site_run.py','test_offline_blind_site_run.py',
 'data4cyber_price_shift_stress.py','test_data4cyber_price_shift_stress.py',
 'data4cyber_price_context_policy.py','test_data4cyber_price_context_policy.py',
 'offline_signed_tariff_verifier.py','test_offline_signed_tariff_verifier.py',
 'offline_tariff_context_bridge.py','test_offline_tariff_context_bridge.py',
 'test_offline_signed_tariff_integration.py',
 'external_mitm_experiment_holdout.py','test_external_mitm_experiment_holdout.py',
 'external_mitm_domain_transfer.py','test_external_mitm_domain_transfer.py',
 'external_mitm_leave_domain_out.py','test_external_mitm_leave_domain_out.py',
 'prospective_site_validation_v2.py','test_prospective_site_validation_v2.py',
 'cyber4ot_independent_modbus_probe.py','test_cyber4ot_independent_modbus_probe.py',
 'cyber4ot_vantage_shift_negative_control.py','test_cyber4ot_vantage_shift_negative_control.py',
 'cyber4ot_full_capture_family_audit.py','test_cyber4ot_full_capture_family_audit.py',
 'cyber4ot_benign_calibrated_rate.py','test_cyber4ot_benign_calibrated_rate.py',
 'cyber4ot_maintenance_counterfactual.py','test_cyber4ot_maintenance_counterfactual.py',
 'zeroswarm_independent_pcap_validation.py','test_zeroswarm_independent_pcap_validation.py',
 'zeroswarm_tcp_scan_negative_control.py','test_zeroswarm_tcp_scan_negative_control.py',
 'cyber4ot_frozen_tcp_cross_dataset.py','test_cyber4ot_frozen_tcp_cross_dataset.py',
 'cyber4ot_arp_sweep_complement.py','test_cyber4ot_arp_sweep_complement.py',
 'smartgrid_research_acceptance.py',
 'data4cyber_reserved_run_audit.py','data4cyber_observability_audit.py',
 'data4cyber_physics_invariants.py','data4cyber_independent_validation.py',
 'cocoon_pv23_topology_balance.py','cocoon_pv23_constrained_wls.py',
 'cocoon_pv23_published_smart_audit.py',
 'smartgrid_phase22_package.py',
]
REPORTS=[
 'SmartGrid_Phase17_Physics_Integrity_Ablation_2026-10-25.md',
 'SmartGrid_Phase19_Limited_WLS_and_Acceptance_2026-10-25.md',
 'SmartGrid_Phase20_Local_Deployment_2026-10-25.md',
 'SmartGrid_Phase21_Fullstack_Implementation_2026-10-25.md',
 'SmartGrid_Phase22_Next_Level_Audit_2026-10-26.md',
 'SmartGrid_Phase22_Replay_Results_2026-10-26.jsonl',
 'SmartGrid_Phase23_Attack_Family_Diagnosis_2026-10-26.md',
 'SmartGrid_Phase23_Attribution_2026-10-26.jsonl',
 'SmartGrid_Phase24_Protocol_Lane_Results_2026-10-26.md',
 'SmartGrid_Phase24_Modbus_Packet_Audit_2026-10-26.jsonl',
 'SmartGrid_Phase24_Modbus_Allowlist_2026-10-26.jsonl',
 'SmartGrid_Phase24_Two_Lane_Results_2026-10-26.jsonl',
 'SmartGrid_Phase24_Modbus_Hold5_Sensitivity_2026-10-26.jsonl',
 'SmartGrid_Phase24_MQTT_Observability_2026-10-26.jsonl',
 'SmartGrid_Phase25_ARP_Coordinated_MITM_2026-10-26.md',
 'SmartGrid_Phase25_ARP_Identity_2026-10-26.jsonl',
 'SmartGrid_Phase25_ARP_Fusion_2026-10-26.jsonl',
 'SmartGrid_Phase25_ARP_Hold5_Sensitivity_2026-10-26.jsonl',
 'SmartGrid_Phase26_ARP_Policy_Tradeoff_2026-10-26.md',
 'SmartGrid_Phase26_ARP_Policy_Sweep_2026-10-26.jsonl',
 'SmartGrid_Phase27_NonARP_Negative_Control_2026-10-26.md',
 'SmartGrid_Phase27_NonARP_Negative_Control_2026-10-26.jsonl',
 'SmartGrid_Phase28_ZeroAlert_Uncertainty_2026-10-26.md',
 'SmartGrid_Phase28_ARP_ZeroAlert_Uncertainty_2026-10-26.json',
 'SmartGrid_Phase29_Private_API_Hardening_2026-10-26.md',
 'SmartGrid_Phase30_Operational_Reliability_2026-10-26.md',
 'SmartGrid_Phase31_Versioned_Database_Migrations_2026-10-26.md',
 'SmartGrid_Phase32_ARP_Identity_Maintenance_Limit_2026-10-26.md',
 'SmartGrid_Phase32_ARP_Identity_Ambiguity_2026-10-26.json',
 'SmartGrid_Phase33_Blind_Site_Validation_2026-10-26.md',
 'SmartGrid_Phase34_Model_Commitment_and_Alert_Burden_2026-10-26.md',
 'SmartGrid_Phase35_Backup_Integrity_and_Local_Smoke_2026-10-26.md',
 'SmartGrid_Phase36_Four_Lane_Benchmark_2026-10-26.md',
 'SmartGrid_Phase36_Modbus_Register_Policy_2026-10-26.jsonl',
 'SmartGrid_Phase36_S6_Price_Domain_Shift_2026-10-26.json',
 'SmartGrid_Phase36_Four_Lane_Results_2026-10-26.json',
 'SmartGrid_Phase37_Lane_Ablation_and_Tradeoff_2026-10-26.md',
 'SmartGrid_Phase37_Four_Lane_Ablation_2026-10-26.json',
 'SmartGrid_Phase38_False_Alert_Timing_2026-10-26.md',
 'SmartGrid_Phase38_False_Alert_Timing_2026-10-26.json',
 'SmartGrid_Phase39_Frozen_Offline_Replay_Interface_2026-10-26.md',
 'SmartGrid_Phase40_Hash_Frozen_Offline_Event_Ingestion_2026-10-26.md',
 'SmartGrid_Phase41_Blind_Site_Selective_Validation_2026-10-26.md',
 'SmartGrid_Phase42_Sealed_Two_Stage_Evaluation_2026-10-26.md',
 'SmartGrid_Phase43_Private_Deployment_Preflight_2026-10-26.md',
 'SmartGrid_Phase44_Price_Regime_Robustness_2026-10-26.md',
 'SmartGrid_Phase44_Price_Shift_Stress_2026-10-26.json',
 'SmartGrid_Phase45_Price_Context_Tradeoff_2026-10-26.md',
 'SmartGrid_Phase45_Price_Context_Tradeoff_2026-10-26.json',
 'SmartGrid_Phase46_Signed_Tariff_Provenance_2026-10-26.md',
 'SmartGrid_Phase47_Tariff_Trust_and_Replay_Boundary_2026-10-26.md',
 'SmartGrid_Phase48_External_MITM_Holdout_2026-10-26.md',
 'SmartGrid_Phase48_External_MITM_Holdout_2026-10-26.json',
 'SmartGrid_Phase49_Domain_Transfer_and_Abstention_2026-10-26.md',
 'SmartGrid_Phase49_External_Domain_Transfer_2026-10-26.json',
 'SmartGrid_Phase50_Multi_Source_Transfer_2026-10-27.md',
 'SmartGrid_Phase50_Leave_Domain_Out_2026-10-27.json',
 'SmartGrid_Phase51_Independent_Site_Abstention_Acceptance_2026-10-27.md',
 'SmartGrid_Phase52_Cyber4OT_Passive_Packet_Holdout_2026-10-27.md',
 'SmartGrid_Phase52_Cyber4OT_Passive_Modbus_2026-10-27.json',
 'SmartGrid_Phase53_Cyber4OT_Benign_Vantage_Shift_2026-10-27.md',
 'SmartGrid_Phase53_Vantage_Shift_Negative_Control_2026-10-27.json',
 'SmartGrid_Phase54_Full_Cyber4OT_Capture_Audit_2026-10-27.md',
 'SmartGrid_Phase54_Full_Cyber4OT_Audit_2026-10-27.json',
 'SmartGrid_Phase55_Benign_Only_Rate_Calibration_2026-10-27.md',
 'SmartGrid_Phase55_Benign_Only_Rate_Calibration_2026-10-27.json',
 'SmartGrid_Phase56_Maintenance_Counterfactual_2026-10-27.md',
 'SmartGrid_Phase56_Maintenance_Counterfactual_2026-10-27.json',
 'SmartGrid_Phase57_Independent_ZeroSWARM_Domain_Shift_2026-10-27.md',
 'SmartGrid_Phase57_ZeroSWARM_External_PCAP_2026-10-27.json',
 'SmartGrid_Phase58_ZeroSWARM_Transport_Alternative_2026-10-27.md',
 'SmartGrid_Phase58_ZeroSWARM_TCP_Scan_Audit_2026-10-27.json',
 'SmartGrid_Phase59_Frozen_TCP_Cross_Dataset_2026-10-27.md',
 'SmartGrid_Phase59_Cyber4OT_Frozen_TCP_Transfer_2026-10-27.json',
 'SmartGrid_Phase60_ARP_Sweep_Complement_2026-10-27.md',
 'SmartGrid_Phase60_Cyber4OT_ARP_Sweep_2026-10-27.json',
 'SmartGrid_Phase61_Deployment_Acceptance_Gate_2026-10-27.md',
 'SmartGrid_Phase62_Private_Token_Authentication_2026-10-27.md',
 'SmartGrid_Phase63_Isolated_PostgreSQL_Restore_Drill_2026-10-27.md',
 'SmartGrid_Phase64_Codespaces_Automated_Deployment_2026-10-27.md',
]
EXAMPLES=['offline_site_policy_example.json','offline_observations_example.json']
BLOCKED={'node_modules','.venv','dist','__pycache__','.pytest_cache','.git','backups'}
ALLOWED_PLATFORM={'.dockerignore','.env.example','.gitignore','.css','.tsx','.ts','.json','.jsonl',
                  '.html','.yaml','.conf','.md','.txt','.ini','.py','Dockerfile'}


def main():
    files={}
    platform=BASE/'smartgrid_platform'
    for path in sorted(platform.rglob('*')):
        if not path.is_file() or BLOCKED.intersection(path.relative_to(platform).parts):continue
        if path.name=='.env' or path.name.startswith('library_'):continue
        if path.name not in ('Dockerfile','.dockerignore','.env.example','.gitignore') and path.suffix not in ALLOWED_PLATFORM:
            raise RuntimeError(f'Unexpected platform file: {path}')
        files[(Path(ROOT)/path.relative_to(BASE)).as_posix()]=path.read_bytes()
    for name in RESEARCH_SCRIPTS:
        p=BASE/name
        files[f'{ROOT}/{name}']=p.read_bytes()
    files[f'{ROOT}/requirements-tariff.txt']=(BASE/'requirements-tariff.txt').read_bytes()
    for name in REPORTS:
        p=BASE/'reports'/name
        if not p.exists():p=BASE/name
        files[f'{ROOT}/reports/{name}']=p.read_bytes()
    for name in EXAMPLES:
        p=BASE/'examples'/name
        files[f'{ROOT}/examples/{name}']=p.read_bytes()
    guide=BASE/'README.md'
    if (BASE/'SmartGrid_Phase22_DELIVERY_README.md').exists():guide=BASE/'SmartGrid_Phase22_DELIVERY_README.md'
    files[f'{ROOT}/README.md']=guide.read_bytes()
    for relative in ('.devcontainer/devcontainer.json','.gitignore','CODESPACES_START_HERE.md'):
        files[f'{ROOT}/{relative}']=(BASE/relative).read_bytes()

    digests='\n'.join(f'{hashlib.sha256(content).hexdigest()}  {name.removeprefix(ROOT+"/")}'
                       for name,content in sorted(files.items()))+'\n'
    files[f'{ROOT}/SHA256SUMS.txt']=digests.encode()
    with zipfile.ZipFile(OUTPUT,'w',zipfile.ZIP_DEFLATED,compresslevel=8) as release:
        for name,content in sorted(files.items()):
            entry=zipfile.ZipInfo(name, date_time=(2026,10,26,0,0,0))
            entry.compress_type=zipfile.ZIP_DEFLATED
            entry.external_attr=(0o100644<<16)
            release.writestr(entry,content,compress_type=zipfile.ZIP_DEFLATED,compresslevel=8)
    with zipfile.ZipFile(OUTPUT) as release:
        assert release.testzip() is None
        assert len(release.namelist())==len(files)
        assert not any(name.endswith('/.env') or 'node_modules/' in name or '.venv/' in name for name in release.namelist())
    print(f'{OUTPUT} | {len(files)} members | {OUTPUT.stat().st_size} bytes')


if __name__=='__main__':main()
