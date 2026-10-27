import os
from datetime import datetime, timedelta, timezone

# The default runtime refuses protected API access without a private secret.
# Tests explicitly opt out except in dedicated authentication assertions.
os.environ.setdefault('GRID_SENTINEL_AUTH_REQUIRED', '0')

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


engine = create_engine(
    'sqlite+pysqlite:///:memory:',
    connect_args={'check_same_thread': False},
    poolclass=StaticPool,
)
Base.metadata.create_all(engine)
TestSession = sessionmaker(bind=engine, expire_on_commit=False)


def override_get_db():
    db: Session = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


DEVICES = [
    'BSS-Inverter-AC-Meter', 'Load-A-AC-Meter', 'Load-B-AC-Meter',
    'PV-Inverter-AC-Meter', 'Substation-AC-Meter',
]


def sample_rows():
    rows=[]
    first=datetime(2026,3,5,13,19,0,tzinfo=timezone.utc)
    for index in range(6):
        values={}
        for device in DEVICES:
            base=5000.0
            power=base*1.4 if device.startswith('PV-') and index>=2 else base
            per_phase=base/3
            quantities={
                'p_sum3':power,'q_sum3':300,'s_sum3':5100,
                'pln1':per_phase,'pln2':per_phase,'pln3':per_phase,
                'qln1':100,'qln2':100,'qln3':100,
                'sln1':1700,'sln2':1700,'sln3':1700,
            }
            values.update({f'{device}.{key}':value for key,value in quantities.items()})
        rows.append({'timestamp':(first+timedelta(seconds=index)).isoformat(), 'values':values})
    return rows


def test_health_model_and_ready():
    assert client.get('/api/health').json()['status']=='alive'
    assert client.get('/api/ready').json()['database']=='connected'
    info=client.get('/api/model').json()
    assert info['features']==15
    assert info['status']=='research_only'
    assert len(info['required_devices'])==5


def test_frozen_research_evidence_is_explicitly_historical():
    response=client.get('/api/research-evidence')
    assert response.status_code==200
    body=response.json()
    assert body['status']=='HISTORICAL_EXPLORATORY_NOT_FIELD_VALIDATED'
    scenarios=[r for r in body['records'] if 'scenario' in r]
    assert any(r['scenario']=='S4_arp_spoof_loads_pv_two_phase' for r in scenarios)
    assert any(r['scenario']=='S0_benign_baseline' for r in scenarios)


def test_protocol_research_never_claims_authentication():
    response=client.get('/api/protocol-research')
    assert response.status_code==200
    body=response.json()
    assert 'POSTHOC' in body['status']
    assert any('spoof' in limitation.lower() for limitation in body['limitations'])
    scenarios={r['scenario']:r for r in body['records']}
    assert scenarios['S1_industroyer_pv']['unexpected_modbus_writer']['f1']>0.6
    assert scenarios['S1_industroyer_pv_alt']['unexpected_modbus_writer']['f1']>0.7


def test_protocol_sensitivity_not_promoted_to_live_model():
    response=client.get('/api/protocol-sensitivity')
    assert response.status_code==200
    body=response.json()
    assert body['hold_seconds']==5
    assert body['status']=='POSTHOC_SENSITIVITY_NOT_DEPLOYED'
    assert 'unseen' in body['warning']


def test_four_lane_results_are_explicitly_posthoc_and_not_model_deployment():
    response = client.get('/api/four-lane-research')
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'POSTHOC_EXPLORATORY_NOT_DEPLOYED_NOT_AUTHENTICATED'
    assert 0.98 < data['macro_f1'] < 1
    assert len(data['records']) == 8
    assert 'Price novelty' in data['warning']
    assert len(data['ablation']) == 4
    assert all(0 <= item['macro_f1_without_lane'] <= 1
               for item in data['ablation'].values())
    for row in data['records']:
        timing = row['false_alert_temporal_attribution']
        assert timing['false_alert_rows_total'] == row['four_lane_or']['fp']
        assert (timing['within_5_seconds'] + timing['between_5_and_30_seconds'] +
                timing['farther_than_30_seconds']) == timing['false_alert_rows_total']
    assert client.get('/api/model').json()['status'] == 'research_only'


def test_price_context_tradeoff_is_distinct_from_security_claim():
    response = client.get('/api/price-context-research')
    assert response.status_code == 200
    body = response.json()
    assert body['status'] == 'POSTHOC_PRICE_CONTEXT_POLICY_TRADEOFF_NOT_DEPLOYED'
    assert body['full_or_macro_f1'] == 0.98943
    assert body['security_only_macro_f1'] == 0.83355
    assert body['price_exclusive_attack_rows_not_security_alerted'] == 1308
    assert body['price_lane_treatment'] == 'CONTEXT_REVIEW_ONLY_NOT_SECURITY_VERDICT'
    assert next(r for r in body['scenarios'] if r['scenario'].startswith('S6_'))['security_only_f1'] < 0.07
    assert any(row['false_review_seconds'] == 360 for row in body['benign_price_offset_stress'])
    assert 'NOT_DEPLOYED' in body['status']


def test_arp_research_exposes_phase2_and_unauthenticated_boundary():
    response=client.get('/api/arp-research')
    assert response.status_code==200
    body=response.json()
    assert 'NOT_AUTHENTICATED' in body['status']
    assert len(body['records'])==len(body['hold5_sensitivity'])==4
    assert len(body['policy_sweep'])==24
    assert len(body['negative_controls'])==15
    assert all(row['known_ip_mac_mismatch_packets']==0 for row in body['negative_controls'])
    assert body['uncertainty']['observed_clean_seconds']==3442
    assert body['uncertainty']['observed_scenarios']==5
    assert body['uncertainty']['hypothetical_independent_scenario_upper_event_probability']>0.45
    assert body['identity_ambiguity']['status']=='SYNTHETIC_IDENTIFIABILITY_COUNTEREXAMPLE'
    same=body['identity_ambiguity']['records']
    assert len(same)==3 and all(r['identical_arp_observations'] for r in same)
    assert next(r for r in same if r['hold_seconds']==2)['synthetic_maintenance_false_alert_seconds']==33
    assert all(row['status']=='POSTHOC_SENSITIVITY_ONLY_NOT_DEPLOYED' for row in body['policy_sweep'])
    s5_hold2=next(row for row in body['policy_sweep'] if row['scenario'].startswith('S5_') and row['arp_hold_seconds']==2)
    assert s5_hold2['per_phase']['s5_mitm_phase_2']['or_detected_seconds']==582
    assert s5_hold2['combined']['clean_fpr']<next(row['combined']['clean_fpr'] for row in body['policy_sweep'] if row['scenario'].startswith('S5_') and row['arp_hold_seconds']==5)
    s5=next(r for r in body['records'] if r['scenario'].startswith('S5_'))
    phase2=s5['per_phase']['s5_mitm_phase_2']
    assert phase2['or_alert_rows']>phase2['physics_alert_rows']


def test_analyses_round_trip_and_overview():
    before=client.get('/api/overview').json()['analyses']
    response=client.post('/api/analyses',json={'source_name':'Synthetic API fixture','records':sample_rows()})
    assert response.status_code==201,response.text
    body=response.json()
    assert body['observation_count']==6
    assert body['review_count']>=1
    assert body['source_name']=='Synthetic API fixture'
    assert all(item['kind']!='VERIFIED_INTRUSION' for item in body['findings'])
    assert client.get(f"/api/analyses/{body['id']}").status_code==200
    assert any(a['id']==body['id'] for a in client.get('/api/analyses').json())
    overview=client.get('/api/overview').json()
    assert overview['analyses']==before+1
    assert overview['observations']>=6
    assert overview['review_rows']>=1


def test_malformed_times_rejected():
    data=sample_rows()
    data[1]['timestamp']=data[0]['timestamp']
    response=client.post('/api/analyses',json={'records':data})
    assert response.status_code==422


def test_no_timezone_and_timestamp_override_rejected():
    data=sample_rows()
    data[0]['timestamp']='2026-03-05T13:19:00'
    assert client.post('/api/analyses',json={'records':data}).status_code==422
    data=sample_rows()
    data[0]['values']['timestamp']=1.0
    assert client.post('/api/analyses',json={'records':data}).status_code==422


def test_raw_telemetry_is_not_persisted():
    # Only analyzed outputs/finding metadata are modeled as database columns.
    columns={c.name for c in Base.metadata.tables['analysis_runs'].columns}
    assert 'raw_payload' not in columns
    assert 'values' not in columns
    finding_columns={c.name for c in Base.metadata.tables['findings'].columns}
    assert 'raw_payload' not in finding_columns


def test_private_headers_and_docs_disabled():
    response = client.get('/api/model')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert response.headers['x-frame-options'] == 'DENY'
    assert client.get('/docs').status_code == 404
    assert client.get('/openapi.json').status_code == 404


def test_private_bearer_authentication_enforced_when_configured(monkeypatch):
    secret = 'private-test-access-token-' + 'A' * 40
    monkeypatch.setenv('GRID_SENTINEL_AUTH_REQUIRED', '1')
    monkeypatch.setenv('GRID_SENTINEL_ACCESS_TOKEN', secret)
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/ready').status_code == 200
    denied = client.get('/api/model')
    assert denied.status_code == 401
    assert denied.headers['cache-control'] == 'no-store'
    assert denied.headers['www-authenticate'] == 'Bearer'
    assert secret not in denied.text
    assert client.get('/api/overview', headers={'Authorization':'Bearer incorrect'}).status_code == 401
    assert client.post('/api/analyses', json={'records':sample_rows()}).status_code == 401
    accepted = client.get('/api/model', headers={'Authorization':'Bearer '+secret})
    assert accepted.status_code == 200
    assert accepted.json()['status'] == 'research_only'


def test_authentication_missing_secret_fails_closed(monkeypatch):
    monkeypatch.setenv('GRID_SENTINEL_AUTH_REQUIRED', '1')
    monkeypatch.delenv('GRID_SENTINEL_ACCESS_TOKEN', raising=False)
    response = client.get('/api/analyses')
    assert response.status_code == 503
    assert 'configuration' in response.json()['detail']


def test_blank_source_and_excessive_measurement_fields_rejected():
    rows = sample_rows()
    assert client.post('/api/analyses', json={'source_name':'   ', 'records':rows}).status_code == 422
    rows[0]['values'].update({f'extra.{i}': 1.0 for i in range(40)})
    assert client.post('/api/analyses', json={'records':rows}).status_code == 422


def test_oversized_meter_name_rejected():
    rows = sample_rows()
    rows[0]['values']['a' * 129] = 10.0
    assert client.post('/api/analyses', json={'records':rows}).status_code == 422
