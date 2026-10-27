"""Private Grid Sentinel API: saved analyses and research-only meter integrity inference."""
import os
import json
import hmac
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session, selectinload

from .database import Base, engine, get_db
from .detector_engine import assess, load_bundle
from .models import AnalysisRun, Finding
from .schemas import AnalysisDetail, AnalysisRequest, AnalysisSummary


MODEL_PATH = Path(os.environ.get('MODEL_PATH', '/app/model/smartgrid_meter_integrity_model.json'))
if not MODEL_PATH.exists():
    MODEL_PATH = Path(__file__).resolve().parent.parent / 'model' / 'smartgrid_meter_integrity_model.json'

model_bundle = load_bundle(str(MODEL_PATH))
EVIDENCE_PATH = MODEL_PATH.parent / 'phase22_replay_results.jsonl'
PROTOCOL_EVIDENCE_PATH = MODEL_PATH.parent / 'phase24_two_lane_results.jsonl'
PROTOCOL_SENSITIVITY_PATH = MODEL_PATH.parent / 'phase24_hold5_sensitivity.jsonl'
ARP_EVIDENCE_PATH = MODEL_PATH.parent / 'phase25_arp_fusion.jsonl'
ARP_SENSITIVITY_PATH = MODEL_PATH.parent / 'phase25_arp_hold5.jsonl'
ARP_POLICY_SWEEP_PATH = MODEL_PATH.parent / 'phase26_arp_policy_sweep.jsonl'
ARP_NEGATIVE_CONTROL_PATH = MODEL_PATH.parent / 'phase27_arp_negative_control.jsonl'
ARP_UNCERTAINTY_PATH = MODEL_PATH.parent / 'phase28_arp_uncertainty.json'
ARP_IDENTITY_AMBIGUITY_PATH = MODEL_PATH.parent / 'phase32_arp_identity_ambiguity.json'
FOUR_LANE_EVIDENCE_PATH = MODEL_PATH.parent / 'phase36_four_lane_results.json'
PRICE_CONTEXT_TRADEOFF_PATH = MODEL_PATH.parent / 'phase45_price_context_tradeoff.json'


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Compose applies guarded Alembic migrations before starting this process.
    # Avoid silently creating unversioned tables in application startup.
    yield


app = FastAPI(
    title='Grid Sentinel Research API',
    description='Private read-only power-meter consistency research monitor. Alerts are not authenticated attacks.',
    version='1.0.0',
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware('http')
async def private_api_access(request: Request, call_next):
    """Protect research/data APIs when deployed with Compose authentication.

    Liveness/readiness remain available for internal health checks. The
    browser retains an entered bearer token in memory only; no credentials are
    embedded into the static build or persisted in the database.
    """
    if request.url.path.startswith('/api/') and request.url.path not in ('/api/health', '/api/ready'):
        # Require authentication by default, even for a manually launched API.
        # Only explicit test/development opt-out disables it.
        if os.getenv('GRID_SENTINEL_AUTH_REQUIRED', '1') != '0':
            expected = os.getenv('GRID_SENTINEL_ACCESS_TOKEN', '')
            if len(expected) < 32:
                return JSONResponse({'detail': 'Private API access configuration unavailable'}, status_code=503)
            authorization = request.headers.get('authorization', '')
            supplied = authorization[7:] if authorization.startswith('Bearer ') else ''
            if not supplied.isascii() or not hmac.compare_digest(supplied, expected):
                return JSONResponse({'detail': 'Private access token required'}, status_code=401,
                                    headers={'WWW-Authenticate': 'Bearer'})
    return await call_next(request)


class PrivateResponseHeaders:
    """Small ASGI header wrapper; avoids buffering or consuming request bodies."""

    def __init__(self, wrapped_app):
        self.wrapped_app = wrapped_app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.wrapped_app(scope, receive, send)

        async def send_private(message):
            if message['type'] == 'http.response.start':
                headers = [(name, value) for name, value in message.get('headers', [])
                           if name.lower() not in (b'cache-control', b'x-content-type-options',
                                                   b'referrer-policy', b'x-frame-options')]
                headers.extend(((b'cache-control', b'no-store'),
                                (b'x-content-type-options', b'nosniff'),
                                (b'referrer-policy', b'no-referrer'),
                                (b'x-frame-options', b'DENY')))
                message['headers'] = headers
            await send(message)

        return await self.wrapped_app(scope, receive, send_private)

allowed_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173').split(',')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x for x in allowed_origins if x],
    allow_methods=['GET', 'POST'],
    allow_headers=['Content-Type', 'Authorization'],
)
app.add_middleware(PrivateResponseHeaders)


@app.get('/api/health')
def health():
    return {'status': 'alive', 'service': 'grid-sentinel-backend'}


@app.get('/api/ready')
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text('SELECT 1'))
    except Exception:
        raise HTTPException(status_code=503, detail='Database unavailable')
    return {'status': 'ready_research_only', 'database': 'connected', 'model_id': model_bundle['model_id']}


@app.get('/api/model')
def model_info():
    return {
        'model_id': model_bundle['model_id'],
        'status': 'research_only',
        'features': len(model_bundle['features']),
        'feature_names': model_bundle['features'],
        'required_devices': model_bundle['required_devices'],
        'required_fields': model_bundle['required_fields'],
        'confirmation_rows': model_bundle['confirmation_consecutive_1hz_rows'],
        'training_rows': model_bundle['fit_rows'],
        'calibration_rows': model_bundle['calibration_rows'],
        'source_sha256': model_bundle['source_csv_sha256'],
        'limitations': model_bundle['limitations'],
    }


@app.get('/api/research-evidence')
def research_evidence():
    """Explicitly historical/posthoc results; never a live accuracy estimate."""
    try:
        lines=EVIDENCE_PATH.read_text(encoding='utf-8').splitlines()
        items=[json.loads(line) for line in lines if line.strip()]
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail='Research evidence not bundled') from exc
    return {
        'status':'HISTORICAL_EXPLORATORY_NOT_FIELD_VALIDATED',
        'dataset':'Data4Cyber v3 / chronological S0 holdout / S1-S6',
        'evidence_date':'2026-10-26',
        'records':items,
    }


@app.get('/api/protocol-research')
def protocol_research():
    """Read-only offline packet audit, not an online authenticated IDS."""
    try:
        lines=PROTOCOL_EVIDENCE_PATH.read_text(encoding='utf8').splitlines()
        records=[json.loads(line) for line in lines if line.strip()]
    except (OSError,ValueError) as exc:
        raise HTTPException(status_code=503,detail='Protocol evidence not bundled') from exc
    return {
        'status':'POSTHOC_EXPLORATORY_IP_NOT_AUTHENTICATED',
        'scope':'Data4Cyber v3 Modbus TCP write-source role audit',
        'records':records,
        'limitations':['Writer IP can be spoofed; not cryptographic device authentication',
                       'S0 role mapping must be replaced by a verified site authorization policy',
                       'No Modbus packet reassembly or operational command response integration',
                       'Not trained or independently evaluated on a new site'],
    }


@app.get('/api/protocol-sensitivity')
def protocol_sensitivity():
    """Fixed five-second exploratory analysis, not a deployed decision policy."""
    try:
        rows=[json.loads(line) for line in PROTOCOL_SENSITIVITY_PATH.read_text(encoding='utf8').splitlines() if line.strip()]
    except (OSError,ValueError) as exc:
        raise HTTPException(status_code=503,detail='Sensitivity evidence not bundled') from exc
    return {
        'status':'POSTHOC_SENSITIVITY_NOT_DEPLOYED',
        'hold_seconds':5,
        'records':rows,
        'warning':'Persistence was explored on already examined campaign data; new clean/unseen capture required to select a field threshold.',
    }


@app.get('/api/arp-research')
def arp_research():
    """Offline S0 identity-map consistency evidence; never an authenticated intrusion claim."""
    try:
        baseline=[json.loads(s) for s in ARP_EVIDENCE_PATH.read_text(encoding='utf8').splitlines() if s.strip()]
        persistence=[json.loads(s) for s in ARP_SENSITIVITY_PATH.read_text(encoding='utf8').splitlines() if s.strip()]
        policies=[json.loads(s) for s in ARP_POLICY_SWEEP_PATH.read_text(encoding='utf8').splitlines() if s.strip()]
        negative_controls=[json.loads(s) for s in ARP_NEGATIVE_CONTROL_PATH.read_text(encoding='utf8').splitlines() if s.strip()]
        uncertainty=json.loads(ARP_UNCERTAINTY_PATH.read_text(encoding='utf8'))
        identity_ambiguity=json.loads(ARP_IDENTITY_AMBIGUITY_PATH.read_text(encoding='utf8'))
    except (OSError,ValueError) as exc:
        raise HTTPException(status_code=503,detail='ARP evidence not bundled') from exc
    return {
        'status':'POSTHOC_ARP_IP_MAC_EVIDENCE_NOT_AUTHENTICATED',
        'records':baseline,
        'hold5_sensitivity':persistence,
        'policy_sweep':policies,
        'negative_controls':negative_controls,
        'uncertainty':uncertainty,
        'identity_ambiguity':identity_ambiguity,
        'warning':'ARP sender IP/MAC claims are spoofable. Persistence candidates were evaluated posthoc and are not deployed.',
    }


@app.get('/api/four-lane-research')
def four_lane_research():
    """Historical multi-signal research, never part of live model inference."""
    try:
        report = json.loads(FOUR_LANE_EVIDENCE_PATH.read_text(encoding='utf8'))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail='Four-lane evidence not bundled') from exc
    return {'status': 'POSTHOC_EXPLORATORY_NOT_DEPLOYED_NOT_AUTHENTICATED',
            'dataset': 'Data4Cyber v3, S0 chronological train/calibration and S1-S6 examined campaigns',
            'macro_f1': report['macro_F1_S1_through_S6'],
            'ablation': report.get('leave_one_lane_out_macro', {}),
            'records': report['scenarios'],
            'warning': report['warning'] +
                ' Neither Modbus source IP nor ARP claims are authenticated. '
                'Price novelty can flag benign tariff regime changes. False-alert burden is not validated across independent sites.'}


@app.get('/api/price-context-research')
def price_context_research():
    """Historical price-only context vs security review tradeoff; never deployed."""
    try:
        report = json.loads(PRICE_CONTEXT_TRADEOFF_PATH.read_text(encoding='utf8'))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail='Price-context research not bundled') from exc
    if report.get('status') != 'POSTHOC_PRICE_CONTEXT_POLICY_TRADEOFF_NOT_DEPLOYED':
        raise HTTPException(status_code=503, detail='Unsupported price-context research status')
    return report


@app.post('/api/analyses', response_model=AnalysisDetail, status_code=201)
def create_analysis(payload: AnalysisRequest, db: Session = Depends(get_db)):
    records=[]
    for record in payload.records:
        if record.timestamp.utcoffset() is None:
            raise HTTPException(status_code=422, detail='Timezone-aware timestamps are required')
        if 'timestamp' in record.values:
            raise HTTPException(status_code=422, detail='values must not override timestamp')
        records.append({'timestamp': record.timestamp.isoformat(), **record.values})
    try:
        output=assess(records, model_bundle)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:250])

    scores=[float(x['score']) for x in output['rows'] if 'score' in x]
    first=payload.records[0].timestamp
    last=payload.records[-1].timestamp
    analysis=AnalysisRun(
        source_name=payload.source_name.strip(),
        observation_count=len(records),
        review_count=output['alerts'],
        abstention_count=output['abstentions'],
        max_score=max(scores, default=0.0),
        duration_seconds=max(0.0,(last-first).total_seconds()),
        model_id=model_bundle['model_id'],
    )
    for result in output['rows']:
        if result['status'] not in ('LOCAL_PHYSICS_REVIEW','ABSTAIN'):
            continue
        analysis.findings.append(Finding(
            timestamp=datetime.fromisoformat(result['timestamp']),
            kind=result['status'],
            score=result.get('score'),
            identity_name=result.get('most_deviant_identity'),
            reason=result.get('reason') or ('Sustained meter identity mismatch; not an authenticated attack'),
        ))
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


@app.get('/api/analyses', response_model=list[AnalysisSummary])
def list_analyses(limit: int=Query(default=25, ge=1, le=100), db: Session=Depends(get_db)):
    return db.scalars(select(AnalysisRun).order_by(desc(AnalysisRun.created_at)).limit(limit)).all()


@app.get('/api/analyses/{analysis_id}', response_model=AnalysisDetail)
def get_analysis(analysis_id: str, db: Session=Depends(get_db)):
    analysis=db.scalar(select(AnalysisRun).options(selectinload(AnalysisRun.findings)).where(AnalysisRun.id==analysis_id))
    if analysis is None:raise HTTPException(status_code=404, detail='Analysis not found')
    return analysis


@app.get('/api/overview')
def overview(db: Session=Depends(get_db)):
    totals=db.execute(select(
        func.count(AnalysisRun.id),
        func.coalesce(func.sum(AnalysisRun.observation_count),0),
        func.coalesce(func.sum(AnalysisRun.review_count),0),
        func.coalesce(func.sum(AnalysisRun.abstention_count),0),
    )).one()
    latest=db.scalar(select(AnalysisRun).order_by(desc(AnalysisRun.created_at)).limit(1))
    cutoff=datetime.now(timezone.utc)-timedelta(days=13)
    recent=db.scalars(select(AnalysisRun).where(AnalysisRun.created_at>=cutoff)).all()
    days={}
    for a in recent:
        day=a.created_at.date().isoformat()
        item=days.setdefault(day,{'date':day,'runs':0,'reviews':0,'observations':0})
        item['runs']+=1;item['reviews']+=a.review_count;item['observations']+=a.observation_count
    chart=[]
    now=datetime.now(timezone.utc)
    for back in range(13,-1,-1):
        day=(now-timedelta(days=back)).date().isoformat()
        chart.append(days.get(day,{'date':day,'runs':0,'reviews':0,'observations':0}))
    findings=db.scalars(select(Finding).order_by(desc(Finding.timestamp)).limit(8)).all()
    return {
        'model_status':'RESEARCH_ONLY',
        'analyses':int(totals[0]),'observations':int(totals[1]),
        'review_rows':int(totals[2]),'abstention_rows':int(totals[3]),
        'last_analysis_at':latest.created_at.isoformat() if latest else None,
        'daily_activity':chart,
        'recent_findings':[
            {'id':f.id,'analysis_id':f.analysis_id,'timestamp':f.timestamp,
             'kind':f.kind,'score':f.score,'identity_name':f.identity_name}
            for f in findings
        ],
    }
