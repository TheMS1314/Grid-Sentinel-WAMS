"""Loopback-only, read-only HTTP inference for a frozen smart-grid research head.

This service cannot operate electricity infrastructure and makes no claim to
identify an authenticated cyberattack. It intentionally has no public bind.
"""
import argparse
import datetime as dt
import json
import math
import os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer


ALLOWED_HOSTS=('127.0.0.1','localhost','0.0.0.0')


def load_bundle(path):
    with open(path,encoding='utf8') as src:obj=json.load(src)
    if obj.get('schema_version')!=1 or obj.get('safety')!='research_only_no_control_or_authenticated_attack_attribution':
        raise ValueError('Unsupported or unsafe model bundle')
    if len(obj.get('features',[]))!=15:raise ValueError('Model requires 15 strict power identities')
    for x in obj['features']:
        if x not in obj['center'] or x not in obj['scale'] or obj['scale'][x]<=0:
            raise ValueError('Malformed calibration')
    if obj.get('confirmation_consecutive_1hz_rows')!=3:
        raise ValueError('Confirmation policy unsupported')
    return obj


def timestamp(value):
    if not isinstance(value,str):raise ValueError('timestamp must be an ISO-8601 string')
    t=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if t.tzinfo is None:raise ValueError('timestamp must include a timezone')
    return t.astimezone(dt.timezone.utc)


def feature_values(record,bundle):
    devs=bundle['required_devices']
    fields=bundle['required_fields']
    measurements={}
    for name in devs:
        for field in fields:
            key=name+'.'+field
            value=record.get(key)
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):
                return None, f'missing_or_nonfinite:{key}'
            if abs(value)>1e12:return None,f'out_of_range:{key}'
            measurements[key]=float(value)
    out={}
    for name in devs:
        get=lambda x:measurements[name+'.'+x]
        power,reactive,apparent=get('p_sum3'),get('q_sum3'),get('s_sum3')
        denom=max(float(bundle['relative_denominator_floor']),abs(power),abs(apparent))
        for quantity,suffix in [('p','p'),('q','q'),('s','s')]:
            total={'p':power,'q':reactive,'s':apparent}[quantity]
            phase_total=sum(get(suffix+'ln'+str(i)) for i in (1,2,3))
            out[name+'.sum_'+quantity]=abs(total-phase_total)/denom
    return out,None


def assess(readings,bundle):
    if not isinstance(readings,list) or not 1<=len(readings)<=1000:
        raise ValueError('readings must be an array of 1..1000 objects')
    rows=[];run=0;last_t=None
    for i,record in enumerate(readings):
        if not isinstance(record,dict):raise ValueError('each reading must be an object')
        stamp=timestamp(record.get('timestamp'))
        delta=(stamp-last_t).total_seconds() if last_t is not None else None
        if delta is not None and delta<=0:
            raise ValueError(f'timestamps must be strictly increasing at row {i}')
        if delta is not None and delta>bundle['largest_tolerated_gap_seconds']:
            run=0
        values,reason=feature_values(record,bundle)
        if reason:
            run=0
            rows.append({'timestamp':stamp.isoformat(),'status':'ABSTAIN',
                         'reason':reason,'consecutive_evidence_rows':0})
            last_t=stamp
            continue
        feature_scores={k:abs(values[k]-bundle['center'][k])/bundle['scale'][k]
                        for k in bundle['features']}
        top=max(feature_scores,key=feature_scores.get)
        score=float(feature_scores[top]);hit=score>bundle['threshold']
        run=run+1 if hit else 0
        rows.append({'timestamp':stamp.isoformat(),
                     'status':'LOCAL_PHYSICS_REVIEW' if run>=3 else 'NO_CONFIRMED_LOCAL_MISMATCH',
                     'raw_mismatch':hit,'score':round(score,4),
                     'most_deviant_identity':top if hit else None,
                     'consecutive_evidence_rows':run})
        last_t=stamp
    return {'model_id':bundle['model_id'],'status':'RESEARCH_ONLY',
            'alerts':sum(r['status']=='LOCAL_PHYSICS_REVIEW' for r in rows),
            'abstentions':sum(r['status']=='ABSTAIN' for r in rows),
            'interpretation':'Integrity mismatch is NOT proof of an attack; never act on the grid.',
            'rows':rows}


class Handler(BaseHTTPRequestHandler):
    model=None
    max_body=2*1024*1024

    def respond(self,status,payload):
        encoded=json.dumps(payload,allow_nan=False).encode('utf8')
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(encoded)))
        self.end_headers();self.wfile.write(encoded)

    def do_GET(self):
        if self.path=='/health':
            return self.respond(200,{'status':'alive'})
        if self.path=='/ready':
            return self.respond(200,{'status':'ready_research_only',
                                     'model_id':self.model['model_id']})
        self.respond(404,{'error':'unknown_path'})

    def do_POST(self):
        if self.path!='/v1/assess':
            return self.respond(404,{'error':'unknown_path'})
        if self.headers.get('Content-Type','').split(';')[0].strip()!='application/json':
            return self.respond(415,{'error':'Content-Type must be application/json'})
        try:
            size=int(self.headers.get('Content-Length','-1'))
        except ValueError:
            return self.respond(400,{'error':'invalid_content_length'})
        if size<=0 or size>self.max_body:
            return self.respond(413,{'error':'invalid_body_size'})
        try:
            payload=json.loads(self.rfile.read(size))
            if not isinstance(payload,dict) or set(payload)!={'readings'}:
                raise ValueError('Expected one readings field')
            output=assess(payload['readings'],self.model)
        except (ValueError,TypeError,json.JSONDecodeError) as exc:
            return self.respond(400,{'error':'invalid_readings','message':str(exc)[:160]})
        self.respond(200,output)


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--model',default='smartgrid_meter_integrity_model.json')
    a.add_argument('--host',choices=ALLOWED_HOSTS,default='127.0.0.1')
    a.add_argument('--port',type=int,default=8765)
    args=a.parse_args()
    if not 1024<=args.port<=65535:raise ValueError('Invalid unprivileged port')
    if args.host=='0.0.0.0' and os.getenv('SMARTGRID_ALLOW_CONTAINER_BIND')!='1':
        raise ValueError('0.0.0.0 requires explicit container-only opt-in; '
                         'never publish this unauthenticated research API directly')
    Handler.model=load_bundle(args.model)
    http=ThreadingHTTPServer((args.host,args.port),Handler)
    print(json.dumps({'status':'RESEARCH_ONLY_LOOPBACK','url':f'http://{args.host}:{args.port}',
                      'model_id':Handler.model['model_id']}),flush=True)
    try:http.serve_forever()
    except KeyboardInterrupt:pass
    finally:http.server_close()


if __name__=='__main__':main()
