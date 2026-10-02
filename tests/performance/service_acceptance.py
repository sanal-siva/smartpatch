#!/usr/bin/env python3
"""Measured HTTP acceptance on an isolated, explicitly synthetic service database.

Does not contact switches, modify the deployed service, call an AI provider, or
establish vulnerability accuracy. Exercises registered-finding lookup/cache and
12 months of history, then 1000 simultaneous assessment requests by default.
"""
import argparse
import asyncio
from datetime import datetime, timezone, timedelta
import json
import math
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))


def settings(directory,port=0):
    from app.config import Settings
    return Settings(_env_file=None,state_dir=directory,database_url='sqlite:///'+str(directory/'fixture.db'),
                    host='127.0.0.1',port=port,jobs_enabled=False,scanner_binary='/not-used/grype',
                    ai_enabled=False,source_roots=[],source_revision='',bootstrap_token='')


def payload():
    return {'sonic_version':'synthetic-performance-v1','device_context':{'device_id':'performance-fixture-1'},
            'vulnerabilities':[{'cve_id':f'SYNTHETIC-PERF-{i:04d}','package_name':f'fixture-package-{i}',
                               'affected_version':'1.0','severity':'HIGH','cvss_score':7.5} for i in range(100)]}


def seed(directory):
    from app.runtime import Runtime
    from app.db.store import inventory_hash,now
    runtime=Runtime(settings(directory));store=runtime.store
    components=[{'component_id':f'host:fixture-{i}','scope':'host','name':f'fixture-package-{i}',
                 'version':'1.0','architecture':'amd64','distro':{'id':'debian','version_id':'12'}} for i in range(100)]
    for number in (1,2):
        device_id=f'performance-fixture-{number}'
        envelope={'device_id':device_id,'hostname':device_id,'epoch':'fixture-epoch','sequence':1,'kind':'checkpoint',
                  'build_id':'fixture-build','sonic_version':'synthetic-performance-v1','components':components,
                  'inventory_digest':inventory_hash(components),'collected_at':now(),'facts':[]}
        store.sync(envelope,{'role':'admin','id':'fixture-seeder'})
        findings=[];evidence=[]
        for i in range(1808):
            eid=f'fixture-evidence-{i}';evidence.append({'id':eid,'type':'synthetic_performance_evidence','data':'fixture '*512})
            findings.append({'component_id':components[i%100]['component_id'],'scope_id':'host',
                'package_name':components[i%100]['name'],'affected_version':'1.0','cve_id':f'SYNTHETIC-PERF-{i:04d}',
                'severity':'HIGH','cvss_score':7.5,'applicability':'under_investigation','exposure':'unknown',
                'evidence_ids':[eid],'rationale':'Synthetic performance fixture; no vulnerability claim.'})
        store.store_findings(device_id,envelope['inventory_digest'],{'findings':findings,'evidence':evidence,
            'scanner':{'status':'complete','db_revision':'synthetic-performance-db'},'coverage':{'complete':True}},'fixture-revision')
    instant=datetime.now(timezone.utc).replace(minute=0,second=0,microsecond=0)
    with store.sessions.begin() as session:
        for hour in range(24*366):
            at=(instant-timedelta(hours=hour)).isoformat().replace('+00:00','Z')
            store._put(session,'snapshot',at,{'date':at[:10],'snapshot_time':at,'measured_at':at,'granularity':'hour',
                'devices':2,'components':200,'unique_packages':100,'unique_cves':1808,'affected':0,
                'under_investigation':3616,'fixed':0,'not_affected':0,'synthetic_fixture':True})
    runtime.stop()


def serve(directory,port):
    import uvicorn
    from app.main import create_app
    from app.runtime import Runtime
    def factory(config):
        runtime=Runtime(config)
        runtime.scanner_info={'status':'ready','db_revision':'synthetic-performance-db'}
        return runtime
    uvicorn.run(create_app(settings(directory,port),factory),host='127.0.0.1',port=port,
                log_level='warning',access_log=False,timeout_graceful_shutdown=10)


def percentile(values,q=.95):
    values=sorted(values)
    return round(values[max(0,math.ceil(len(values)*q)-1)],3) if values else None


async def measure(base,token,concurrency):
    import httpx
    headers={'Authorization':'Bearer '+token}
    limits=httpx.Limits(max_connections=concurrency,max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(base_url=base,headers=headers,limits=limits,timeout=180) as client:
        body=payload()
        first=await client.post('/api/v1/assess-vulnerabilities',json=body);first.raise_for_status()
        assert len(first.json()['recommendations'])==100
        assert all(r['assessment_source']=='registered_device_finding' for r in first.json()['recommendations'])
        timings=[];hit_count=0
        for _ in range(30):
            started=time.monotonic();response=await client.post('/api/v1/assess-vulnerabilities',json=body)
            response.raise_for_status();timings.append(1000*(time.monotonic()-started));hit_count+=bool(response.json()['cached'])
        routes={}
        for route in ('/api/v1/overview','/api/v1/devices','/api/v1/findings?limit=50',
                      '/api/v1/analytics?days=366','/api/v1/operations','/metrics'):
            times=[]
            for _ in range(12):
                started=time.monotonic();response=await client.get(route);response.raise_for_status()
                times.append(1000*(time.monotonic()-started))
            routes[route]={'samples':len(times),'p95_ms':percentile(times),'bytes':len(response.content)}
        start=asyncio.Event()
        async def request_one():
            await start.wait();began=time.monotonic()
            try:
                response=await client.post('/api/v1/assess-vulnerabilities',json=body);response.raise_for_status()
                data=response.json()
                if len(data['recommendations'])!=100:raise AssertionError('Recommendation count changed')
                return {'status':response.status_code,'request_id':data['request_id'],'cached':data['cached'],
                        'duration_ms':1000*(time.monotonic()-began)}
            except Exception as exc:return {'status':'failed','error':type(exc).__name__+': '+str(exc)[:300]}
        tasks=[asyncio.create_task(request_one()) for _ in range(concurrency)]
        began=time.monotonic();start.set();results=await asyncio.gather(*tasks)
        successful=[r for r in results if r['status']==200]
        ids=[r['request_id'] for r in successful]
        return {'sequential_100_cve_requests':{'samples':30,'p95_ms':percentile(timings),'cache_hit_rate':hit_count/30},
                'dashboard_api_routes':routes,'concurrent_requests':{'simultaneous_tasks':concurrency,
                    'completed':len(successful),'unique_request_ids':len(set(ids)),'failed':len(results)-len(successful),
                    'wall_seconds':round(time.monotonic()-began,3),
                    'p95_ms':percentile([r['duration_ms'] for r in successful]),
                    'cache_hit_rate':sum(r['cached'] for r in successful)/len(successful) if successful else None,
                    'errors':[r for r in results if r['status']!=200][:10]},'request_ids':ids}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--concurrency',type=int,default=1000)
    parser.add_argument('--serve-fixture')
    parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args()
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,(min(max(soft,8192),hard),hard))
    if args.serve_fixture:return serve(Path(args.serve_fixture),args.port)
    if not 1<=args.concurrency<=2000:raise ValueError('Concurrency must be 1..2000')
    output=Path(args.output).resolve();output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='smart-patch-performance-') as temp:
        directory=Path(temp);seed(directory)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        with (directory/'server.log').open('wb') as log:
            process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--serve-fixture',str(directory),
                '--port',str(port),'--output',str(output)],cwd=ROOT,stdout=log,stderr=log)
        try:
            import httpx
            base=f'http://127.0.0.1:{port}'
            for _ in range(100):
                if process.poll() is not None:raise RuntimeError('Fixture server exited: '+(directory/'server.log').read_text()[-2000:])
                try:
                    if httpx.get(base+'/health',timeout=1).is_success:break
                except httpx.RequestError:pass
                time.sleep(.1)
            else:raise RuntimeError('Fixture server readiness timed out')
            report=asyncio.run(measure(base,(directory/'bootstrap-token').read_text().strip(),args.concurrency))
            from app.db.store import Store
            store=Store(settings(directory).database_url)
            requests={r['id'] for r in store.list('request')}
            ids=report.pop('request_ids');report['all_successful_requests_persisted']=set(ids)<=requests
            with store.engine.connect() as connection:
                report['sqlite_integrity_check']=connection.exec_driver_sql('PRAGMA integrity_check').scalar()
            store.close()
            sequential=report['sequential_100_cve_requests'];concurrent=report['concurrent_requests']
            report['checks']={'sequential_p95_under_2_seconds':sequential['p95_ms']<2000,
                'repeated_workload_cache_hit_rate_above_70_percent':sequential['cache_hit_rate']>=.7,
                'dashboard_api_p95_under_1_second':all(r['p95_ms']<1000 for r in report['dashboard_api_routes'].values()),
                'concurrency_no_failed_or_missing_requests':concurrent['completed']==args.concurrency and concurrent['unique_request_ids']==args.concurrency and report['all_successful_requests_persisted'],
                'database_integrity':report['sqlite_integrity_check']=='ok'}
            report.update(fixture='Synthetic: 2 devices, 3616 candidates, 100-CVE registered queries, 366 days of hourly observations',
                limitations=['Does not measure scanner throughput, model latency/accuracy, source-clone duration or live switch behavior.',
                             'The 2-second lookup gate is measured sequentially; concurrent latency is reported separately.',
                             'Dashboard measurements cover API responses; DOM rendering is covered separately by browser tests.'])
            output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
            if not all(report['checks'].values()):raise SystemExit(1)
        finally:
            process.terminate()
            try:process.wait(timeout=20)
            except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':main()
