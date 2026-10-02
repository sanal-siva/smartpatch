"""Authenticated SONiC Smart Patch service with durable inventory and evidence APIs."""
import hashlib
import copy
import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import FastAPI, Depends, Header, HTTPException, Request, UploadFile, File, Form
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from starlette.concurrency import run_in_threadpool

from app.config import Settings, settings
from app.api.models import SyncEnvelope, AssessmentRequestIn, TokenRequest, ReleaseRequest, ToolRequest, PlanRequest
from app.db.store import now, stable_hash
from app.runtime import Runtime, age_seconds
from app.analytics import build_analytics
from app.services.sbom_parser import SBOMParser, SBOMValidationError
from app.services.assessment import finding_decision_fresh, relevant_fact_deadlines, RULESET_VERSION
from app.services.applicability_context import applicability_facts
from app.services.request_assessment import assess_request, RequestAssessmentError
from app.services.package_metadata import package_fields
from app.services.maintenance_commands import finding_is_current, plan_is_current, transaction
from app.services.external_agent import (ExternalAnalysisSubmission, ExternalAgentError,
    create_external_session, get_external_session, call_external_tool, submit_external_analysis,
    project_external_analysis)
from app.ui import routes as ui_routes
from app.services.remediation_batches import BatchCreate, BatchEdit, BatchControl, BatchStage, BatchExecute
from app.services.remediation_status import RemediationEnvelope
from app.services.maintenance_capability import package_automation, maintenance_view, plan_container_matches

logger = logging.getLogger('smart_patch.service')


SBOM_UPLOAD_PATHS = frozenset({'/api/v1/sbom-upload', '/admin/sbom-upload'})
SBOM_MULTIPART_OVERHEAD = 64 * 1024


def request_byte_limit(config, path, method):
    if method == 'POST' and path in SBOM_UPLOAD_PATHS:
        return config.max_sbom_upload_bytes + SBOM_MULTIPART_OVERHEAD
    return config.max_request_bytes


class RequestSizeLimit:
    """Count streamed request bytes as well as checking Content-Length."""
    def __init__(self,app,max_bytes,config=None):
        self.app,self.max_bytes,self.config=app,max_bytes,config

    async def __call__(self,scope,receive,send):
        if scope['type']!='http':
            return await self.app(scope,receive,send)
        received=0
        limit=request_byte_limit(self.config,scope.get('path'),scope.get('method')) if self.config else self.max_bytes
        async def bounded_receive():
            nonlocal received
            message=await receive()
            if message['type']=='http.request':
                received+=len(message.get('body',b''))
                if received>limit:
                    raise HTTPException(413,'Request exceeds configured size limit')
            return message
        await self.app(scope,bounded_receive,send)


def create_app(config=None, runtime_factory=Runtime):
    config = config or settings
    registry = CollectorRegistry()
    requests_count = Counter('smart_patch_api_requests_total','Requests',['method','route','status'],registry=registry)
    latency = Histogram('smart_patch_api_request_duration_seconds','Request duration',['route'],registry=registry)
    queue = Gauge('smart_patch_queue_depth','Queued operations',registry=registry)
    devices = Gauge('smart_patch_devices_total','Enrolled devices',registry=registry)
    provider = Gauge('smart_patch_ai_configured','AI provider enabled and configured',registry=registry)
    coverage = Gauge('smart_patch_inventory_coverage_ratio','Fraction of devices with completed assessment coverage',registry=registry)
    api_p95=Gauge('smart_patch_api_p95_seconds','Observed API p95 over a bounded five-minute window',registry=registry)
    cache_rate=Gauge('smart_patch_cache_hit_rate_percent','Observed assessment API cache hit percentage',registry=registry)
    cache_samples=Gauge('smart_patch_cache_observations','Cache observations in the bounded five-minute window',registry=registry)
    ai_available=Gauge('smart_patch_ai_available','Last observed provider availability, zero when unknown',registry=registry)
    ai_health_known=Gauge('smart_patch_ai_health_known','Whether actual provider availability has been observed',registry=registry)
    ai_last_check=Gauge('smart_patch_ai_last_check_timestamp_seconds','Time of the last actual provider request',registry=registry)
    sla_alert=Gauge('smart_patch_sla_alert_active','Active local SLA alert',['alert'],registry=registry)

    @asynccontextmanager
    async def lifespan(application):
        runtime = runtime_factory(config)
        application.state.runtime = runtime
        runtime.start()
        try:
            yield
        finally:
            runtime.stop()
            application.state.runtime = None

    application = FastAPI(title='SONiC Smart Patch Intelligence',version='3.0.0',lifespan=lifespan)
    application.state.runtime = None
    application.add_middleware(RequestSizeLimit,max_bytes=config.max_request_bytes,config=config)
    application.include_router(ui_routes.router)
    application.mount('/ui/static',StaticFiles(directory=str(Path(__file__).parent/'ui/static')),name='static')

    def runtime():
        service = application.state.runtime
        if service is None:
            raise HTTPException(503,'Service has not completed startup')
        return service

    async def principal(authorization: str | None = Header(None)):
        if not authorization or not authorization.startswith('Bearer '):
            raise HTTPException(401,'Bearer token required')
        value = authorization[7:]
        if not value or any(c.isspace() for c in value):
            raise HTTPException(401,'Invalid Bearer token')
        identity = await run_in_threadpool(runtime().store.authenticate,value)
        if identity is None:
            raise HTTPException(401,'Invalid or revoked Bearer token')
        return identity

    async def operator(identity=Depends(principal)):
        if identity['role'] not in ('admin','operator'):
            raise HTTPException(403,'Operator permission required')
        return identity

    async def admin(identity=Depends(principal)):
        if identity['role'] != 'admin':
            raise HTTPException(403,'Administrator permission required')
        return identity

    @application.exception_handler(HTTPException)
    async def http_error(_request, exc):
        names={401:'UNAUTHORIZED',403:'FORBIDDEN',404:'NOT_FOUND',409:'CONFLICT',413:'REQUEST_TOO_LARGE',422:'INVALID_REQUEST',503:'UNAVAILABLE'}
        return JSONResponse({'error':names.get(exc.status_code,'REQUEST_FAILED'),'message':str(exc.detail)},status_code=exc.status_code,
                            headers={'WWW-Authenticate':'Bearer'} if exc.status_code==401 else None)

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request, exc):
        errors=[{'field':'.'.join(map(str,e['loc'])),'message':e['msg']} for e in exc.errors()]
        return JSONResponse({'error':'INVALID_REQUEST','message':'Request failed validation','details':errors},status_code=422)

    @application.middleware('http')
    async def observe(request, call_next):
        start=time.monotonic()
        request.state.started_monotonic=start
        content_length=request.headers.get('content-length')
        body_limit=request_byte_limit(config,request.url.path,request.method)
        if content_length and (not content_length.isdigit() or int(content_length)>body_limit):
            response=JSONResponse({'error':'REQUEST_TOO_LARGE','message':'Request exceeds configured size limit'},status_code=413)
        else:
            try:response=await call_next(request)
            except Exception as exc:
                logger.error(json.dumps({'event':'api.failed','error_type':type(exc).__name__}))
                response=JSONResponse({'error':'INTERNAL_ERROR','message':'The request failed; consult the service event log'},status_code=500)
        route=getattr(request.scope.get('route'),'path','unmatched')
        elapsed=time.monotonic()-start
        requests_count.labels(request.method,route,str(response.status_code)).inc()
        latency.labels(route).observe(elapsed)
        service=application.state.runtime
        if service is not None:service.observations.request(request.url.path,response.status_code,elapsed)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['Cache-Control']='no-store' if not request.url.path.startswith('/ui/static') else 'public, max-age=3600'
        logger.info(json.dumps({'event':'api.request','method':request.method,'route':route,'status':response.status_code,
                               'duration_ms':round(elapsed*1000,2)}))
        return response

    @application.get('/',include_in_schema=False)
    async def home():
        return RedirectResponse('/ui/')

    @application.get('/health')
    async def health():
        service=runtime()
        try:
            await run_in_threadpool(service.store.health)
        except Exception:
            return JSONResponse({'status':'unhealthy','database':'unavailable'},status_code=503)
        return {'status':'healthy','database':'healthy','timestamp':now()}

    @application.get('/api/v1/readiness')
    async def readiness(_=Depends(operator)):
        service=runtime()
        return {'status':'ready' if service.scanner_info.get('status') in ('ready','complete') else 'degraded',
                'database':service.store.health(),'scanner':service.scanner_info,'ai':service.pipeline.ai.health()}

    @application.get('/metrics')
    async def metrics(_=Depends(operator)):
        data=await run_in_threadpool(runtime().overview)
        queue.set(data['summary']['queue_depth']);devices.set(data['summary']['devices_total'])
        coverage.set(data['summary']['coverage_pct']/100)
        measured=await run_in_threadpool(runtime().observability_snapshot)
        provider.set(measured['ai_configured'])
        api_p95.set(measured['api_p95_seconds'] if measured['api_p95_seconds'] is not None else float('nan'))
        cache_rate.set(measured['cache_hit_rate_percent'] if measured['cache_hit_rate_percent'] is not None else float('nan'))
        cache_samples.set(measured['cache_samples'])
        ai_available.set(measured['ai_available'] is True)
        ai_health_known.set(measured['ai_available'] is not None)
        ai_last_check.set(measured['ai_last_check_timestamp'])
        for alert in runtime().store.list('alert'):
            sla_alert.labels(alert['id']).set(alert['status']=='firing')
        return PlainTextResponse(generate_latest(registry),media_type=CONTENT_TYPE_LATEST)

    @application.get('/api/v1/observability')
    async def observability(_=Depends(operator)):
        service=runtime()
        measured=await run_in_threadpool(service.observability_snapshot)
        config_values=service.configuration(public=True)
        return {**measured,'alerts':service.store.list('alert'),
            'thresholds':{k:v for k,v in config_values.items() if k.startswith('alert')},
            'alert_channel':'Smart Patch UI events and authenticated API','evaluation_interval_seconds':10}

    @application.post('/api/v1/agents/remediation')
    async def agent_remediation(envelope: RemediationEnvelope, identity=Depends(principal)):
        from app.services.remediation_status import ingest
        return await run_in_threadpool(ingest, runtime(), envelope, identity)

    @application.get('/api/v1/remediation-status')
    async def remediation_status(device_id:str|None=None,cve_id:str|None=None,scope:str|None=None,
                                 status:str|None=None,limit:int=100,offset:int=0,record_id:str|None=None,_=Depends(operator)):
        from app.services.remediation_status import project
        return await run_in_threadpool(project,runtime().store,device_id,cve_id,scope,status,limit,offset,record_id)

    @application.post('/api/v1/agents/sync')
    async def agent_sync(envelope: SyncEnvelope, request:Request, identity=Depends(principal)):
        service=runtime()
        # Preserve exactly supplied component fields for the inventory digest contract.
        body=envelope.model_dump(exclude_unset=True)
        body.setdefault('schema_version',1)
        try:
            result,changed=await run_in_threadpool(service.store.sync,body,identity,request.client.host if request.client else '')
        except PermissionError as exc:
            raise HTTPException(403,str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409,str(exc)) from exc
        if result['resync_required']:
            return {**result,'service_time':now(),'findings':[],'evidence_requests':[]}
        device=service.store.device(envelope.device_id)
        binding=service.store.get('build_binding',device.get('build_id',''))
        binding_verified=bool(binding and binding.get('verification')=='signature_verified'
                              and binding.get('manifest_digest')==device.get('manifest_digest')
                              and stable_hash(binding.get('manifest',{}))==stable_hash(device.get('manifest',{})))
        service.store.update_device(envelope.device_id,{'artifact_verified':binding_verified,
            'assessment_build_evidence_policy':service.configuration().get('build_evidence_policy','required'),
            'assessment_policy_revision':service.configuration().get('assessment_policy_revision'),
            'artifact_id':binding.get('artifact_id') if binding_verified else None,
            'bound_manifest':binding.get('manifest') if binding_verified else {},
            'binding_revision':binding.get('index_digest') if binding_verified else 'unverified',
            'artifact_binding':'signed_release_baseline' if binding_verified else 'unverified',
            'runtime_attestation':'not_available'})
        if changed:
            operation=service.schedule_scan(envelope.device_id)
            result['operation_id']=operation['id']
        for fact in envelope.facts:
            request_id=fact.get('fact_id') or fact.get('request_id')
            pending=service.store.get('evidence_request',request_id) if request_id else None
            if pending and pending['device_id']==envelope.device_id:
                service.store.put('evidence_request',request_id,{**pending,'status':fact.get('status','complete'),'result':fact})
            # Consume each action acknowledgement once. A retried heartbeat must
            # not move an executing plan back to an earlier staged state.
            with transaction(service) as maintenance:
                pending=maintenance.store.get('action_request',request_id) if request_id else None
                if not pending or pending['device_id']!=envelope.device_id:
                    continue
                if pending.get('result_consumed') or pending.get('result') is not None:
                    continue
                plan=maintenance.store.get('plan',pending['plan']['id'])
                stage_result=pending.get('action')=='stage_plan'
                stale_stage=stage_result and (not plan or plan.get('stage_request_id')!=request_id
                                             or plan.get('status')!='staging_queued')
                value=fact.get('value') if isinstance(fact.get('value'),dict) else {}
                action_status=value.get('status',fact.get('status','unknown'))
                allowed_statuses = ({'staged', 'failed', 'staging_failed', 'denied', 'unknown'} if stage_result else
                                    {'pending_reassessment', 'rolled_back', 'rollback_failed', 'failed', 'denied', 'unknown'})
                interrupted = (action_status == 'denied' and isinstance(value.get('details'), str)
                               and 'Interrupted maintenance action requires operator recovery' in value['details'])
                if interrupted:
                    action_status = 'unknown'
                if (not isinstance(action_status, str) or action_status not in allowed_statuses or
                        fact.get('status') not in ('complete', 'failed', 'denied') or
                        (action_status in {'staged', 'pending_reassessment', 'rolled_back'} and fact.get('status') != 'complete')):
                    action_status = 'unknown'
                receipt_status = fact.get('status')
                if receipt_status not in ('complete', 'failed', 'denied'):
                    receipt_status = 'unknown'
                maintenance.store.put('action_request',request_id,{**pending,
                    'status':'superseded' if stale_stage else receipt_status,
                    'result':fact,'result_consumed':True,'result_received_at':now(),
                    'outcome_unknown':action_status=='unknown'}, envelope.device_id)
                if stale_stage:
                    maintenance.store.audit('action.result_ignored','Late or superseded staging result retained without changing the plan',
                                        envelope.device_id,{'request_id':request_id,'plan_id':pending['plan']['id']})
                    continue
                if plan:
                    eligible=bool(stage_result and action_status=='staged' and plan.get('approved')
                                  and plan.get('staging_eligible') and plan_is_current(plan,maintenance.store.device(envelope.device_id)))
                    updates={'status':action_status,'execution_eligible':eligible,
                             'outcome_unknown':action_status=='unknown',
                             'execution_result':fact,'updated_at':now()}
                    if stage_result:updates['staging_result']=fact
                    maintenance.store.put('plan',plan['id'],{**plan,**updates},envelope.device_id)
        # A scan can commit before this heartbeat supplies its action receipt.
        # Reconciliation uses the saved full-scan proof in one Store transaction.
        await run_in_threadpool(service.reconcile_maintenance, envelope.device_id)
        device=service.store.device(envelope.device_id)
        current_page=await run_in_threadpool(service.store.query_findings,envelope.device_id,None,None,'',1000,0,'priority')
        current=current_page['findings'];findings_total=current_page['total']
        fields=['id','cve_id','component_id','scope','package_name','affected_version','severity','cvss_score','fixed_versions',
                'applicability','exposure','rationale','assessed_at','inventory_digest','evidence_ids','action_type',
                'vex_justification','decision_valid_until','decision_basis','build_evidence_policy',
                'artifact_binding','remediation_eligible','candidate_fixed_versions']
        current_views=[fresh_finding_view(f,device) for f in current[:1000]]
        compact=[{k:f.get(k) for k in fields} for f in current_views]
        # Older collectors do not understand the metadata-only remediation guard.
        # Keep advisory candidates visible separately, but supply no executable
        # fixed-version target until a scoped review authorizes that assessment.
        for finding in compact:
            if finding.get('decision_basis')=='inventory_advisory_match':
                finding['candidate_fixed_versions']=finding.get('candidate_fixed_versions') or finding.get('fixed_versions',[])
                finding['fixed_versions']=[]
        evidence_requests=[r for r in service.store.list('evidence_request') if r.get('device_id')==envelope.device_id and r.get('status')=='queued']
        action_requests=[]
        for pending in service.store.list('action_request'):
            if pending.get('device_id')!=envelope.device_id or pending.get('status')!='queued':continue
            plan=service.store.get('plan',(pending.get('plan') or {}).get('id',''))
            selected=[service.store.get('finding',ident) for ident in (plan or {}).get('finding_ids',[])]
            plan_valid=bool(plan and plan.get('approved') and plan_is_current(plan,device) and selected
                            and all(f and f.get('applicability')=='affected' and finding_is_current(f,device)
                                    and f.get('decision_basis')!='inventory_advisory_match'
                                    and f.get('remediation_eligible') is not False for f in selected))
            stage=pending.get('action')=='stage_plan'
            current_request=bool(plan and pending.get('request_id')==plan.get('stage_request_id' if stage else 'action_request_id'))
            phase_valid=bool(plan and plan.get('status') in (('staging_queued',) if stage else ('queued','executing')))
            maintenance_allowed=bool(plan and package_automation(device,plan.get('scope'),plan.get('package_name',''))[0]
                                     and plan_container_matches(plan,device))
            allowed=plan_valid and current_request and phase_valid and maintenance_allowed
            if allowed:
                if not pending.get('delivered_at'):
                    pending = {**pending, 'delivered_at': now()}
                    service.store.put('action_request', pending['request_id'], pending, envelope.device_id)
                action_requests.append(pending)
            else:
                service.store.put('action_request',pending['request_id'],{**pending,'status':'superseded',
                    'reason':'Plan or supporting decision changed before delivery; any prior result remains auditable'},envelope.device_id)
                if plan and current_request and (not plan_valid or not maintenance_allowed):
                    service.store.put('plan',plan['id'],{**plan,'status':'requires_revalidation','execution_eligible':False},envelope.device_id)
        return {**result,'inventory_digest':device['inventory_digest'],'assessment_revision':device.get('assessment_revision'),
                'assessment_status':device.get('scan_status','pending'),'findings':compact,'findings_total':findings_total,
                'findings_truncated':findings_total>len(compact),'evidence_requests':evidence_requests[:10],
                'action_requests':action_requests[:3],'service_time':now(),'coverage':device.get('coverage',{})}

    @application.get('/api/v1/overview')
    async def overview(_=Depends(operator)):
        return await run_in_threadpool(runtime().overview)

    @application.get('/api/v1/analytics')
    async def analytics(days:int=30,_=Depends(operator)):
        return await run_in_threadpool(build_analytics,runtime().store,days)

    def enrich_device(device):
        age=age_seconds(device['last_seen'])
        counts=runtime().store.finding_counts()['by_device'].get(device['id'],{})
        return {**device,'status':'online' if age<=config.online_threshold_seconds else 'stale',
                'findings_counts':counts,**device_freshness(device),**maintenance_view(device)}

    @application.get('/api/v1/devices')
    async def devices_list(_=Depends(operator)):
        def fetch():
            counts=runtime().store.finding_counts()['by_device']
            result=[]
            for device in runtime().store.device_summaries():
                age=age_seconds(device['last_seen'])
                result.append({**device,'status':'online' if age<=config.online_threshold_seconds else 'stale',
                    'findings_counts':counts.get(device['id'],{}),**device_freshness(device),**maintenance_view(device)})
            return result
        result=await run_in_threadpool(fetch)
        return {'devices':result}

    @application.get('/api/v1/devices/{device_id}')
    async def device_detail(device_id:str,include_findings:bool=True,_=Depends(operator)):
        def fetch():
            device=runtime().store.device(device_id)
            if not device:raise HTTPException(404,'Device not found')
            result={**enrich_device(device),'events':runtime().store.list('event',owner=device_id,limit=50)}
            if include_findings:result['findings']=runtime().store.list('finding',owner=device_id)
            return result
        return JSONResponse(await run_in_threadpool(fetch))

    @application.post('/api/v1/devices/{device_id}/scan',status_code=202)
    async def scan_device(device_id:str,_=Depends(operator)):
        try:return public_operation(runtime().schedule_scan(device_id))
        except KeyError as exc:raise HTTPException(404,'Device not found') from exc

    @application.post('/api/v1/devices/{device_id}/evidence',status_code=202)
    async def request_evidence(device_id:str,body:dict,_=Depends(operator)):
        service=runtime();device=service.store.device(device_id)
        if not device:raise HTTPException(404,'Device not found')
        collector=body.get('collector')
        if collector not in {'services','listeners','features','interfaces','routing','resources','inventory','processes','kernel','bgp','package_versions'}:
            raise HTTPException(422,'Collector is not allowlisted')
        scope=body.get('scope','host')
        if scope not in {'host'} | {c['scope'] for c in device.get('components',[])}:
            raise HTTPException(422,'Evidence scope is not in the device current inventory')
        arguments=body.get('args',{})
        if not isinstance(arguments,dict):raise HTTPException(422,'Collector arguments must be an object')
        if collector=='package_versions':
            packages=arguments.get('packages',[])
            if set(arguments)!={'packages'} or not isinstance(packages,list) or not 1<=len(packages)<=10 or any(not isinstance(p,str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?',p) for p in packages):
                raise HTTPException(422,'package_versions requires 1-10 valid package names')
        elif arguments:raise HTTPException(422,'This collector does not accept arguments')
        ident=str(uuid.uuid4())
        item={'request_id':ident,'id':ident,'device_id':device_id,'collector':collector,'scope':scope,
              'args':arguments,'status':'queued','created_at':now(),'inventory_digest':device['inventory_digest']}
        service.store.put('evidence_request',ident,item,device_id)
        return item

    @application.get('/api/v1/findings')
    async def findings(device_id:str|None=None,applicability:str|None=None,severity:str|None=None,
                       search:str='',limit:int=1000,offset:int=0,sort:str='severity',fix_available:bool|None=None,_=Depends(operator)):
        return await run_in_threadpool(runtime().store.query_findings,device_id,applicability,severity,search,limit,offset,sort,fix_available)

    @application.get('/api/v1/findings/{finding_id}')
    async def finding_detail(finding_id:str,_=Depends(operator)):
        finding=runtime().store.get('finding',finding_id)
        if not finding:raise HTTPException(404,'Finding not found')
        device=runtime().store.device(finding['device_id'])
        result=await run_in_threadpool(project_external_analysis,runtime(),fresh_finding_view(finding,device))
        result['analysis_lifecycle']=await run_in_threadpool(runtime().store.analysis_lifecycles,'device',finding['device_id'],finding_id,5)
        return result

    @application.get('/api/v1/analysis-lifecycle')
    async def analysis_lifecycle(target_kind:str,target_id:str,finding_id:str|None=None,limit:int=100,_=Depends(operator)):
        if target_kind not in {'device','release'}:raise HTTPException(422,'target_kind must be device or release')
        records=await run_in_threadpool(runtime().store.analysis_lifecycles,target_kind,target_id,finding_id,limit)
        return {'target_kind':target_kind,'target_id':target_id,'records':records,
                'meaning':'Recorded processing transitions bound to their input identities; applicability is a separate decision.'}

    @application.get('/api/v1/findings/{finding_id}/history')
    async def finding_history(finding_id:str,limit:int=100,_=Depends(operator)):
        rows=await run_in_threadpool(runtime().store.list,'assessment_history',finding_id,min(max(limit,1),1000))
        return {'finding_id':finding_id,'assessments':rows,'history_basis':'Recorded assessment revisions; earlier history is not backfilled'}

    @application.get('/api/v1/releases/{release_id}/findings/{finding_id}')
    async def release_finding_detail(release_id:str,finding_id:str,_=Depends(operator)):
        finding=await run_in_threadpool(runtime().store.get,'release_finding',finding_id)
        if not finding or finding.get('release_id')!=release_id:raise HTTPException(404,'Release finding not found')
        return {**finding,'analysis_lifecycle':await run_in_threadpool(runtime().store.analysis_lifecycles,'release',release_id,finding_id,5)}

    @application.get('/api/v1/releases/{release_id}/findings/{finding_id}/history')
    async def release_finding_history(release_id:str,finding_id:str,limit:int=100,_=Depends(operator)):
        rows=await run_in_threadpool(runtime().store.list,'release_assessment_history',finding_id,min(max(limit,1),1000))
        rows=[row for row in rows if row.get('release_id')==release_id]
        if not rows:
            finding=await run_in_threadpool(runtime().store.get,'release_finding',finding_id)
            if not finding or finding.get('release_id')!=release_id:raise HTTPException(404,'Release finding history not found')
        return {'release_id':release_id,'finding_id':finding_id,'assessments':rows,
                'history_basis':'Immutable recorded release assessment revisions; earlier history is not backfilled'}

    @application.get('/api/v1/evidence-snapshots/{digest}')
    async def evidence_snapshot(digest:str,_=Depends(operator)):
        if not re.fullmatch(r'[0-9a-f]{64}',digest):raise HTTPException(422,'Invalid evidence digest')
        record=await run_in_threadpool(runtime().store.get,'evidence_snapshot',digest)
        if record is None:raise HTTPException(404,'Evidence snapshot not found')
        return {'sha256':digest,'evidence':record}

    @application.post('/api/v1/findings/{finding_id}/investigate',status_code=202)
    async def investigate(finding_id:str,_=Depends(operator)):
        finding=runtime().store.get('finding',finding_id)
        if not finding:raise HTTPException(404,'Finding not found')
        return public_operation(runtime().schedule_scan(finding['device_id'],investigate=True,finding_ids=[finding_id]))

    @application.get('/api/v1/events')
    @application.get('/api/v1/changes')
    async def events_list(device_id:str|None=None,limit:int=100,_=Depends(operator)):
        values=runtime().store.list('event',owner=device_id,limit=min(max(limit,1),1000))
        return {'events':values,'changes':values}

    @application.get('/api/v1/operations')
    async def operations_list(_=Depends(operator)):
        return {'operations':[public_operation(o) for o in runtime().store.operations()]}

    @application.get('/operations/{operation_id}')
    @application.get('/api/v1/operations/{operation_id}')
    async def operation_detail(operation_id:str,_=Depends(operator)):
        operation=runtime().store.operation(operation_id)
        if not operation:raise HTTPException(404,'Operation not found')
        return public_operation(operation)

    @application.get('/operations/{operation_id}/logs')
    @application.get('/api/v1/operations/{operation_id}/logs')
    async def operation_logs(operation_id:str,_=Depends(operator)):
        operation=runtime().store.operation(operation_id)
        if not operation:raise HTTPException(404,'Operation not found')
        return {'logs':operation.get('logs',[])}

    @application.get('/api/v1/tools')
    async def tools_list(_=Depends(operator)):
        tools=[]
        for tool in runtime().pipeline.tools.list_tools():
            function=tool.get('function',tool)
            tools.append({'name':function['name'],'description':function.get('description',''),
                          'input_schema':function.get('parameters',function.get('input_schema',{}))})
        return {'tools':tools}

    async def external_call(function,*arguments):
        try:
            return await run_in_threadpool(function,runtime(),*arguments)
        except ExternalAgentError as exc:
            raise HTTPException(exc.status_code,str(exc)) from exc

    @application.post('/api/v1/findings/{finding_id}/agent-session',status_code=201)
    async def agent_session_create(finding_id:str,identity=Depends(operator)):
        return await external_call(create_external_session,finding_id,identity)

    @application.get('/api/v1/agent-sessions/{session_id}')
    async def agent_session_read(session_id:str,identity=Depends(operator)):
        return await external_call(get_external_session,session_id,identity)

    @application.post('/api/v1/agent-sessions/{session_id}/tools/{tool_name}')
    async def agent_session_tool(session_id:str,tool_name:str,body:ToolRequest,identity=Depends(operator)):
        return await external_call(call_external_tool,session_id,tool_name,body.arguments,identity)

    @application.post('/api/v1/agent-sessions/{session_id}/analysis',status_code=201)
    async def agent_session_analysis(session_id:str,body:ExternalAnalysisSubmission,identity=Depends(operator)):
        return await external_call(submit_external_analysis,session_id,body,identity)

    @application.post('/api/v1/tools/{tool_name}')
    async def run_tool(tool_name:str,body:ToolRequest,identity=Depends(operator)):
        try:
            result=await run_in_threadpool(runtime().pipeline.tools.call,tool_name,body.arguments)
        except (ValueError,KeyError,RuntimeError) as exc:
            raise HTTPException(422,str(exc)) from exc
        runtime().store.audit('tool.called','Source evidence tool executed',details={'name':tool_name,'principal':identity['id'],'evidence_id':result.get('id')})
        return {'result':result}

    @application.get('/api/v1/settings')
    async def settings_read(_=Depends(operator)):
        return runtime().configuration(public=True)

    @application.put('/api/v1/settings')
    @application.post('/admin/setup')
    async def settings_write(body:dict,_=Depends(admin)):
        try:return runtime().save_configuration(body)
        except (ValueError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc

    @application.get('/admin/tokens')
    @application.get('/api/v1/tokens')
    async def tokens_list(_=Depends(admin)):
        return {'tokens':runtime().store.tokens()}

    @application.post('/admin/tokens',status_code=201)
    @application.post('/api/v1/tokens',status_code=201)
    async def tokens_create(body:TokenRequest,identity=Depends(admin)):
        result=runtime().store.issue_token(body.description,body.role,body.device_id)
        runtime().store.audit('token.created','API credential created',details={'token_id':result['token_id'],'role':body.role,'actor':identity['id']})
        return result

    @application.delete('/admin/tokens/{token_id}')
    @application.delete('/api/v1/tokens/{token_id}')
    async def tokens_revoke(token_id:str,identity=Depends(admin)):
        if token_id==identity['id']:raise HTTPException(409,'Create another admin credential before revoking the current session')
        if not runtime().store.revoke(token_id):raise HTTPException(404,'Token not found')
        runtime().store.audit('token.revoked','API credential revoked',details={'token_id':token_id,'actor':identity['id']})
        return {'status':'revoked'}

    @application.get('/api/v1/releases')
    async def releases_list(_=Depends(operator)):
        return {'releases':runtime().store.list('release')}

    @application.post('/admin/releases',status_code=201)
    @application.post('/api/v1/releases',status_code=201)
    async def release_create(body:ReleaseRequest,_=Depends(admin)):
        match=re.fullmatch(r'sonic\.([A-Za-z0-9_.]+)\.([0-9]+)-([0-9a-fA-F]{7,40})',body.release_id)
        if not match and not body.release_id.startswith('custom:'):
            raise HTTPException(422,'Expected sonic.<branch>.<build-id>-<commit-id> or custom:<name>')
        from urllib.parse import urlparse
        for repository in body.repositories:
            url=urlparse(repository.base_url)
            if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise HTTPException(422,'Repository URL must be HTTPS without embedded credentials or query strings')
            keyring=Path(repository.keyring).resolve()
            allowed_roots=[Path('/usr/share/keyrings'),runtime().state_dir/'keyrings']
            if not keyring.is_file() or not any(keyring.is_relative_to(root.resolve()) for root in allowed_roots):
                raise HTTPException(422,'Repository keyring must exist under /usr/share/keyrings or the service state keyrings directory')
        existing=runtime().store.get('release',body.release_id) or {}
        release={**body.model_dump(),**existing,**body.model_dump(exclude_unset=True),
                 'branch':match.group(1) if match else None,'commit':match.group(3) if match else None,
                 'created_at':existing.get('created_at') or now(),'status':'configured'}
        if body.primary:
            for old in runtime().store.list('release'):
                runtime().store.put('release',old['release_id'],{**old,'primary':False})
        runtime().store.put('release',body.release_id,release)
        if body.source_url and (body.source_revision or release.get('commit')):
            release['clone_operation_id']=runtime().enqueue('source_clone',{'release_id':body.release_id},'clone:'+body.release_id)['id']
        if body.sbom_source:
            release['operation_id']=runtime().enqueue('release_sync',{'release_id':body.release_id},'release:'+body.release_id)['id']
        runtime().store.put('release',body.release_id,release)
        return release

    @application.delete('/admin/releases/{release_id}')
    @application.delete('/api/v1/releases/{release_id}')
    async def release_remove(release_id:str,_=Depends(admin)):
        if not runtime().store.remove('release',release_id):raise HTTPException(404,'Release not found')
        return {'status':'deleted'}

    @application.post('/admin/sync-now',status_code=202)
    @application.post('/api/v1/sync-now',status_code=202)
    async def sync_now(body:dict,_=Depends(admin)):
        release_id=body.get('release_id') or body.get('sonic_release')
        if release_id:
            if not runtime().store.get('release',release_id):raise HTTPException(404,'Release not found')
            return public_operation(runtime().enqueue('release_sync',{'release_id':release_id},'release:'+release_id))
        return public_operation(runtime().enqueue('advisory_update',{},'advisory-update'))

    @application.get('/api/v1/upload-limits')
    async def upload_limits(_=Depends(operator)):
        return {'sbom_bytes':config.max_sbom_upload_bytes,'request_bytes':config.max_request_bytes}

    @application.post('/admin/sbom-upload',status_code=201)
    @application.post('/api/v1/sbom-upload',status_code=201)
    async def sbom_upload(file:UploadFile=File(...),release_id:str=Form(...),_=Depends(admin)):
        raw=await file.read(config.max_sbom_upload_bytes+1)
        if len(raw)>config.max_sbom_upload_bytes:
            raise HTTPException(413,f'SBOM upload exceeds {config.max_sbom_upload_bytes / (1024 * 1024):g} MiB limit')
        try:
            parser=SBOMParser(max_bytes=config.max_sbom_upload_bytes)
            document=parser.load_bytes(raw);packages=parser.parse_packages(document)
        except json.JSONDecodeError as exc:
            raise HTTPException(422,f'Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}') from exc
        except (SBOMValidationError,UnicodeDecodeError,ValueError) as exc:
            raise HTTPException(422,str(exc)) from exc
        ident=stable_hash(document)
        source_sha256=hashlib.sha256(raw).hexdigest()
        previous_artifact=runtime().store.get('artifact',ident)
        previous_release=runtime().store.get('release',release_id) or {}
        if previous_artifact and previous_artifact.get('source_sha256') not in (None,source_sha256):
            invalidate_artifact_bindings(runtime(),ident,'Raw SBOM source bytes changed')
        same_bytes=bool(previous_artifact and previous_artifact.get('source_sha256')==source_sha256)
        runtime().store.put('artifact',ident,{**(previous_artifact if same_bytes else {}),'id':ident,'sbom':document,'release_id':release_id,'digest':'sha256:'+ident,
            'source_sha256':source_sha256,
            'source':'operator_upload','imported_at':now(),'verification':previous_artifact.get('verification','unverified') if same_bytes else 'unverified'})
        release={**previous_release,'release_id':release_id,'artifact_id':ident,'packages_count':len(packages),
                 'status':'imported','created_at':previous_release.get('created_at') or now(),
                 'last_synced_at':now(),'primary':previous_release.get('primary',False)}
        if previous_release.get('artifact_id')!=ident or not same_bytes:
            release.update(verification='unverified',binding={})
        runtime().store.put('release',release_id,release)
        incoming_package_ids={stable_hash([release_id,ident,package['id']]) for package in packages}
        for previous in runtime().store.list('package',owner=release_id):
            if previous['id'] not in incoming_package_ids:
                runtime().store.put('package',previous['id'],{**previous,'status':'historical',
                    'superseded_at':now(),'superseded_reason':'Replaced by current scoped SBOM package records'},release_id)
        for package in packages:
            package_id=stable_hash([release_id,ident,package['id']])
            runtime().store.put('package',package_id,{**package,'id':package_id,'component_id':package['id'],
                'artifact_id':ident,'release_id':release_id,'status':'current','created_at':now(),
                **package_fields(package)},release_id)
        operation=runtime().enqueue('release_sync',{'release_id':release_id},'release:'+release_id)
        return {'artifact_id':ident,'release_id':release_id,'packages_count':len(packages),'status':'queued','operation_id':operation['id']}

    @application.post('/api/v1/artifacts/verify')
    async def verify_artifact_binding(body:dict,identity=Depends(admin)):
        from app.services.provenance import verify_release_binding, ProvenanceVerificationError
        service=runtime();release=service.store.get('release',body.get('release_id',''))
        if not release:raise HTTPException(404,'Registered release not found')
        artifact=service.store.get('artifact',release.get('artifact_id',''))
        if not artifact:raise HTTPException(404,'Upload the exact release SBOM before verifying its binding')
        try:
            binding=await run_in_threadpool(verify_release_binding,body,artifact,service.state_dir/'trusted-build-keys')
        except ProvenanceVerificationError as exc:
            raise HTTPException(422,str(exc)) from exc
        binding.update(artifact_id=artifact['id'],release_id=release['release_id'],verified_by=identity['id'])
        binding['manifest']=json.loads(body['manifest_text'])
        with service.store.lock:
            prior=service.store.get('build_binding',binding['build_id'])
            if prior and prior.get('image_digest')!=binding['image_digest']:
                raise HTTPException(409,'Build identity collision: this build ID already names a different image artifact')
            service.store.put('build_binding',binding['build_id'],binding)
        service.store.put('release',release['release_id'],{**release,'binding':binding,'build_id':binding['build_id'],'verification':'signature_verified'})
        matched=[]
        for device in service.store.devices():
            if (device.get('build_id')==binding['build_id'] and device.get('manifest_digest')==binding['manifest_digest']
                    and stable_hash(device.get('manifest',{}))==stable_hash(binding['manifest'])):
                service.store.update_device(device['id'],{'artifact_verified':True,'artifact_id':artifact['id'],
                    'bound_manifest':binding['manifest'],'binding_revision':binding['index_digest'],
                    'artifact_binding':'signed_release_baseline','runtime_attestation':'not_available'})
                service.schedule_scan(device['id']);matched.append(device['id'])
        service.store.audit('build.binding_verified','Signed release baseline binding verified',
                           details={'build_id':binding['build_id'],'key_id':binding['key_id'],'matched_devices':matched})
        return {**binding,'matched_devices':matched,'runtime_attestation':'not_available'}

    @application.delete('/api/v1/artifacts/bindings/{build_id:path}')
    async def revoke_artifact_binding(build_id:str,identity=Depends(admin)):
        service=runtime();binding=service.store.get('build_binding',build_id)
        if not binding:raise HTTPException(404,'Build binding not found')
        revoked={**binding,'verification':'revoked','revoked_at':now(),'revoked_by':identity['id']}
        service.store.put('build_binding',build_id,revoked)
        release=service.store.get('release',binding.get('release_id',''))
        if release:service.store.put('release',release['release_id'],{**release,'verification':'revoked','binding':revoked})
        for device in service.store.devices():
            if device.get('build_id')==build_id:
                service.store.update_device(device['id'],{'artifact_verified':False,'artifact_binding':'revoked',
                    'binding_revision':'revoked:'+binding['index_digest'],'bound_manifest':{}})
                service.schedule_scan(device['id'])
        return {'status':'revoked','build_id':build_id}

    @application.get('/admin/pkg-db/stats')
    @application.get('/api/v1/pkg-db/stats')
    async def package_stats(release:str|None=None,_=Depends(operator)):
        packages=runtime().store.list('package')
        if release:packages=[p for p in packages if p.get('release_id')==release]
        return {'total_packages':len(packages),'releases':len(runtime().store.list('release')),'cves_analyzed':len(runtime().store.list('finding'))}

    @application.get('/admin/pkg-db/query')
    @application.get('/api/v1/pkg-db/query')
    async def package_query(release:str|None=None,package:str|None=None,_=Depends(operator)):
        packages=runtime().store.list('package')
        verdicts=runtime().store.list('package_cve',owner=release)
        if package:verdicts=[v for v in verdicts if v.get('package_name')==package]
        return {'packages':[p for p in packages if (not release or p.get('release_id')==release) and (not package or p.get('name')==package)],
                'verdicts':verdicts}

    @application.post('/api/v1/assess-vulnerabilities')
    async def assess(body:AssessmentRequestIn,request:Request,identity=Depends(principal)):
        service=runtime();started=request.state.started_monotonic
        try:return JSONResponse(await run_in_threadpool(assess_request,service,body,identity,started))
        except Exception as exc:
            request_id=str(uuid.uuid4())
            await run_in_threadpool(service.store.put,'request',request_id,{'id':request_id,
                'smart_patch_instance_id':identity.get('device_id'),'sonic_version':body.sonic_version,
                'cve_count':len(body.vulnerabilities),'status':'failed','submitted_at':now(),
                'assessment_duration_ms':round((time.monotonic()-started)*1000),'response_cached':False,
                'error_type':type(exc).__name__})
            if isinstance(exc,RequestAssessmentError):raise HTTPException(exc.status_code,str(exc)) from exc
            raise

    @application.post('/api/v1/findings/{finding_id}/review')
    async def review_finding(finding_id:str,body:dict,identity=Depends(admin)):
        service=runtime();finding=service.store.get('finding',finding_id)
        if not finding:raise HTTPException(404,'Finding not found')
        state=body.get('applicability')
        if state not in {'affected','fixed','not_affected','under_investigation'}:
            raise HTTPException(422,'Invalid applicability outcome')
        justification=body.get('justification','').strip()
        if not 20<=len(justification)<=4000:
            raise HTTPException(422,'A detailed review justification of 20-4000 characters is required')
        evidence_ids=body.get('evidence_ids',[])
        if not isinstance(evidence_ids,list) or not evidence_ids:
            raise HTTPException(422,'Review must reference existing finding evidence')
        allowed=set(finding.get('evidence_ids',[])) | {e.get('id') for e in finding.get('evidence',[]) if isinstance(e,dict)}
        if any(e not in allowed for e in evidence_ids):
            raise HTTPException(422,'Unknown or cross-finding evidence reference')
        vex_justification=body.get('vex_justification')
        vex_terms={'component_not_present','vulnerable_code_not_present','vulnerable_code_not_in_execute_path',
                   'vulnerable_code_cannot_be_controlled_by_adversary','inline_mitigations_already_exist'}
        if state=='not_affected' and vex_justification not in vex_terms:
            raise HTTPException(422,'A valid OpenVEX justification is required for not_affected')
        external=body.get('review_reference','').strip()
        if state in {'fixed','not_affected'} and not re.match(r'^https://[^\s]+$',external):
            raise HTTPException(422,'Suppressing review requires an HTTPS reference to supporting build/patch evidence')
        device=service.store.device(finding['device_id'])
        if not device or not finding_is_current(finding,device):
            raise HTTPException(409,'Finding is stale; reassess current inventory before review')
        expiry=datetime.now(timezone.utc)+timedelta(days=30)
        try:
            deadlines=relevant_fact_deadlines({'runtime_facts':device.get('facts',[])})
            validity=min([expiry,*deadlines])
        except (KeyError,ValueError,TypeError):
            raise HTTPException(409,'Runtime evidence freshness is invalid; collect fresh evidence before review')
        if validity<=datetime.now(timezone.utc):raise HTTPException(409,'Supporting runtime evidence expired; reassess before review')
        review_id=str(uuid.uuid4())
        evidence={'id':'review-'+review_id,'type':'operator_review','source':external or 'administrator',
                  'created_at':now(),'reviewed_by':identity['id'],'data':{'justification':justification,
                  'reference':external,'applicability':state,'vex_justification':vex_justification}}
        updated={**finding,'applicability':state,'rationale':justification,'vex_justification':vex_justification,
                 'review_required':False,'decision_basis':'operator_review','assessed_at':now(),
                 'build_evidence_policy':service.configuration().get('build_evidence_policy','required'),
                 'remediation_eligible':state=='affected','action_type':'maintenance_window' if state=='affected' else 'defer',
                 'decision_valid_until':validity.isoformat(),'review_record_id':review_id,'ruleset_version':RULESET_VERSION,
                 'evidence_ids':list(dict.fromkeys(finding.get('evidence_ids',[])+[evidence['id']])),
                 'evidence':finding.get('evidence',[])+[evidence]}
        record={'id':review_id,'build_id':device.get('artifact_id') or device.get('build_id') or device.get('sonic_version'),
                'build_evidence_policy':service.configuration().get('build_evidence_policy','required'),
                'device_id':device['id'],'inventory_digest':device['inventory_digest'],
                'context_hash':stable_hash(applicability_facts(device.get('facts',[]))),
                'scope_id':finding['scope'],'component_id':finding['component_id'],'cve_id':finding['cve_id'],
                'version':finding['affected_version'],'applicability':state,'justification':justification,
                'vex_justification':vex_justification,'evidence_ids':evidence_ids+[evidence['id']],
                'verification':'reviewed','reviewed_by':identity['id'],'created_at':now(),
                'expires_at':expiry.isoformat()}
        with service.store.lock:
            current_device=service.store.device(device['id'])
            current_finding=service.store.get('finding',finding_id)
            if current_finding!=finding or not finding_is_current(finding,current_device):
                raise HTTPException(409,'Inventory, assessment or policy changed during review')
            service.store.put('reviewed_assessment',review_id,record)
            service.store.update_device(device['id'],{'review_revision':review_id})
            service.store.put('finding',finding_id,updated,finding['device_id'])
            service.store.put('evidence',evidence['id'],evidence)
            service.refresh_reviewed_assessments()
        service.store.audit('finding.reviewed','Applicability review recorded',finding['device_id'],{'finding_id':finding_id,'review_id':review_id,'applicability':state})
        return updated

    @application.get('/api/v1/remediation-batches')
    async def remediation_batches_list(_=Depends(operator)):
        from app.services.remediation_batches import list_batches
        return await run_in_threadpool(list_batches, runtime())

    @application.post('/api/v1/remediation-batches', status_code=201)
    async def remediation_batch_create(body:BatchCreate, identity=Depends(operator)):
        from app.services.remediation_batches import create_batch
        return await run_in_threadpool(create_batch, runtime(), body, identity['id'])

    @application.get('/api/v1/remediation-batches/{batch_id}')
    async def remediation_batch_detail(batch_id:str, _=Depends(operator)):
        from app.services.remediation_batches import get_batch
        return await run_in_threadpool(get_batch, runtime(), batch_id)

    @application.patch('/api/v1/remediation-batches/{batch_id}')
    async def remediation_batch_edit(batch_id:str, body:BatchEdit, identity=Depends(operator)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'edit', body, identity['id'])

    @application.post('/api/v1/remediation-batches/{batch_id}/refresh')
    async def remediation_batch_refresh(batch_id:str, body:BatchControl, identity=Depends(operator)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'refresh', body, identity['id'])

    @application.post('/api/v1/remediation-batches/{batch_id}/approve-and-stage', status_code=202)
    async def remediation_batch_stage(batch_id:str, body:BatchStage, identity=Depends(admin)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'approve-and-stage', body, identity['id'])

    @application.post('/api/v1/remediation-batches/{batch_id}/execute', status_code=202)
    async def remediation_batch_execute(batch_id:str, body:BatchExecute, identity=Depends(admin)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'execute', body, identity['id'])

    @application.post('/api/v1/remediation-batches/{batch_id}/pause')
    async def remediation_batch_pause(batch_id:str, body:BatchControl, identity=Depends(admin)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'pause', body, identity['id'])

    @application.post('/api/v1/remediation-batches/{batch_id}/resume')
    async def remediation_batch_resume(batch_id:str, body:BatchControl, identity=Depends(admin)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'resume', body, identity['id'])

    @application.post('/api/v1/remediation-batches/{batch_id}/stop')
    async def remediation_batch_stop(batch_id:str, body:BatchControl, identity=Depends(admin)):
        from app.services.remediation_batches import mutate_batch
        return await run_in_threadpool(mutate_batch, runtime(), batch_id, 'stop', body, identity['id'])

    @application.get('/api/v1/plans')
    async def plans_list(_=Depends(operator)):
        return {'plans':runtime().store.list('plan')}

    @application.post('/api/v1/plans',status_code=201)
    async def plan_create(body:PlanRequest,_=Depends(operator)):
        from app.services.maintenance_commands import transaction, create_plan
        with transaction(runtime()) as service:
            return create_plan(service, body)

    @application.get('/api/v1/plans/{plan_id}')
    async def plan_detail(plan_id:str,_=Depends(operator)):
        plan=runtime().store.get('plan',plan_id)
        if not plan:raise HTTPException(404,'Plan not found')
        return plan

    @application.post('/api/v1/plans/{plan_id}/approve')
    async def plan_approve(plan_id:str,identity=Depends(admin)):
        from app.services.maintenance_commands import transaction, approve_plan
        with transaction(runtime()) as service:
            return approve_plan(service, plan_id, identity['id'])

    @application.post('/api/v1/plans/{plan_id}/execute',status_code=202)
    async def plan_execute(plan_id:str,body:dict,identity=Depends(admin)):
        from app.services.maintenance_commands import transaction, require_plan, queue_plan
        with transaction(runtime()) as service:
            plan = require_plan(service, plan_id)
            if body.get('confirmed_device_id') != plan['device_id']:
                raise HTTPException(422, 'Confirm the exact device ID before execution')
            return queue_plan(service, plan_id, 'execute', identity['id'])

    @application.post('/api/v1/plans/{plan_id}/stage',status_code=202)
    async def plan_stage(plan_id:str,identity=Depends(admin)):
        from app.services.maintenance_commands import transaction, queue_plan
        with transaction(runtime()) as service:
            return queue_plan(service, plan_id, 'stage', identity['id'])

    @application.post('/api/v1/plans/{plan_id}/validate-target',status_code=202)
    async def plan_validate_target(plan_id:str,body:dict,_=Depends(operator)):
        service=runtime();plan=service.store.get('plan',plan_id)
        if not plan:raise HTTPException(404,'Plan not found')
        if plan.get('batch_id'):raise HTTPException(409,'Use the remediation batch draft to change its target')
        if plan.get('outcome_unknown') or plan.get('status') in ('unknown','rollback_unknown'):
            raise HTTPException(409,'An earlier maintenance outcome is unknown; resolve operator recovery before changing this plan')
        if not plan_is_current(plan,service.store.device(plan['device_id'])):
            raise HTTPException(409,'Plan expired or build/inventory changed')
        if plan.get('status') in ('staging_queued','staged','queued','pending_reassessment'):
            raise HTTPException(409,'Create a new plan to change a staged or executing target')
        service.store.put('plan',plan_id,{**plan,'status':'validating_target','approved':False,'staging_eligible':False,'execution_eligible':False},plan['device_id'])
        return public_operation(service.enqueue('plan_validate',{'plan_id':plan_id,'target_version':body.get('target_version') or plan.get('target_version')},'plan:'+plan_id))

    @application.get('/api/v1/devices/{device_id}/vex')
    async def vex_export(device_id:str,_=Depends(operator)):
        device=runtime().store.device(device_id)
        if not device:raise HTTPException(404,'Device not found')
        statements=[]
        for finding in runtime().store.list('finding',owner=device_id):
            if finding.get('status')!='current':continue
            status=finding.get('applicability','under_investigation')
            if not finding_is_current(finding,device):status='under_investigation'
            justification=finding.get('vex_justification')
            if status=='not_affected' and not justification:status='under_investigation'
            statement={'vulnerability':{'name':finding['cve_id']},'products':[{'@id':'urn:smart-patch:component:'+finding['component_id']}],
                       'status':status,'timestamp':finding.get('assessed_at',now())}
            if status=='not_affected':statement['justification']=justification;statement['impact_statement']=finding.get('rationale','')
            if status=='affected':statement['action_statement']=finding.get('rationale','Review available fixes')
            statements.append(statement)
        return {'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:smart-patch:vex:'+device_id+':'+stable_hash(statements),
                'author':'SONiC Smart Patch','timestamp':now(),'version':1,'statements':statements}

    # Legacy dashboard consumers share real state rather than placeholder responses.
    @application.get('/admin/dashboard/{view}')
    async def legacy_dashboard(view:str,_=Depends(operator)):
        if view=='instances':return {'instances':[enrich_device(d) for d in runtime().store.devices()]}
        if view=='requests':return {'requests':runtime().store.list('request')}
        if view=='packages':return {'releases':runtime().store.list('release'),'packages':runtime().store.list('package')}
        if view=='cves':return runtime().overview()
        raise HTTPException(404,'Dashboard not found')

    return application


def CounterFor(values):
    from collections import Counter
    return dict(Counter(values))


def device_freshness(device):
    heartbeat=age_seconds(device.get('last_seen'))
    result={'heartbeat_age_seconds':round(heartbeat) if heartbeat!=float('inf') else None,
            'inventory_age_seconds':None,'inventory_freshness':'unknown'}
    try:
        instant=datetime.fromisoformat(device['inventory_collected_at'].replace('Z','+00:00'))
        if instant.tzinfo is None:return result
        age=(datetime.now(timezone.utc)-instant).total_seconds()
        if age < -30:
            return {**result,'inventory_freshness':'clock_uncertain'}
        ttl=min(max(1,int(device.get('inventory_ttl_seconds',600))),86400)
        return {**result,'inventory_age_seconds':round(max(0,age)),
                'inventory_freshness':'fresh' if age<=ttl else 'stale'}
    except (KeyError,AttributeError,ValueError,TypeError):return result



def fresh_finding_view(finding,device):
    if finding_is_current(finding,device):return finding
    return {**finding,'applicability':'under_investigation','exposure':'unknown','vex_verdict':None,
            'vex_justification':None,'review_required':True,'action_type':'defer','assessment_stale':True,'remediation_eligible':False,
            'rationale':'Assessment context changed or supporting evidence expired; reassess before relying on this verdict.'}


def invalidate_artifact_bindings(service,artifact_id,reason):
    for binding in service.store.list('build_binding'):
        if binding.get('artifact_id')!=artifact_id or binding.get('verification')!='signature_verified':continue
        invalidated={**binding,'verification':'invalidated','invalidated_at':now(),'invalidation_reason':reason}
        service.store.put('build_binding',binding['build_id'],invalidated)
        release=service.store.get('release',binding.get('release_id',''))
        if release:service.store.put('release',release['release_id'],{**release,'verification':'invalidated','binding':invalidated})
        for device in service.store.devices():
            if device.get('artifact_id')==artifact_id:
                service.store.update_device(device['id'],{'artifact_verified':False,'artifact_binding':'invalidated',
                    'binding_revision':'invalidated:'+binding['index_digest'],'bound_manifest':{}})
                service.schedule_scan(device['id'])



def public_operation(operation):
    return {k:v for k,v in operation.items() if k not in ('arguments','logs')}


app=create_app()


def run_server():
    import uvicorn
    logging.basicConfig(level=settings.log_level.upper(),format='%(message)s')
    uvicorn.run(app,host=settings.host,port=settings.port,
                ssl_certfile=settings.tls_cert or None,ssl_keyfile=settings.tls_key or None)


if __name__=='__main__':
    run_server()
