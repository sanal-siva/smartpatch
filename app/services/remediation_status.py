"""Durable collector progress and scoped CVE lifecycle, separate from authorization.

A collector report can describe an installation, never approve a central plan or
assert resolution. Resolution requires independently committed inventory/scan
proof. GET projections are read-only and never dispatch work.
"""
import copy
import json
from collections import Counter
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from app.db.store import Device, Record, Token, Store, now, stable_hash
from .maintenance_reassessment import (scan_identity, _advisory_generation, _instant,
                                      SCAN_REQUIRED_REASONS, scan_request)
from .maintenance_capability import plan_container_matches
from .maintenance_commands import finding_is_current

STATES = Literal['draft','planned','approved','staging','downloading','downloaded','staged',
    'installing','installed','restarting','pending_reassessment','failed','staging_failed',
    'denied','rolled_back','rollback_required','rolling_back','rollback_failed','rollback_unknown','unknown','cancelled','expired']


class ContainerIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[0-9a-f]{64}$')
    image: str = Field(pattern=r'^sha256:[0-9a-f]{64}$')
    name: str = Field(min_length=2,max_length=128,pattern=r'^/[A-Za-z0-9][A-Za-z0-9_.-]*$')
    running: bool = Field(strict=True)
    pid: int = Field(ge=0,strict=True)


class RemediationReport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    local_plan_id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')
    revision: int = Field(ge=1, strict=True)
    origin: Literal['cli','service'] = 'cli'
    service_plan_id: str | None = Field(default=None, max_length=128)
    request_id: str | None = Field(default=None, max_length=128)
    scope: str = Field(min_length=1, max_length=256)
    package_name: str = Field(min_length=1, max_length=256)
    from_version: str = Field(min_length=1, max_length=256)
    target_version: str = Field(min_length=1, max_length=256)
    component_id: str = Field(min_length=1, max_length=256)
    architecture: str = Field(default='', max_length=64)
    container_identity: ContainerIdentity | None = None
    finding_ids: list[str] = Field(default_factory=list, max_length=100)
    cve_ids: list[str] = Field(min_length=1, max_length=100)
    inventory_digest: str = Field(min_length=1, max_length=256)
    inventory_epoch: str = Field(min_length=1, max_length=128)
    build_id: str = Field(default='', max_length=256)
    status: STATES
    progress: dict = Field(default_factory=dict)
    staging_result: dict | None = None
    execution_result: dict | None = None
    rollback: dict | None = None
    created_at: str = Field(default='', max_length=64)
    updated_at: str = Field(default='', max_length=64)

    @model_validator(mode='after')
    def bounded(self):
        if any(not isinstance(value, str) or not value or len(value)>256 for value in self.finding_ids+self.cve_ids):
            raise ValueError('Finding and CVE identities must be bounded strings')
        if len(json.dumps(self.model_dump(), ensure_ascii=True,allow_nan=False)) > 65536:
            raise ValueError('A remediation report may contain at most 64 KiB')
        events=self.progress.get('events',[])
        if not isinstance(events,list) or len(events)>128 or any(not isinstance(event,dict) for event in events):
            raise ValueError('Progress events must be a bounded list of objects')
        if self.origin == 'service' and (not self.service_plan_id or not self.request_id):
            raise ValueError('Service progress requires the bound plan and action request identifiers')
        return self


class RemediationEnvelope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device_id: str = Field(min_length=1, max_length=128)
    epoch: str = Field(min_length=1, max_length=128)
    build_id: str = Field(default='', max_length=256)
    inventory_digest: str = Field(min_length=1, max_length=256)
    maintenance_mode: bool = Field(strict=True)
    capabilities: dict[str, int] = Field(default_factory=dict, max_length=8)
    containers: dict[str,ContainerIdentity] = Field(default_factory=dict,max_length=128)
    reports: list[RemediationReport] = Field(default_factory=list, max_length=64)

    @model_validator(mode='after')
    def matching_scopes(self):
        if any(scope!='container:'+identity.name.removeprefix('/') for scope,identity in self.containers.items()):
            raise ValueError('Container identity map keys must match the reported container names')
        if any(len(key)>64 for key in self.capabilities):
            raise ValueError('Capability names must be bounded')
        return self


IDENTITY = ('local_plan_id','origin','service_plan_id','scope','package_name','from_version',
            'target_version','component_id','architecture','finding_ids','cve_ids',
            'inventory_digest','inventory_epoch','build_id','container_identity')
POST_RESOLUTION_OPERATIONS = frozenset({'rollback_required','rolling_back','rolled_back','rollback_failed',
    'rollback_unknown','failed','staging_failed','unknown','denied'})


def _known_inventory(session, device, epoch, digest):
    # InventoryMessage.digest is the wire-envelope replay hash, not the package
    # inventory hash. Accepted inventory events retain the latter explicitly.
    if device.epoch==epoch and device.inventory_digest==digest:
        return True
    return session.scalar(select(Record.id).where(Record.kind=='event',Record.owner==device.id,
        Record.payload['type'].as_string().in_(['inventory.checkpoint','inventory.delta']),
        Record.payload['details']['epoch'].as_string()==epoch,
        Record.payload['details']['inventory_digest'].as_string()==digest.removeprefix('sha256:')).limit(1)) is not None


def _selection(session, device_id, report):
    """Retain original findings even when their current-list rows disappear."""
    candidates = [row.payload for row in session.scalars(select(Record).where(
        Record.kind=='finding', Record.owner==device_id,
        Record.payload['component_id'].as_string()==report['component_id'],
        Record.payload['cve_id'].as_string().in_(report['cve_ids'])))]
    selected = []
    for cve in report['cve_ids']:
        matches = [f for f in candidates if f.get('cve_id')==cve
            and f.get('component_id')==report['component_id'] and f.get('scope')==report['scope']
            and f.get('package_name')==report['package_name'] and f.get('affected_version')==report['from_version']
            and f.get('inventory_digest')==report['inventory_digest'] and f.get('inventory_epoch')==report['inventory_epoch']
            and f.get('build_id')==report['build_id']]
        if report.get('finding_ids'):
            matches = [f for f in matches if f['id'] in report['finding_ids']]
        if not matches:
            # The same occurrence/CVE finding ID is reused by a newer scan.
            # Its immutable assessment history retains the original version.
            history=session.scalars(select(Record).where(Record.kind=='assessment_history',
                Record.payload['device_id'].as_string()==device_id,
                Record.payload['component_id'].as_string()==report['component_id'],
                Record.payload['cve_id'].as_string()==cve,
                Record.payload['affected_version'].as_string()==report['from_version'],
                Record.payload['inventory_digest'].as_string()==report['inventory_digest']))
            matches=[{**item.payload,'id':item.payload.get('finding_id')} for item in history
                if item.payload.get('scope')==report['scope']
                and item.payload.get('package_name')==report['package_name']
                and item.payload.get('inventory_epoch')==report['inventory_epoch']
                and item.payload.get('build_id')==report['build_id']
                and (not report.get('finding_ids') or item.payload.get('finding_id') in report['finding_ids'])]
        if not matches:
            return []
        selected.append(copy.deepcopy(matches[0]))
    return selected


def ingest(service, envelope, identity):
    """Authenticate device scope and atomically accept monotonically revised rows."""
    body = envelope.model_dump()
    accepted, rejected = [], []
    with service.store.lock, service.store.sessions.begin() as session:
        if identity.get('role') != 'agent':
            raise HTTPException(403, 'A device-scoped collector token is required for remediation reports')
        token = session.get(Token, identity['id'])
        if not token or token.revoked or token.device_id != body['device_id']:
            raise HTTPException(403, 'Collector credential does not belong to this switch')
        device = session.get(Device, body['device_id'])
        if not device:
            raise HTTPException(409, 'Synchronize switch inventory before reporting maintenance')
        if body['epoch'] != device.epoch or body['build_id'] != device.payload.get('build_id',''):
            raise HTTPException(409, 'Maintenance report belongs to a different switch epoch or build')
        known = _known_inventory(session,device,device.epoch,body['inventory_digest'])
        if not known:
            raise HTTPException(409, 'Synchronize this inventory identity before reporting maintenance')
        received = now()
        device.last_seen = received
        device.payload = {**device.payload, 'maintenance': {
            'maintenance_mode':body['maintenance_mode'],
            'capabilities':{key:value for key,value in body['capabilities'].items()
                            if key in ('container_package_update','local_plan_reporting') and value == 1},
            'containers':body['containers'],
            'reported_at':received,'epoch':device.epoch,'build_id':body['build_id']}}
        for report in body['reports']:
            ident = stable_hash([device.id, report['local_plan_id']])
            kind = 'local_remediation' if report['origin']=='cli' else 'collector_progress'
            row = session.get(Record, (kind, ident))
            previous = row.payload if row else {}
            reason = None
            if report['inventory_epoch'] != device.epoch or report['build_id'] != body['build_id']:
                reason = 'The local plan belongs to another epoch or build'
            elif previous and any(previous.get(key) != report.get(key) for key in IDENTITY):
                reason = 'A report cannot change the immutable package, finding or plan identity'
            elif previous and report['revision'] < previous['revision']:
                reason = 'An older report revision was ignored'
            elif previous and report['revision'] == previous['revision']:
                if previous.get('report_hash') != stable_hash(report):
                    reason = 'Conflicting content for the same report revision'
                else:
                    accepted.append({'local_plan_id':report['local_plan_id'],'revision':report['revision']})
                    continue
            elif (previous.get('status') in ('installed','restarting','pending_reassessment')
                    and report['status'] in ('draft','planned','approved','staging','downloading','downloaded','staged','installing')):
                reason = 'An installation report cannot regress to an earlier maintenance phase'
            elif report['origin']=='service':
                action = session.get(Record, ('action_request', report['request_id']))
                plan = session.get(Record, ('plan', report['service_plan_id']))
                approved = action.payload.get('plan',{}) if action else {}
                if (not plan or plan.owner != device.id or not action or action.owner != device.id
                        or approved.get('id') != report['service_plan_id']
                        or report['request_id'] != plan.payload.get('stage_request_id' if action.payload.get('action')=='stage_plan' else 'action_request_id')
                        or any(approved.get(k) != report.get(k) for k in
                               ('scope','package_name','from_version','target_version','inventory_digest','inventory_epoch','build_id'))
                        or not approved.get('approved')):
                    reason = 'Progress is not bound to the current authorized service action'
                elif set(report['finding_ids']) != set(approved.get('finding_ids',[])):
                    reason = 'Progress finding selection does not match the authorized service plan'
                elif report['scope'].startswith('container:') and any((approved.get('container_identity') or {}).get(key)
                        != (report.get('container_identity') or {}).get(key) for key in ('id','image','name')):
                    reason = 'Progress container identity differs from the authorized service plan'
            if reason:
                rejected.append({'local_plan_id':report['local_plan_id'],'reason':reason})
                continue
            selected = previous.get('selected_findings') or _selection(session, device.id, report)
            initial = _known_inventory(session,device,report['inventory_epoch'],report['inventory_digest'])
            value = {**previous, **report, 'id':ident,'device_id':device.id,'hostname':device.payload.get('hostname'),
                     'report_hash':stable_hash(report),'received_at':received,
                     'first_received_at':previous.get('first_received_at', received),
                     'selected_findings':selected,'original_inventory_known':bool(initial) or previous.get('original_inventory_known',False)}
            if report['origin']=='service' and report['status'] in POST_RESOLUTION_OPERATIONS:
                central=plan.payload.get('reassessment') or {}
                if central.get('status')=='completed':
                    value['invalidates_resolution_at']=received
            if report['status']=='pending_reassessment' and (not previous.get('execution_observed_at')
                    or previous.get('central_resolution',{}).get('reason_code')=='collector_operation_after_resolution'):
                value['execution_observed_at'] = received
            # Replayed installation reports cannot erase independently recorded resolution.
            if (previous.get('central_resolution',{}).get('status')=='completed'
                    and report['status'] in POST_RESOLUTION_OPERATIONS):
                value['last_resolution']=previous['central_resolution']
                value['central_resolution']={'status':'waiting','reason_code':'collector_operation_after_resolution',
                    'reason':'The collector reported a later recovery or failed operation; the earlier resolution is historical.',
                    'checked_at':received}
            elif previous.get('central_resolution'):
                value['central_resolution'] = previous['central_resolution']
            Store._put(session,kind,ident,value,device.id)
            accepted.append({'local_plan_id':report['local_plan_id'],'revision':report['revision']})
    # Reporting is independent of inventory collection. Reconciliation queues
    # work only once the exact target is observed; persisted reports recover this
    # decision after a crash, including a crash before this call.
    service.reconcile_maintenance(body['device_id'])
    projection=project(service.store,device_id=body['device_id'],limit=1000,include_unplanned=False)
    compact=[];size=0
    for row in projection['items']:
        value={key:row.get(key) for key in ('id','device_id','origin','plan_id','local_plan_id','report_revision',
            'finding_id','finding_ids','cve_id','cve_ids','component_id','package_name','scope','from_version',
            'target_version','current_version','state','status','collector_state','applicability','updated_at')}
        progress=row.get('progress') or {}
        value['progress']={key:progress[key] for key in ('phase','status','updated_at') if key in progress}
        value['progress']['events']=[{key:str(event[key])[:400] for key in ('phase','status','at','updated_at','message') if key in event}
            for event in (progress.get('events') or [])[-32:] if isinstance(event,dict)]
        resolution=row.get('central_resolution') or {}
        value['central_resolution']={key:resolution[key] for key in ('status','reason_code','reason','checked_at',
            'observed_version','scan_completed_at','scanner_db_revision') if key in resolution}
        value['reassessment']=value['central_resolution']
        rollback=row.get('rollback') or {}
        value['rollback']={key:rollback[key] for key in ('available','source','reason') if key in rollback}
        encoded=len(json.dumps(value).encode())
        if size+encoded>1500000:break
        compact.append(value);size+=encoded
    return {'accepted':accepted,'rejected':rejected,'service_time':now(),'remediation_status':compact,
            'remediation_total':projection['total'],'remediation_truncated':projection['total']>len(compact)}


def _local_assess(session, plan, device):
    result={'status':'waiting','selected_cves':plan['cve_ids'],'remaining_cves':[],
            'scope':plan['scope'],'package_name':plan['package_name'],'target_version':plan['target_version'],
            'observed_version':None,'execution_evidence':'collector_reported'}
    def waiting(code, reason):
        return {**result,'reason_code':code,'reason':reason}
    if not plan.get('original_inventory_known') or not plan.get('selected_findings'):
        return waiting('selection_unknown','The original inventory and scoped CVE selection have not been verified.')
    if not device or device.epoch!=plan['inventory_epoch'] or device.payload.get('build_id')!=plan['build_id']:
        return waiting('identity_mismatch','Current switch epoch or build differs from the CLI plan.')
    components=[c for c in device.payload.get('components',[]) if c.get('component_id')==plan['component_id']]
    if len(components)!=1:
        return waiting('identity_mismatch','The exact package occurrence is absent or ambiguous in current inventory.')
    component=components[0]
    if plan['scope'].startswith('container:'):
        device_view=Store._device_payload(device)
        if (not plan_container_matches(plan,device_view)
                or component.get('image_digest')!=(plan.get('container_identity') or {}).get('image')):
            return waiting('container_identity_mismatch','The running container identity or inventory image differs from the installed CLI plan.')
    if (component.get('scope')!=plan['scope'] or component.get('name')!=plan['package_name']
            or (plan.get('architecture') and component.get('architecture')!=plan['architecture'])):
        return waiting('identity_mismatch','Current package scope, name or architecture differs from the CLI plan.')
    result['observed_version']=component.get('version')
    if device.inventory_digest==plan['inventory_digest'] or component.get('version')!=plan['target_version']:
        return waiting('awaiting_inventory','Waiting for changed inventory containing the exact requested package version.')
    proof_row=session.get(Record,('maintenance_scan',device.id))
    proof=proof_row.payload if proof_row else {}
    result.update(inventory_digest=device.inventory_digest,assessment_revision=proof.get('assessment_revision'),
                  scanner_db_revision=proof.get('scanner_db_revision'),scan_completed_at=proof.get('scan_completed_at'))
    scanned, executed = _instant(proof.get('scan_completed_at')), _instant(plan.get('execution_observed_at'))
    if not scanned or not executed or scanned < executed:
        return waiting('awaiting_scan','Waiting for a complete scan accepted after the CLI installation report.')
    if (proof.get('identity')!=scan_identity(device) or proof.get('advisory_generation')!=_advisory_generation(session)
            or proof.get('scanner_db_revision')!=device.payload.get('scanner',{}).get('db_revision')):
        return waiting('stale_scan','Current inventory, evidence or advisory identity differs from the saved scan.')
    if (not proof.get('complete') or device.payload.get('scan_status')!='completed'
            or device.payload.get('coverage',{}).get('complete') is not True):
        return waiting('incomplete_scan','A partial or failed scan cannot establish resolution.')
    matches=set(proof.get('match_keys',[]))
    result['remaining_cves']=[cve for cve in plan['cve_ids'] if stable_hash([plan['scope'],plan['component_id'],cve]) in matches]
    if result['remaining_cves']:
        return waiting('remaining_findings','The selected CVEs are still reported for this exact package occurrence.')
    return {**result,'status':'completed','reason_code':'selected_cves_absent',
            'reason':'Current inventory reports the target version and a complete scan no longer reports the selected CVEs in this scope.'}


def reconcile_local(store, session, device_id=None):
    query=select(Record).where(Record.kind=='local_remediation',Record.payload['status'].as_string()=='pending_reassessment')
    if device_id:
        query=query.where(Record.owner==device_id)
    requests = []
    for row in session.scalars(query):
        plan=row.payload
        result=_local_assess(session,plan,session.get(Device,plan['device_id']))
        if result['reason_code'] in SCAN_REQUIRED_REASONS:
            requests.append(scan_request(plan, 'cli'))
        previous=plan.get('central_resolution') or {}
        result['checked_at']=previous.get('checked_at',now()) if {k:v for k,v in previous.items() if k!='checked_at'}==result else now()
        if previous!=result:
            row.payload={**plan,'central_resolution':result,'updated_at':now(),
                         'last_resolution':result if result['status']=='completed' else plan.get('last_resolution'),
                         'previously_resolved':plan.get('previously_resolved',False) or result['status']=='completed'}
            row.updated_at=now()
    return requests


def _current_scan(session, device, generation):
    """Read current scan proof once per switch; historical completion is separate."""
    record=session.get(Record,('maintenance_scan',device.id)) if device else None
    proof=record.payload if record else {}
    result={'proof':proof,'current':False,'matches':set(),
            'reason_code':'awaiting_scan','reason':'A current accepted complete scan is required to establish the CVE outcome.'}
    if not device or not proof or not _instant(proof.get('scan_completed_at')):
        return result
    if (proof.get('identity')!=scan_identity(device)
            or proof.get('advisory_generation')!=generation
            or not proof.get('scanner_db_revision')
            or proof.get('scanner_db_revision')!=device.payload.get('scanner',{}).get('db_revision')):
        return {**result,'reason_code':'stale_scan',
                'reason':'Inventory, build, evidence, policy or advisory identity changed; the earlier resolution remains historical.'}
    if (proof.get('complete') is not True or device.payload.get('scan_status')!='completed'
            or device.payload.get('coverage',{}).get('complete') is not True
            or device.payload.get('scanner',{}).get('status')!='complete'):
        return {**result,'reason_code':'incomplete_scan',
                'reason':'The latest scan is partial or unsuccessful; reassessment is required before reporting the current CVE outcome.'}
    return {**result,'current':True,'matches':set(proof.get('match_keys',[]))}


def _current_outcome(plan, component_id, cve, device, scan, historical, invalidated):
    """Project an already resolved occurrence against today's accepted scan.

    This never completes a plan or converts a collector installation into proof.
    A later rollback/failure retains its operation state even when an older scan
    had no matches. Only a fresh post-operation match can establish recurrence.
    """
    proof=scan['proof']
    resolution={'status':'waiting','selected_cves':[cve],'remaining_cves':[],
        'scope':plan['scope'],'package_name':plan['package_name'],'target_version':plan.get('target_version'),
        'inventory_digest':device.get('inventory_digest'),'observed_version':None,
        'assessment_revision':proof.get('assessment_revision'),'scanner_db_revision':proof.get('scanner_db_revision'),
        'scan_completed_at':proof.get('scan_completed_at'),'checked_at':proof.get('scan_completed_at'),
        'reason_code':scan['reason_code'],'reason':scan['reason']}
    components=[component for component in device.get('components',[]) if component.get('component_id')==component_id]
    occurrence=(components[0] if len(components)==1 else {})
    occurrence_matches=(occurrence.get('scope')==plan['scope'] and occurrence.get('name')==plan['package_name']
                        and (not plan.get('architecture') or occurrence.get('architecture')==plan['architecture']))
    resolution['observed_version']=occurrence.get('version')
    if not occurrence_matches:
        return 'pending_reassessment',{**resolution,'reason_code':'identity_mismatch',
            'reason':'The exact package occurrence is absent or ambiguous in current inventory; earlier resolution is historical.'},None
    if not scan['current']:
        return 'pending_reassessment',resolution,None
    matched=stable_hash([plan['scope'],component_id,cve]) in scan['matches']
    if invalidated:
        scanned_at=_instant(proof.get('scan_completed_at'))
        if not scanned_at or scanned_at<=invalidated:
            return None,resolution,None
        if not matched:
            return None,resolution,False
    if matched:
        return 'reopened',{**resolution,'remaining_cves':[cve],'reason_code':'remaining_findings',
            'reason':'The current accepted complete scan reports this CVE again for the exact package occurrence.'},True
    return 'resolved',{**resolution,'status':'completed','reason_code':'selected_cves_absent',
        'execution_evidence':historical.get('execution_evidence'),
        'reason':'The current accepted complete scan no longer reports this CVE for the exact package occurrence.'},False


def project(store, device_id=None, cve_id=None, scope=None, status=None, limit=100, offset=0, record_id=None,
            include_unplanned=True):
    """Return one row per selected CVE and occurrence; history does not imply fleet resolution."""
    limit=min(max(limit,1),1000);offset=max(offset,0)
    with store.lock,store.sessions() as session:
        query=select(Record).where(Record.kind.in_(['plan','local_remediation','collector_progress']))
        if device_id:query=query.where(Record.owner==device_id)
        records=list(session.scalars(query))
        plan_records=[r for r in records if r.kind in ('plan','local_remediation')]
        if not include_unplanned and not plan_records:
            return {'items':[],'total':0,'limit':limit,'offset':offset,'counts':{}}
        device_query=select(Device)
        if device_id:device_query=device_query.where(Device.id==device_id)
        device_records={d.id:d for d in session.scalars(device_query)}
        devices={ident:Store._device_payload(device) for ident,device in device_records.items()}
        generation=_advisory_generation(session)
        scans={ident:_current_scan(session,device,generation) for ident,device in device_records.items()}
        summaries=select(Record).where(Record.kind=='finding_summary')
        if device_id:summaries=summaries.where(Record.owner==device_id)
        if not include_unplanned:
            selected_ids=set()
            for record in plan_records:
                value=record.payload
                selected_ids.update(value.get('finding_ids',[]))
                selected_ids.update(stable_hash([value['device_id'],value.get('component_id'),value.get('scope'),cve])
                                    for cve in value.get('cve_ids',[]))
            summaries=summaries.where(Record.id.in_(selected_ids))
        if scope:summaries=summaries.where(Record.payload['scope'].as_string()==scope)
        if cve_id:summaries=summaries.where(Record.payload['cve_id'].as_string().icontains(cve_id,autoescape=True))
        records.extend(session.scalars(summaries))
        findings={r.id:{**r.payload,'id':r.id} for r in records if r.kind=='finding_summary'}
        progress={r.payload.get('service_plan_id'):r.payload for r in records if r.kind=='collector_progress'}
        current={ (f['device_id'],f.get('scope'),f.get('component_id'),f.get('cve_id')):f
                  for f in findings.values() if (f.get('status')=='current'
                      and scans.get(f['device_id'],{}).get('current')
                      and stable_hash([f.get('scope'),f.get('component_id'),f.get('cve_id')])
                          in scans[f['device_id']]['matches'])}
        covered=set();items=[]
        for record in records:
            if record.kind not in ('plan','local_remediation'):continue
            plan=record.payload;local=record.kind=='local_remediation';device=devices.get(plan['device_id'],{})
            selected=plan.get('selected_findings') or [findings.get(i) or (plan.get('finding') if plan.get('finding',{}).get('id')==i else None) for i in plan.get('finding_ids',[])]
            selected=[f for f in selected if f]
            cves=plan.get('cve_ids',[]) if local else sorted({f['cve_id'] for f in selected})
            component_id=plan.get('component_id') or (selected[0].get('component_id') if selected else None)
            telemetry=plan if local else progress.get(plan['id'],{})
            resolution=plan.get('central_resolution',{}) if local else plan.get('reassessment',{})
            prior_resolution=plan.get('last_resolution') if local else None
            changed_after_resolution=bool(not local and resolution.get('status')=='completed'
                and _instant(telemetry.get('invalidates_resolution_at')) and _instant(resolution.get('checked_at'))
                and _instant(telemetry['invalidates_resolution_at']) > _instant(resolution['checked_at']))
            if changed_after_resolution:
                prior_resolution=resolution
                resolution={'status':'waiting','reason_code':'collector_operation_after_resolution',
                    'reason':'The collector reported a later recovery or failed operation; the earlier completed plan is historical.',
                    'checked_at':telemetry['received_at']}
            historical=(prior_resolution if (prior_resolution or {}).get('status')=='completed'
                        else resolution if resolution.get('status')=='completed' else {})
            if historical:
                prior_resolution=historical
            invalidated=(_instant(telemetry.get('invalidates_resolution_at')) if changed_after_resolution
                else _instant(resolution.get('checked_at'))
                    if resolution.get('reason_code')=='collector_operation_after_resolution' else None)
            scan=scans.get(plan['device_id']) or _current_scan(session,None,generation)
            observed=next((c.get('version') for c in device.get('components',[]) if c.get('component_id')==component_id),None)
            for cve in cves:
                key=(plan['device_id'],plan['scope'],component_id,cve);match=current.get(key);covered.add(key)
                finding=next((f for f in selected if f['cve_id']==cve),{})
                central=resolution.get('status')=='completed'
                state='resolved' if central and not match else 'reopened' if (central or plan.get('previously_resolved') or changed_after_resolution) and match else plan.get('status','planned')
                if changed_after_resolution and state!='reopened':
                    state=telemetry['status']
                if state!='reopened' and not central and telemetry.get('status') and (local or (plan.get('status') in ('staging_queued','queued','executing') and telemetry.get('request_id')==plan.get('stage_request_id' if plan.get('status')=='staging_queued' else 'action_request_id'))):
                    state=telemetry['status']
                if state=='draft':state='planned'
                if state=='completed' and not central:state='pending_reassessment'
                current_resolution=resolution
                current_match=bool(match) if scan['current'] else None
                if historical:
                    projected,current_evidence,current_match=_current_outcome(plan,component_id,cve,device,scan,historical,invalidated)
                    if invalidated and projected!='reopened':
                        state=telemetry.get('status') or plan.get('status','pending_reassessment')
                    else:
                        state=projected or 'pending_reassessment'
                        current_resolution=current_evidence
                effective=(match or finding)
                applicability=(effective.get('applicability') if current_match is True
                    and finding_is_current(effective,device) else 'under_investigation')
                items.append({'id':stable_hash([record.kind,record.id,cve]),'device_id':plan['device_id'],
                    'hostname':device.get('hostname') or plan.get('hostname'),'origin':'cli' if local else 'service',
                    'plan_id':None if local else plan['id'],'local_plan_id':telemetry.get('local_plan_id'),
                    'finding_id':finding.get('id'),'finding_ids':plan.get('finding_ids',[]),'cve_id':cve,'cve_ids':[cve],
                    'component_id':component_id,'package_name':plan['package_name'],'scope':plan['scope'],
                    'from_version':plan.get('from_version'),'target_version':plan.get('target_version'),
                    'observed_version':observed,'current_version':observed,'state':state,'status':state,
                    'collector_state':telemetry.get('status'),'applicability':applicability,
                    'report_revision':telemetry.get('revision'),
                    'finding_status':(match or finding).get('status'),'current_matching_finding':current_match,
                    'central_resolution':current_resolution,'reassessment':current_resolution,
                    'last_resolution':prior_resolution,
                    'updated_at':telemetry.get('received_at') or plan.get('updated_at') or plan.get('created_at'),
                    'progress':telemetry.get('progress',{}),'staging_result':plan.get('staging_result') or telemetry.get('staging_result'),
                    'execution_result':plan.get('execution_result') or telemetry.get('execution_result'),
                    'rollback':telemetry.get('rollback'),'maintenance_mode':device.get('maintenance',{}).get('maintenance_mode',False),
                    'available_actions':[] if local else ['review_plan']})
        for finding in findings.values():
            if not include_unplanned:break
            key=(finding['device_id'],finding.get('scope'),finding.get('component_id'),finding.get('cve_id'))
            if key in covered:continue
            device=devices.get(finding['device_id'],{})
            scan=scans.get(finding['device_id']) or _current_scan(session,None,generation)
            matched=(stable_hash([finding.get('scope'),finding.get('component_id'),finding.get('cve_id')])
                     in scan['matches']) if scan['current'] else None
            state=('no_longer_reported' if finding.get('status')=='no_longer_reported' else 'no_plan')
            if state=='no_longer_reported' and not scan['current']:
                state='pending_reassessment'
            applicability=(finding.get('applicability') if matched is True and finding_is_current(finding,device)
                           else 'under_investigation')
            items.append({'id':stable_hash(['inventory',finding['id']]),'device_id':finding['device_id'],'hostname':device.get('hostname'),
                'origin':'inventory','plan_id':None,'local_plan_id':None,'finding_id':finding['id'],'finding_ids':[finding['id']],
                'cve_id':finding.get('cve_id'),'cve_ids':[finding.get('cve_id')],'component_id':finding.get('component_id'),
                'package_name':finding.get('package_name'),'scope':finding.get('scope'),'from_version':finding.get('affected_version'),
                'target_version':None,'state':state,'status':state,'applicability':applicability,
                'finding_status':finding.get('status'),'current_matching_finding':matched,
                'updated_at':finding.get('last_seen') or finding.get('assessed_at'),'progress':{},'central_resolution':{},
                'available_actions':[]})
        filtered=[item for item in items if (not cve_id or cve_id.lower() in item['cve_id'].lower()) and (not scope or item['scope']==scope)]
        counts=dict(Counter(item['state'] for item in filtered))
        if status:filtered=[item for item in filtered if item['state']==status]
        if record_id:filtered=[item for item in filtered if item['id']==record_id]
        filtered.sort(key=lambda item:(item.get('updated_at') or '',item['id']),reverse=True)
        return {'items':filtered[offset:offset+limit],'total':len(filtered),'limit':limit,'offset':offset,'counts':counts}
