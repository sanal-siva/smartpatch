"""Shared, transactional single-switch maintenance commands.

The transaction facade lets a batch and its child plans/action outbox commit
atomically. The process-wide Store lock also serializes standalone commands.
"""
import copy
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from fastapi import HTTPException
from sqlalchemy import select
from app.db.store import Store, Record, Device, now, stable_hash
from app.services.assessment import RULESET_VERSION, finding_decision_fresh
from app.services.applicability_context import applicability_facts
from app.services.maintenance_capability import package_automation, plan_container_matches

class TransactionStore:
    def __init__(self, store, session):
        self.base, self.session, self.lock = store, session, store.lock
    def get(self, kind, ident):
        row = self.session.scalar(select(Record).where(Record.kind==kind,Record.id==ident))
        return copy.deepcopy(row.payload) if row else None
    def list(self, kind, owner=None, limit=None):
        query = select(Record).where(Record.kind == kind)
        if owner is not None: query = query.where(Record.owner == owner)
        if limit is not None: query = query.limit(limit)
        return [copy.deepcopy(row.payload) for row in self.session.scalars(query)]
    def device(self, ident):
        row = self.session.get(Device, ident)
        return copy.deepcopy(Store._device_payload(row)) if row else None
    def put(self, kind, ident, payload, owner=None):
        Store._put(self.session, kind, ident, copy.deepcopy(payload), owner)
        self.session.flush()
        return payload
    def audit(self, event_type, message, device_id=None, details=None, severity='info'):
        ident = str(uuid.uuid4())
        return self.put('event', ident, dict(id=ident, type=event_type, message=message,
            device_id=device_id, details=details or {}, severity=severity, created_at=now()), device_id)

@contextmanager
def transaction(runtime):
    with runtime.store.lock:
        config = runtime.configuration()
        with runtime.store.sessions.begin() as session:
            yield SimpleNamespace(store=TransactionStore(runtime.store, session), configuration=lambda: config)

def finding_is_current(finding,device):
    if not device or not finding_decision_fresh(finding,{'runtime_facts':device.get('facts',[])}):return False
    if (finding.get('build_evidence_policy') or 'required') != (device.get('assessment_build_evidence_policy') or 'required'):
        return False
    if finding.get('assessment_policy_revision') != device.get('assessment_policy_revision'):
        return False
    desired=device.get('assessment_ruleset_version')
    if desired and finding.get('ruleset_version')!=desired and finding.get('decision_basis') not in ('operator_review','artifact_verified'):
        return False
    facts=applicability_facts(device.get('facts',[]))
    return (finding.get('inventory_digest')==device.get('inventory_digest')
            and finding.get('inventory_epoch')==device.get('epoch')
            and finding.get('build_id')==device.get('build_id')
            and finding.get('context_hash')==stable_hash(facts)
            and finding.get('artifact_id')==device.get('artifact_id')
            and bool(finding.get('artifact_verified'))==bool(device.get('artifact_verified'))
            and finding.get('binding_revision','unverified')==device.get('binding_revision','unverified'))



def plan_is_current(plan,device):
    try:unexpired=datetime.fromisoformat(plan['expires_at'].replace('Z','+00:00'))>datetime.now(timezone.utc)
    except (KeyError,ValueError,TypeError):return False
    return bool(device and unexpired and device['inventory_digest']==plan.get('inventory_digest')
                and (plan.get('build_evidence_policy') or 'required')==(device.get('assessment_build_evidence_policy') or 'required')
                and plan.get('assessment_policy_revision')==device.get('assessment_policy_revision')
                and device['epoch']==plan.get('inventory_epoch') and device.get('build_id')==plan.get('build_id')
                and device.get('artifact_id')==plan.get('artifact_id')
                and bool(device.get('artifact_verified'))==bool(plan.get('artifact_verified'))
                and device.get('binding_revision','unverified')==plan.get('binding_revision','unverified')
                and device.get('review_revision')==plan.get('review_revision')
                and device.get('assessment_revision')==plan.get('assessment_revision')
                and finding_decision_fresh(plan.get('finding',{}))
                and plan.get('ruleset_version')==RULESET_VERSION)



def create_plan(service, body):
    device=service.store.device(body.device_id)
    if not device:raise HTTPException(404,'Device not found')
    findings=[service.store.get('finding',f) for f in body.finding_ids]
    if any(not f or f['device_id']!=body.device_id for f in findings):raise HTTPException(422,'Findings must belong to selected device')
    if any(not finding_is_current(f,device) for f in findings):raise HTTPException(409,'Reassess current build and inventory before planning changes')
    identities={(f.get('scope'),f.get('package_name'),f.get('affected_version')) for f in findings}
    if len(identities)!=1:raise HTTPException(422,'Create one plan per package and scope')
    if len({f.get('component_id') for f in findings})!=1:
        raise HTTPException(422,'Create one plan per exact package occurrence and architecture')
    scope,package,version=next(iter(identities))
    from app.services.maintenance_policy import resolve_maintenance_targets,MaintenancePolicyError
    from app.services.maintenance_jobs import repository_candidates
    try:
        resolution=resolve_maintenance_targets(findings,repository_candidates(service.store,device,package),body.target_version)
    except MaintenancePolicyError as exc:raise HTTPException(422,str(exc)) from exc
    target=resolution['target_version']
    candidates=[o['version'] for o in resolution['target_options']]
    selected=next((o for o in resolution['target_options'] if o['version']==target),None)
    automatable, automation_reason = package_automation(device, scope, package)
    high_impact = not automatable
    ident=str(uuid.uuid4())
    plan={'id':ident,'device_id':body.device_id,'hostname':device.get('hostname'),'finding_ids':body.finding_ids,
        'finding_id':body.finding_ids[0],'finding':findings[0],
        'cve_ids':sorted({f['cve_id'] for f in findings}), 'component_id':findings[0].get('component_id'),
        'architecture':(findings[0].get('component') or {}).get('architecture',''),
        'selected_findings':[{key:f.get(key) for key in ('id','device_id','cve_id','component_id','scope','package_name',
            'affected_version','inventory_digest','inventory_epoch','build_id','applicability','status')} for f in findings],
        'inventory_epoch':device['epoch'],'build_id':device.get('build_id'),
        'assessment_revision':device.get('assessment_revision'),
        'artifact_id':device.get('artifact_id'),'artifact_verified':bool(device.get('artifact_verified')),
        'binding_revision':device.get('binding_revision','unverified'),'review_revision':device.get('review_revision'),
        'ruleset_version':RULESET_VERSION,
        'build_evidence_policy':service.configuration().get('build_evidence_policy','required'),
        'assessment_policy_revision':service.configuration().get('assessment_policy_revision'),
        'scope':scope,'package_name':package,'from_version':version,'target_version':target,
        'candidate_versions':sorted(candidates),'inventory_digest':device['inventory_digest'],
        'status':'draft','approved':False,'execution_eligible':False,
        'staging_eligible':bool(selected and selected['status'] in ('candidate_only','recheck_passed') and not high_impact
                                and not resolution.get('applicability_review_required')
                                and all(f.get('applicability')=='affected' for f in findings)),
        'target_resolution':resolution,'target_package_sha256':selected.get('sha256') if selected else None,
        'maintenance_required':high_impact,'container_maintenance':bool(scope.startswith('container:') and automatable),
        'maintenance_reason':automation_reason,'created_at':now(),
        'expires_at':(datetime.now(timezone.utc)+timedelta(hours=24)).isoformat(),
        'steps':['Prepare the authorized exact target using configured APT sources',
                 'Apply the switch maintenance_checks_enabled policy to optional preflight and health checks',
                 'Stage forward artifacts and attempt rollback retention; inspect reported rollback availability',
                 'Apply only after explicit approval in a permitted mode',
                 'Validate health when enabled; automatic rollback requires complete retained artifacts',
                 'Collect updated inventory and re-assess centrally'],
        'limitations':['Optional maintenance checks follow the switch policy; authorization, target identity and actual package-manager errors remain enforced',
                      'Missing previous-version artifacts mean automatic rollback is unavailable'],
        'impact':automation_reason}
    if plan['container_maintenance']:
        plan['container_identity'] = copy.deepcopy(device['maintenance']['containers'][scope])
        plan['steps'].insert(0, 'Confirm the switch remains in maintenance mode; stage and install only in the selected running container')
        plan['steps'].insert(-1, 'Restart only the selected container after installation and collect its updated inventory')
        plan['limitations'].append('A package installed in a container writable layer is lost when that container is recreated; rebuild the SONiC image for a durable fix.')
    if high_impact:
        family='kernel' if package.startswith('linux-') else 'routing' if package.startswith('frr') else 'cryptographic library' if package.startswith(('openssl','libssl')) else 'SONiC service/container'
        plan['steps']=[
            f'Obtain a signed SONiC image or service image containing the verified {package} fix; record its exact digest and platform compatibility.',
            'Verify out-of-band recovery access, save the current configuration, and retain the previously bootable image and service image digests.',
            'Capture host services, affected containers, interfaces, BGP peers and received-prefix/route counts; agree a traffic-drain and rollback window.',
            'Stage the approved image with the platform-supported SONiC image workflow; verify signature, free space and rollback availability before activation.',
            'For kernel changes, use the approved reboot window and confirm the selected boot entry. For FRR, drain affected routing sessions before replacing/restarting its service image. For OpenSSL, identify and restart all affected consumers in the approved window.',
            'Compare post-change services, interfaces, peers and prefix/route counts against the captured baseline; recover the retained image and configuration if validation fails.',
            'Collect fresh scoped inventory, verify the new build binding, and reassess the selected CVEs before closing the maintenance record.']
        plan['maintenance_family']=family
        plan['expected_downtime_minutes']=None
        plan['limitations'].append('This is an operator maintenance runbook; automatic image activation, routing restarts and reboots are not executed by this package plan.')
    service.store.put('plan',ident,plan,body.device_id)
    return plan


IN_FLIGHT = {'staging_queued', 'queued', 'executing', 'pending_reassessment', 'unknown', 'rollback_unknown'}


def require_plan(service, plan_id, batch_id=None):
    plan = service.store.get('plan', plan_id)
    if not plan:
        raise HTTPException(404, 'Plan not found')
    if plan.get('batch_id') and plan['batch_id'] != batch_id:
        raise HTTPException(409, 'This plan belongs to a remediation batch; use the batch workflow')
    return plan


def require_current(service, plan):
    device = service.store.device(plan['device_id'])
    if not plan_is_current(plan, device):
        raise HTTPException(409, 'Plan expired or build/inventory changed; create a new plan')
    if plan.get('container_maintenance'):
        allowed, reason = package_automation(device,plan.get('scope'),plan.get('package_name',''))
        if not allowed:
            raise HTTPException(409,reason)
        if not plan_container_matches(plan,device):
            raise HTTPException(409,'The selected container was replaced; create a new plan for its current identity')
    findings = [service.store.get('finding', ident) for ident in plan['finding_ids']]
    if not findings or any(not f or not finding_is_current(f, device) or f.get('applicability') != 'affected'
            or f.get('decision_basis') == 'inventory_advisory_match' or f.get('remediation_eligible') is False
            for f in findings):
        raise HTTPException(409, 'Record a current scoped affected review for every selected finding before remediation')
    return device


def device_busy(service, device_id, except_plan_id=None):
    for local in service.store.list('local_remediation', owner=device_id):
        if (local.get('central_resolution',{}).get('status') != 'completed'
                and local.get('status') in {'staging','downloading','installing','installed','restarting','pending_reassessment','rollback_required','rolling_back','unknown','rollback_unknown'}):
            return 'cli:' + local['local_plan_id']
    for other in service.store.list('plan', owner=device_id):
        if other['id'] == except_plan_id:
            continue
        if other.get('outcome_unknown') or other.get('status') in IN_FLIGHT:
            return other['id']
    # An outbox row remains a reservation until its matching collector receipt.
    # This covers policy invalidation or an unexpected plan-state transition.
    for action in service.store.list('action_request', owner=device_id):
        if (action.get('plan') or {}).get('id') == except_plan_id:
            continue
        if action.get('outcome_unknown') or (not action.get('result_consumed') and (action.get('status') == 'queued' or action.get('delivered_at'))):
            return (action.get('plan') or {}).get('id') or action.get('request_id')
    return None


def approve_plan(service, plan_id, actor, batch_id=None):
    plan = require_plan(service, plan_id, batch_id)
    require_current(service, plan)
    if plan.get('approved'):
        return plan
    if plan.get('status') not in ('draft', 'approved', 'staging_failed', 'validation_failed', 'unknown', 'denied'):
        raise HTTPException(409, 'Plan is not in an approvable state')
    plan = {**plan, 'status': 'approved', 'approved': True, 'approved_at': now(), 'approved_by': actor}
    service.store.put('plan', plan_id, plan, plan['device_id'])
    service.store.audit('plan.approved', 'Maintenance plan approved', plan['device_id'],
                        {'plan_id': plan_id, 'batch_id': batch_id, 'actor': actor})
    return plan


def queue_plan(service, plan_id, phase, actor, batch_id=None):
    plan = require_plan(service, plan_id, batch_id)
    stage = phase == 'stage'
    if plan.get('outcome_unknown'):
        raise HTTPException(409, 'An earlier maintenance outcome is unknown; operator recovery is required before dispatch')
    device = require_current(service, plan)
    allowed, reason = package_automation(device, plan.get('scope'), plan.get('package_name', ''))
    if not allowed:
        raise HTTPException(409, reason)
    if not plan_container_matches(plan,device):
        raise HTTPException(409,'The selected container was replaced; create a new plan for its current identity')
    if not plan.get('approved') or plan.get('maintenance_required'):
        raise HTTPException(409, 'Plan requires approval and an eligible package maintenance scope')
    if stage:
        if not plan.get('staging_eligible'):
            raise HTTPException(409, 'Plan requires approval and target verification before staging')
        if plan.get('status') in ('staging_queued', 'staged'):
            return plan
        if plan.get('status') in ('unknown', 'rollback_unknown'):
            raise HTTPException(409, 'An earlier maintenance outcome is unknown; operator recovery is required before staging')
        if plan.get('status') not in ('approved', 'staging_failed', 'denied'):
            raise HTTPException(409, 'Plan cannot be restaged while execution or reassessment is pending')
    elif not plan.get('execution_eligible') or plan.get('status') != 'staged':
        raise HTTPException(409, 'Plan requires approval and successful agent staging before execution')
    if device_busy(service, plan['device_id'], plan_id):
        raise HTTPException(409, 'Another maintenance operation is still active or awaiting an outcome on this switch')
    ident = str(uuid.uuid4())
    action = {'request_id': ident, 'device_id': plan['device_id'],
              'action': 'stage_plan' if stage else 'execute_plan', 'plan': plan,
              'status': 'queued', 'created_at': now(), 'batch_id': batch_id, 'authorized_by': actor}
    service.store.put('action_request', ident, action, plan['device_id'])
    plan = {**plan, 'status': 'staging_queued' if stage else 'queued',
            'stage_request_id' if stage else 'action_request_id': ident, 'execution_eligible': False}
    service.store.put('plan', plan_id, plan, plan['device_id'])
    service.store.audit('plan.' + phase + '_queued', 'Maintenance ' + phase + ' queued', plan['device_id'],
                        {'plan_id': plan_id, 'batch_id': batch_id, 'actor': actor, 'request_id': ident})
    return plan
