"""Durable orchestration of explicitly selected, independently authorized plans.

Only mutations and the scheduler dispatch work. An outbox request and its child
plan and batch are committed in one transaction under the single-process Store
lock. A missing/unknown receipt never frees an execution slot.
"""
import copy
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app.db.store import now, stable_hash
from .maintenance_commands import (transaction, create_plan, require_current,
    approve_plan, queue_plan, device_busy, finding_is_current, IN_FLIGHT)
from .maintenance_capability import package_automation


class BatchCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(default='Selected switch remediation', min_length=1, max_length=160)
    finding_ids: list[str] = Field(min_length=1, max_length=200)
    max_concurrent_switches: int = Field(default=1, ge=1, le=10, strict=True)
    pause_on_failure: bool = Field(default=True, strict=True)
    target_versions: dict[str, str] = Field(default_factory=dict, max_length=200)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=128)


class BatchEdit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1, strict=True)
    name: str | None = Field(default=None, min_length=1, max_length=160)
    finding_ids: list[str] | None = Field(default=None, min_length=1, max_length=200)
    max_concurrent_switches: int | None = Field(default=None, ge=1, le=10, strict=True)
    pause_on_failure: bool | None = Field(default=None, strict=True)
    target_versions: dict[str, str] | None = Field(default=None, max_length=200)


class BatchControl(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1, strict=True)


class BatchStage(BatchControl):
    confirmed_plan_ids: list[str] = Field(min_length=1, max_length=50)


class BatchExecute(BatchStage):
    confirmed_device_ids: list[str] = Field(min_length=1, max_length=50)


FAILURES = {'failed', 'staging_failed', 'validation_failed', 'denied', 'unknown',
            'rollback_unknown', 'rolled_back', 'rollback_failed', 'requires_revalidation', 'stale', 'cancelled', 'superseded'}
TERMINAL = FAILURES - {'unknown', 'rollback_unknown'} | {'completed'}
CLOSED = {'completed', 'completed_with_failures', 'stopped'}


def _online(service, device):
    try:
        seen = datetime.fromisoformat(device['last_seen'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - seen).total_seconds()
        return -30 <= age <= service.configuration().get('online_threshold_seconds', 180)
    except (TypeError, KeyError, ValueError):
        return False


def _entry_key(finding):
    return stable_hash([finding.get(key) for key in
        ('device_id', 'scope', 'package_name', 'affected_version', 'component_id')])[:24]


def _snapshot(plan):
    """Approval covers targets, findings and policy, not subsequent receipts/status."""
    keys = ('id', 'device_id', 'finding_ids', 'finding', 'selected_findings', 'cve_ids', 'component_id', 'architecture', 'container_maintenance', 'container_identity', 'scope', 'package_name', 'from_version',
            'target_version', 'inventory_digest', 'inventory_epoch', 'build_id', 'artifact_id',
            'artifact_verified', 'binding_revision', 'review_revision', 'assessment_revision',
            'ruleset_version', 'assessment_policy_revision', 'build_evidence_policy', 'expires_at',
            'target_resolution', 'target_package_sha256', 'maintenance_required', 'staging_eligible')
    return stable_hash({key: plan.get(key) for key in keys})


def _staged_snapshot(plan):
    return stable_hash([_snapshot(plan), plan.get('stage_request_id'), plan.get('staging_result')])


def _preview(service, batch):
    groups = defaultdict(list)
    for ident in dict.fromkeys(batch['finding_ids']):
        finding = service.store.get('finding', ident)
        if not finding:
            raise HTTPException(422, 'One or more selected findings no longer exist; refresh your selection')
        groups[_entry_key(finding)].append(finding)
    if len({f['device_id'] for fs in groups.values() for f in fs}) > 50:
        raise HTTPException(422, 'A remediation batch supports at most 50 switches')
    unknown = set(batch.get('target_versions', {})) - set(groups)
    if unknown:
        raise HTTPException(422, 'Target version override refers to an entry outside this selection')
    entries = []
    for ident, findings in groups.items():
        first = findings[0]
        device = service.store.device(first['device_id'])
        entry = {'id': ident, 'device_id': first['device_id'], 'hostname': (device or {}).get('hostname'),
                 'finding_ids': [f['id'] for f in findings], 'cve_ids': sorted({f['cve_id'] for f in findings}),
                 'scope': first['scope'], 'package_name': first['package_name'],
                 'from_version': first['affected_version'], 'target_version': None, 'target_options': [],
                 'eligibility': 'eligible', 'reason': 'Ready for explicit staging approval', 'status': 'draft'}
        if not device or any(not finding_is_current(f, device) for f in findings):
            entry.update(eligibility='stale', reason='Refresh inventory and reassess the selected findings')
        elif not _online(service, device):
            entry.update(eligibility='offline', reason='Switch has no recent heartbeat; reconnect and refresh this draft')
        elif not package_automation(device, first['scope'], first['package_name'])[0]:
            entry.update(eligibility='manual', reason=package_automation(device, first['scope'], first['package_name'])[1])
        elif any(not (f.get('fixed_versions') or f.get('candidate_fixed_versions')) for f in findings):
            entry.update(eligibility='no_fix', reason='No advisory-supported fixed target is recorded for every selected CVE')
        elif any(f.get('applicability') != 'affected' or f.get('remediation_eligible') is False
                 or f.get('decision_basis') == 'inventory_advisory_match' for f in findings):
            entry.update(eligibility='review_required', reason='Record a current scoped affected review for every selected finding')
        try:
            plan = create_plan(service, SimpleNamespace(device_id=entry['device_id'],
                finding_ids=entry['finding_ids'], target_version=batch.get('target_versions', {}).get(ident)))
            plan = {**plan, 'batch_id': batch['id'], 'batch_entry_id': ident}
            service.store.put('plan', plan['id'], plan, plan['device_id'])
            entry.update(plan_id=plan['id'], target_version=plan['target_version'],
                         target_options=plan['target_resolution']['target_options'])
            if entry['eligibility'] == 'eligible' and not plan['staging_eligible']:
                options = entry['target_options']
                selected = next((option for option in options if option['version'] == plan['target_version']), None)
                if not options:
                    reason = 'No supported common target is available; inspect advisory and repository evidence in a single-switch plan'
                elif plan['target_version'] is None:
                    reason = 'Choose one exact target version from the available options, then save this draft'
                elif selected and selected.get('status') == 'recheck_required':
                    reason = 'Central target recheck required; use a single-switch plan for repository target validation'
                else:
                    reason = 'Verify a supported target and applicability before staging'
                entry.update(eligibility='review_required', reason=reason)
        except HTTPException as exc:
            if entry['eligibility'] == 'eligible':
                entry.update(eligibility='error', reason=str(exc.detail))
        if entry['eligibility'] != 'eligible':
            entry['status'] = 'blocked'
        entries.append(entry)
    return entries


def _view(service, batch):
    result = copy.deepcopy(batch)
    result.pop('commands', None)
    result.pop('create_hash', None)
    for entry in result['entries']:
        if entry.get('plan_id'):
            plan = service.store.get('plan', entry['plan_id'])
            if plan:
                entry['plan'] = plan
                if entry.get('selected'):
                    entry['status'] = ('execution_pending' if entry.get('execution_authorization')
                                       and plan['status'] == 'staged' else plan['status'])
                    if entry.get('stopped'):
                        entry['status'] = 'stopped'
                for key in ('staging_result', 'execution_result', 'reassessment'):
                    if key in plan:
                        entry[key] = plan[key]
    result['counts'] = dict(Counter(e['status'] for e in result['entries']))
    result['eligible_count'] = sum(e['eligibility'] == 'eligible' for e in result['entries'])
    result['selected_count'] = sum(bool(e.get('selected')) for e in result['entries'])
    return result


def get_batch(runtime, ident):
    with transaction(runtime) as service:
        batch = service.store.get('remediation_batch', ident)
        if not batch:
            raise HTTPException(404, 'Remediation batch not found')
        return _view(service, batch)


def list_batches(runtime):
    with transaction(runtime) as service:
        batches = service.store.list('remediation_batch')
        return {'batches': [_view(service, batch) for batch in sorted(batches, key=lambda b: b['created_at'], reverse=True)]}


def create_batch(runtime, body, actor):
    data = body.model_dump()
    create_hash = stable_hash([actor, {k: v for k, v in data.items() if k != 'idempotency_key'}])
    with transaction(runtime) as service:
        if body.idempotency_key:
            for previous in service.store.list('remediation_batch'):
                if previous.get('idempotency_key') == body.idempotency_key and previous.get('created_by') == actor:
                    if previous.get('create_hash') != create_hash:
                        raise HTTPException(409, 'This idempotency key was already used for a different selection')
                    return _view(service, previous)
        batch = {**data, 'id': str(uuid.uuid4()), 'revision': 1, 'status': 'draft', 'created_at': now(),
                 'updated_at': now(), 'created_by': actor, 'create_hash': create_hash, 'commands': {},
                 'paused': False, 'stop_requested': False}
        batch['entries'] = _preview(service, batch)
        service.store.put('remediation_batch', batch['id'], batch)
        service.store.audit('remediation_batch.created', 'Remediation selection preview created',
            details={'batch_id': batch['id'], 'actor': actor, 'finding_ids': batch['finding_ids']})
        return _view(service, batch)


def _active(service, plan):
    if plan.get('outcome_unknown') or plan.get('status') in IN_FLIGHT:
        return True
    for key in ('stage_request_id', 'action_request_id'):
        action = service.store.get('action_request', plan.get(key, ''))
        if action and (action.get('outcome_unknown') or (not action.get('result_consumed') and (action.get('status') == 'queued' or action.get('delivered_at')))):
            return True
    return False


def _advance(service, batch):
    if batch['status'] == 'draft' or batch['status'] in CLOSED:
        return batch
    original = copy.deepcopy(batch)
    entries = batch['entries']
    selected = [e for e in entries if e.get('selected')]
    plans = {e['plan_id']: service.store.get('plan', e['plan_id']) for e in selected}
    for entry in selected:
        plan = plans[entry['plan_id']]
        if not plan:
            entry.update(status='unknown', reason='Child plan is missing; operator investigation required')
            batch.update(paused=True, pause_reason=entry['reason'])
            continue
        entry['status'] = plan['status']
        if plan['status'] == 'completed':
            entry['reason'] = (plan.get('reassessment') or {}).get('reason', 'Target inventory and selected-CVE reassessment completed')
        elif plan['status'] == 'pending_reassessment':
            entry['reason'] = (plan.get('reassessment') or {}).get('reason', 'Waiting for fresh inventory and a complete central reassessment')
        elif plan['status'] == 'staged':
            entry['reason'] = ('Execution is confirmed; waiting for available batch capacity'
                               if entry.get('execution_authorization') else 'Staging succeeded; explicit execution confirmation is still required')
        elif plan['status'] in ('unknown', 'rollback_unknown'):
            entry['reason'] = 'Outcome is unknown; this switch retains its reservation until operator recovery establishes the result'
        reassessment = plan.get('reassessment') or {}
        reassessment_failed = (plan['status'] == 'pending_reassessment' and (
            reassessment.get('reason_code') in {'remaining_findings', 'target_version_mismatch', 'identity_mismatch', 'selection_unknown'}
            or (service.store.device(plan['device_id']) or {}).get('scan_status') == 'failed'))
        if (plan['status'] in FAILURES or reassessment_failed) and not entry.get('failure_observed'):
            entry['failure_observed'] = now()
            entry['reason'] = (plan.get('invalidation_reason') or plan.get('reassessment', {}).get('reason')
                               or (entry['reason'] if plan['status'] in ('unknown', 'rollback_unknown') else
                                   'Inspect the collector result and current inventory'))
            if batch['pause_on_failure']:
                batch.update(paused=True, pause_reason=f"{entry['hostname'] or entry['device_id']}: {plan['status']}")
                service.store.audit('remediation_batch.auto_paused', 'Batch paused after child outcome',
                    entry['device_id'], {'batch_id': batch['id'], 'plan_id': plan['id'], 'status': plan['status']})
    active = sum(not plan or _active(service, plan) for plan in plans.values())
    if batch.get('stop_requested'):
        for entry in selected:
            plan = plans[entry['plan_id']]
            if plan and not _active(service, plan) and plan['status'] not in TERMINAL:
                entry['stopped'] = True
        batch['status'] = 'stopping' if active else 'stopped'
    elif batch.get('paused'):
        batch['status'] = 'paused'
    else:
        for entry in selected:
            plan = plans[entry['plan_id']]
            if not plan or active >= batch['max_concurrent_switches']:
                continue
            phase = ('stage' if plan['status'] == 'approved' else
                     'execute' if plan['status'] == 'staged' and entry.get('execution_authorization') else None)
            if not phase or entry.get('failure_observed'):
                continue
            device = service.store.device(entry['device_id'])
            if not _online(service, device):
                entry['reason'] = 'Waiting for a recent switch heartbeat; no new request dispatched'
                continue
            if device_busy(service, entry['device_id'], plan['id']):
                entry['reason'] = 'Waiting for another operation on this switch to finish'
                continue
            try:
                if _snapshot(plan) != entry['approved_snapshot']:
                    raise HTTPException(409, 'Approved child plan changed; create a fresh batch')
                if phase == 'execute' and _staged_snapshot(plan) != entry['execution_authorization']['snapshot']:
                    raise HTTPException(409, 'Staged result changed after execution confirmation')
                actor = entry['execution_authorization']['actor'] if phase == 'execute' else batch['approved_by']
                plans[plan['id']] = queue_plan(service, plan['id'], phase, actor, batch['id'])
                entry.update(status=plans[plan['id']]['status'], reason='Waiting for the collector outcome')
                active += 1
            except HTTPException as exc:
                plan = {**plan, 'status': 'requires_revalidation', 'execution_eligible': False,
                        'invalidation_reason': str(exc.detail)}
                service.store.put('plan', plan['id'], plan, plan['device_id'])
                plans[plan['id']] = plan
                entry.update(status=plan['status'], reason=str(exc.detail), failure_observed=now())
                if batch['pause_on_failure']:
                    batch.update(paused=True, pause_reason=str(exc.detail))
                    break
        statuses = [p['status'] if p else 'unknown' for p in plans.values()]
        if batch.get('paused'):
            batch['status'] = 'paused'
        elif any(s in ('queued', 'executing', 'pending_reassessment', 'unknown', 'rollback_unknown') for s in statuses) or any(
                e.get('execution_authorization') and plans[e['plan_id']] and plans[e['plan_id']]['status'] == 'staged' for e in selected):
            batch['status'] = 'executing'
        elif any(s in ('approved', 'staging_queued') for s in statuses):
            batch['status'] = 'staging'
        elif any(s == 'staged' for s in statuses):
            batch['status'] = 'ready'
        elif active:
            batch['status'] = 'executing'  # Authorization may be stale while a physical outcome remains uncertain.
        elif statuses and all(s in TERMINAL for s in statuses):
            batch['status'] = 'completed' if all(s == 'completed' for s in statuses) else 'completed_with_failures'
        if batch['status'] in CLOSED:
            batch['completed_at'] = now()
    if batch != original:
        batch['updated_at'] = now()
        service.store.put('remediation_batch', batch['id'], batch)
    return batch


def reconcile_batches(runtime):
    with transaction(runtime) as service:
        for batch in service.store.list('remediation_batch'):
            if batch['status'] not in CLOSED | {'draft'}:
                _advance(service, batch)


def mutate_batch(runtime, ident, action, body, actor):
    data = body.model_dump(exclude_none=True)
    command_hash = stable_hash([action, data, actor])
    with transaction(runtime) as service:
        batch = service.store.get('remediation_batch', ident)
        if not batch:
            raise HTTPException(404, 'Remediation batch not found')
        if command_hash in batch.get('commands', {}):
            return _view(service, batch)
        if body.expected_revision != batch['revision']:
            raise HTTPException(409, 'Batch changed; refresh it before confirming this action')
        if action in ('edit', 'refresh'):
            if batch['status'] != 'draft':
                raise HTTPException(409, 'Only a draft batch may be changed; create a fresh batch')
            for entry in batch['entries']:
                if entry.get('plan_id'):
                    plan = service.store.get('plan', entry['plan_id'])
                    if plan:
                        service.store.put('plan', plan['id'], {**plan, 'status': 'superseded'}, plan['device_id'])
            if action == 'edit':
                batch.update({k: v for k, v in data.items() if k != 'expected_revision'})
            batch['entries'] = _preview(service, batch)
        elif action == 'approve-and-stage':
            if batch['status'] != 'draft':
                raise HTTPException(409, 'This batch already has a frozen staging approval')
            selected = set(body.confirmed_plan_ids)
            eligible = {e.get('plan_id') for e in batch['entries'] if e['eligibility'] == 'eligible'}
            if len(selected) != len(body.confirmed_plan_ids) or not selected <= eligible:
                raise HTTPException(422, 'Confirm only unique eligible child plan IDs from this draft')
            device_ids = [e['device_id'] for e in batch['entries'] if e.get('plan_id') in selected]
            if len(set(device_ids)) != len(device_ids):
                raise HTTPException(422, 'Select one package occurrence per switch; create a fresh batch after reassessment for another package')
            batch.update(status='staging', approved_by=actor, approved_at=now())
            for entry in batch['entries']:
                entry['selected'] = entry.get('plan_id') in selected
                if entry['selected']:
                    plan = approve_plan(service, entry['plan_id'], actor, batch['id'])
                    entry['approved_snapshot'] = _snapshot(plan)
                    entry['status'] = 'approved'
                elif entry['eligibility'] == 'eligible':
                    entry['status'] = 'excluded'
        elif action == 'execute':
            if batch['status'] in CLOSED | {'draft', 'stopping'} or batch.get('paused'):
                raise HTTPException(409, 'Execution requires an active batch with successfully staged plans')
            selected = set(body.confirmed_plan_ids)
            staged = {e['plan_id']: e for e in batch['entries'] if e.get('selected')}
            if len(selected) != len(body.confirmed_plan_ids) or not selected <= set(staged):
                raise HTTPException(422, 'Confirm selected child plans from this batch')
            devices = {staged[ident]['device_id'] for ident in selected}
            if set(body.confirmed_device_ids) != devices or len(body.confirmed_device_ids) != len(devices):
                raise HTTPException(422, 'Confirm the exact device IDs for the selected staged plans')
            for plan_id in selected:
                entry = staged[plan_id]
                plan = service.store.get('plan', plan_id)
                if not plan:
                    raise HTTPException(409, 'Child plan is missing; investigate before proceeding')
                require_current(service, plan)
                if not plan.get('execution_eligible') or plan['status'] != 'staged' or entry.get('failure_observed'):
                    raise HTTPException(409, 'Every selected plan must have a successful current staging result')
                if _snapshot(plan) != entry['approved_snapshot']:
                    raise HTTPException(409, 'Approved plan changed; create a fresh batch')
                entry['execution_authorization'] = {'actor': actor, 'confirmed_at': now(), 'snapshot': _staged_snapshot(plan)}
                entry['status'] = 'execution_pending'
        elif action == 'pause':
            if batch['status'] in CLOSED | {'draft', 'stopping'}:
                raise HTTPException(409, 'This batch cannot be paused')
            batch.update(paused=True, pause_reason='Paused by operator', status='paused')
        elif action == 'resume':
            if not batch.get('paused') or batch.get('stop_requested'):
                raise HTTPException(409, 'Only a paused batch can resume')
            batch.update(paused=False, pause_reason=None)
        elif action == 'stop':
            if batch['status'] in CLOSED:
                raise HTTPException(409, 'This batch is already terminal')
            batch.update(stop_requested=True, paused=False, status='stopping')
        else:
            raise HTTPException(404, 'Unknown batch action')
        batch['revision'] += 1
        batch.setdefault('commands', {})[command_hash] = {'action': action, 'actor': actor, 'at': now()}
        batch['updated_at'] = now()
        service.store.audit('remediation_batch.' + action, 'Remediation batch ' + action,
            details={'batch_id': batch['id'], 'actor': actor, 'phase': action,
                     'confirmed_plan_ids': data.get('confirmed_plan_ids'),
                     'selected_device_ids': [e['device_id'] for e in batch['entries'] if e.get('selected')],
                     'revision': batch['revision']})
        service.store.put('remediation_batch', batch['id'], batch)
        batch = _advance(service, batch)
        return _view(service, batch)
