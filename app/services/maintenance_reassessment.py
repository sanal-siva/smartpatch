"""Close installed package plans using a committed scan of their exact occurrence.

Collector receipts prove the action outcome. An independent, accepted full scan
proves only that the selected CVEs were not reported for the observed target. AI
verdict changes and disappearance from an incomplete result cannot close a plan.
All functions run inside the caller's Store lock and database transaction.
"""
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.store import Device, InventoryMessage, Record, now, stable_hash
from .applicability_context import assessment_facts
from .maintenance_capability import plan_container_matches


def scan_identity(device):
    payload = device.payload
    fields = ('build_id', 'artifact_id', 'artifact_verified', 'binding_revision', 'review_revision',
              'baseline_digest', 'assessment_ruleset_version', 'assessment_build_evidence_policy',
              'assessment_policy_revision')
    return {'device_id': device.id, 'epoch': device.epoch, 'inventory_digest': device.inventory_digest,
            **{field: payload.get(field) for field in fields},
            'manifest_hash': stable_hash(payload.get('manifest', {})),
            'bound_manifest_hash': stable_hash(payload.get('bound_manifest', {})),
            'facts_hash': stable_hash(assessment_facts(payload.get('facts', [])))}


def _advisory_generation(session):
    status = session.get(Record, ('status', 'advisory'))
    return (status.payload if status else {}).get('generation', 0)


SCAN_REQUIRED_REASONS = frozenset({'awaiting_scan', 'stale_scan', 'incomplete_scan'})


def scan_request(plan, origin):
    """Name an execution durably; the scheduler adds the current scan context.

    A failed attempt is not automatically repeated on every heartbeat or restart.
    A different execution or assessment context can request a new attempt.
    """
    execution = (plan.get('execution_observed_at') if origin == 'cli'
                 else plan.get('action_request_id'))
    return {'id': stable_hash([origin, plan['id'], execution]),
            'device_id': plan['device_id'], 'plan_id': plan['id'], 'origin': origin}


def current_scan_complete(session, device):
    """Whether a superseded worker already has a current accepted successor."""
    row = session.get(Record, ('maintenance_scan', device.id)) if device else None
    proof = row.payload if row else {}
    return bool(device and proof.get('complete') and _instant(proof.get('scan_completed_at'))
                and proof.get('identity') == scan_identity(device)
                and proof.get('advisory_generation') == _advisory_generation(session)
                and proof.get('scanner_db_revision')
                and proof['scanner_db_revision'] == device.payload.get('scanner', {}).get('db_revision')
                and device.payload.get('scan_status') == 'completed'
                and device.payload.get('coverage', {}).get('complete') is True)


def remember_scan(store, session, device, result, revision):
    """Capture scan matches before later analysis-only updates can change views."""
    scanner = result.get('scanner') or {}
    complete = (result.get('coverage', {}).get('complete') is True
                and scanner.get('status') == 'complete' and bool(scanner.get('db_revision')))
    keys = set()
    for finding in result.get('findings', []):
        component_id = finding.get('component_id') or finding.get('component', {}).get('component_id')
        scope = finding.get('scope_id') or finding.get('scope')
        cve = finding.get('cve_id')
        if not component_id or not scope or not cve:
            complete = False
            continue
        ids = {cve}
        ids.update(item.get('id') for item in finding.get('related_vulnerabilities', []) if isinstance(item, dict))
        keys.update(stable_hash([scope, component_id, ident]) for ident in ids if ident)
    proof = {'schema_version': 1, 'identity': scan_identity(device), 'complete': complete,
             'assessment_revision': revision, 'inventory_digest': device.inventory_digest,
             'scanner_db_revision': scanner.get('db_revision'), 'scan_completed_at': now(),
             'advisory_generation': _advisory_generation(session), 'match_keys': sorted(keys)}
    store._put(session, 'maintenance_scan', device.id, proof, device.id)


def _instant(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def _receipt(session, plan):
    request_id = plan.get('action_request_id')
    row = session.get(Record, ('action_request', request_id)) if request_id else None
    request = row.payload if row else {}
    receipt = request.get('result') or {}
    value = receipt.get('value') or {}
    approved = request.get('plan') or {}
    matches = ('id', 'device_id', 'scope', 'package_name', 'from_version', 'target_version',
               'inventory_digest', 'inventory_epoch', 'build_id', 'finding_ids', 'finding_id',
               'container_identity', 'component_id', 'architecture', 'cve_ids')
    valid = (request.get('action') == 'execute_plan' and request.get('device_id') == plan.get('device_id')
             and request.get('status') == 'complete' and request.get('result_consumed') is True
             and request.get('request_id') == request_id and approved.get('approved') is True
             and all(approved.get(key) == plan.get(key) for key in matches)
             and receipt.get('fact_id') == request_id and receipt.get('status') == 'complete'
             and value.get('status') == 'pending_reassessment'
             and value.get('action', 'execute_plan') == 'execute_plan'
             and value.get('plan_id', plan['id']) == plan['id']
             and receipt.get('scope', plan.get('scope')) == plan.get('scope')
             and plan.get('execution_result') == receipt)
    return request if valid else None


def _selection(session, plan):
    selected = []
    for ident in plan.get('finding_ids', []):
        embedded = next((f for f in plan.get('selected_findings',[]) if f.get('id')==ident),plan.get('finding') or {})
        row = session.get(Record, ('finding', ident))
        finding = embedded if embedded.get('id') == ident else row.payload if row else None
        if not finding:
            return None
        if (finding.get('device_id') != plan.get('device_id') or finding.get('scope', finding.get('scope_id')) != plan.get('scope')
                or finding.get('package_name') != plan.get('package_name') or not finding.get('component_id') or not finding.get('cve_id')):
            return None
        selected.append(finding)
    if not selected or len({finding['component_id'] for finding in selected}) != 1:
        return None
    return selected


def _assess(session, plan, device):
    proof_row = session.get(Record, ('maintenance_scan', device.id)) if device else None
    proof = proof_row.payload if proof_row else {}
    result = {'status': 'waiting', 'scope': plan.get('scope'), 'package_name': plan.get('package_name'),
              'target_version': plan.get('target_version'), 'observed_version': None,
              'inventory_digest': device.inventory_digest if device else None,
              'assessment_revision': proof.get('assessment_revision'), 'selected_cves': [], 'remaining_cves': [],
              'scanner_db_revision': proof.get('scanner_db_revision'), 'scan_completed_at': proof.get('scan_completed_at')}

    def waiting(code, reason):
        return {**result, 'reason_code': code, 'reason': reason}

    request = _receipt(session, plan)
    if not request:
        return waiting('missing_execution_receipt', 'Waiting for a successful execution receipt bound to this approved plan.')
    if not device or device.epoch != plan.get('inventory_epoch') or device.payload.get('build_id') != plan.get('build_id'):
        return waiting('identity_mismatch', 'The current device epoch or build does not match the executed plan.')
    selected = _selection(session, plan)
    if not selected:
        return waiting('selection_unknown', 'The original package occurrence and selected CVEs could not be established.')
    result['selected_cves'] = sorted({finding['cve_id'] for finding in selected})
    component_id = selected[0]['component_id']
    components = [item for item in device.payload.get('components', []) if item.get('component_id') == component_id]
    if len(components) != 1:
        return waiting('identity_mismatch', 'Fresh inventory does not contain the exact package occurrence from this plan.')
    component = components[0]
    if plan.get('scope','').startswith('container:'):
        if (not plan_container_matches(plan,{'epoch':device.epoch,**device.payload})
                or component.get('image_digest')!=(plan.get('container_identity') or {}).get('image')):
            return waiting('container_identity_mismatch', 'The current container identity or inventory image differs from the executed plan.')
    expected_arch = plan.get('architecture') or (selected[0].get('component') or {}).get('architecture') or (selected[0].get('component') or {}).get('arch')
    if (component.get('scope') != plan.get('scope') or component.get('name') != plan.get('package_name')
            or (expected_arch and component.get('architecture') != expected_arch)):
        return waiting('identity_mismatch', 'The observed package scope, name or architecture differs from the executed plan.')
    result['observed_version'] = component.get('version')
    message = session.scalar(select(InventoryMessage).where(InventoryMessage.device_id == device.id,
                             InventoryMessage.epoch == device.epoch, InventoryMessage.sequence == device.sequence))
    accepted_at = _instant(message.created_at) if message else None
    requested_at = _instant(request.get('created_at'))
    if (device.inventory_digest == plan.get('inventory_digest') or not accepted_at or not requested_at
            or accepted_at < requested_at):
        return waiting('awaiting_inventory', 'Waiting for a changed inventory accepted after the execution request.')
    if component.get('version') != plan.get('target_version'):
        return waiting('target_version_mismatch', 'The current inventory does not report the requested target version.')
    if not proof:
        return waiting('awaiting_scan', 'Waiting for a full scan with an authoritative inventory and context snapshot.')
    scanned_at = _instant(proof.get('scan_completed_at'))
    if not scanned_at or scanned_at < requested_at:
        return waiting('stale_scan', 'The available scan predates the execution request or has no valid completion time.')
    if proof.get('identity') != scan_identity(device) or proof.get('advisory_generation') != _advisory_generation(session):
        return waiting('stale_scan', 'The available scan belongs to an earlier inventory, evidence context or advisory revision.')
    if (not proof.get('complete') or device.payload.get('scan_status') != 'completed'
            or device.payload.get('coverage', {}).get('complete') is not True):
        return waiting('incomplete_scan', 'Waiting for a successful complete scan of the current inventory.')
    if proof.get('scanner_db_revision') != device.payload.get('scanner', {}).get('db_revision'):
        return waiting('stale_scan', 'The scanner revision no longer matches the accepted full scan.')
    matches = set(proof.get('match_keys', []))
    result['remaining_cves'] = [cve for cve in result['selected_cves']
                               if stable_hash([plan['scope'], component_id, cve]) in matches]
    if result['remaining_cves']:
        return waiting('remaining_findings', 'The latest scan still reports selected CVEs for this package occurrence.')
    return {**result, 'status': 'completed', 'reason_code': 'selected_cves_absent',
            'reason': 'The target version is observed and the accepted complete scan no longer reports the selected CVEs for this package and scope.'}


def reconcile(store, session, device_id=None):
    query = select(Record).where(Record.kind == 'plan', Record.payload['status'].as_string() == 'pending_reassessment')
    if device_id is not None:
        query = query.where(Record.owner == device_id)
    summary = {'completed': [], 'waiting': [], 'needs_scan': [], 'scan_requests': []}
    needs_scan = set()
    for row in session.scalars(query.with_for_update()):
        plan = row.payload
        device = session.get(Device, plan.get('device_id'))
        assessment = _assess(session, plan, device)
        previous = plan.get('reassessment') or {}
        unchanged = {key: value for key, value in previous.items() if key != 'checked_at'} == assessment
        assessment['checked_at'] = previous.get('checked_at') if unchanged and previous.get('checked_at') else now()
        completed = assessment['status'] == 'completed'
        summary['completed' if completed else 'waiting'].append(plan['id'])
        # _assess reaches these reasons only after validating the bound receipt,
        # exact occurrence, target version and post-execution inventory. An
        # installation report by itself must not scan the pre-install inventory.
        if assessment['reason_code'] in SCAN_REQUIRED_REASONS and device:
            needs_scan.add(device.id)
            summary['scan_requests'].append(scan_request(plan, 'service'))
        updates = {**plan, 'reassessment': assessment, 'staging_eligible': False, 'execution_eligible': False}
        if completed:
            updates.update(status='completed', completed_at=assessment['checked_at'])
        if updates != plan:
            updates['updated_at'] = now()
            row.payload, row.updated_at = updates, now()
            if completed:
                event_id = stable_hash(['plan.reassessed', plan['id'], assessment['assessment_revision']])
                store._put(session, 'event', event_id, {'id': event_id, 'type': 'plan.reassessed',
                    'device_id': plan['device_id'], 'severity': 'info', 'message': assessment['reason'],
                    'created_at': assessment['checked_at'], 'details': {'plan_id': plan['id'], **assessment}}, plan['device_id'])
    summary['needs_scan'] = sorted(needs_scan)
    return summary
