"""Scoped legacy assessment API backed by registered findings and package evidence.

Caller flags never confer trust. Optional provider work is an explicit bounded
background request, and cache reuse requires an unchanged server evidence state.
"""
import copy
import hashlib
import json
import math
import re
import threading
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, func
from app.db.store import Record, Device, now, stable_hash
from .assessment import finding_decision_fresh, result_cache_fresh, RULESET_VERSION
from .applicability_context import applicability_facts, assessment_facts

_LOCKS = [threading.Lock() for _ in range(64)]


class RequestAssessmentError(ValueError):
    def __init__(self, message, status_code=422):
        super().__init__(message)
        self.status_code = status_code


def _date(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timezone required')
    return parsed


def _device(runtime, ident):
    fields = ('sonic_version', 'build_id', 'artifact_id', 'artifact_verified', 'binding_revision', 'facts',
              'review_revision', 'assessment_ruleset_version', 'assessment_build_evidence_policy', 'assessment_policy_revision', 'bound_manifest', 'manifest', 'baseline_digest', 'scanner', 'assessment_revision')
    columns = [Device.id, Device.epoch, Device.inventory_digest]
    columns += [Device.payload[name].label(name) for name in fields]
    with runtime.store.sessions() as session:
        row = session.execute(select(*columns).where(Device.id == ident)).mappings().first()
        return dict(row) if row else None


def _device_identity(device):
    if device is None:
        return None
    return {key: device.get(key) for key in ('id', 'epoch', 'inventory_digest', 'build_id', 'artifact_id', 'artifact_verified',
                                            'binding_revision', 'review_revision', 'assessment_ruleset_version', 'assessment_build_evidence_policy', 'assessment_policy_revision',
                                            'baseline_digest', 'assessment_revision')} | {
        'assessment_build_evidence_policy': device.get('assessment_build_evidence_policy') or 'required',
        'facts_hash': stable_hash(assessment_facts(device.get('facts'))), 'manifest_hash': stable_hash(device.get('manifest') or {})}


def _canonical(payload):
    if not isinstance(payload.get('sonic_version'), str) or not 1 <= len(payload['sonic_version']) <= 256:
        raise RequestAssessmentError('sonic_version must be a bounded release label')
    requests = payload.get('vulnerabilities')
    if not isinstance(requests, list) or not 1 <= len(requests) <= 1000:
        raise RequestAssessmentError('Provide 1..1000 vulnerability queries')
    context = payload.get('device_context') or {}
    unique, order = {}, []
    for item in requests:
        if not isinstance(item, dict):
            raise RequestAssessmentError('Each vulnerability query must be an object')
        normalized = {key: item.get(key) for key in ('cve_id', 'package_name', 'affected_version', 'severity', 'cvss_score')}
        for key in ('cve_id', 'package_name', 'affected_version'):
            if not isinstance(normalized[key], str) or not normalized[key] or len(normalized[key]) > 256:
                raise RequestAssessmentError('Vulnerability identity fields must be bounded strings')
        score = normalized.get('cvss_score')
        if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10):
            raise RequestAssessmentError('cvss_score must be null or between 0 and 10')
        normalized['scope_id'] = item.get('scope_id') or item.get('scope') or context.get('scope_id') or context.get('scope')
        normalized['component_id'] = item.get('component_id') or context.get('component_id')
        for key in ('scope_id', 'component_id'):
            if normalized[key] is not None and (not isinstance(normalized[key], str) or len(normalized[key]) > 256):
                raise RequestAssessmentError('Scope/component selectors must be bounded strings')
        key = stable_hash(normalized)
        unique[key] = normalized
        order.append(key)
    return unique, order


def _matching_rows(runtime, kind, requested, owner=None, artifact_id=None):
    values = list(requested.values())
    where = [Record.kind == kind,
             Record.payload['cve_id'].as_string().in_({v['cve_id'] for v in values}),
             Record.payload['package_name'].as_string().in_({v['package_name'] for v in values})]
    if owner is not None:
        where.append(Record.owner == owner)
    if artifact_id:
        where.append(Record.payload['artifact_id'].as_string() == artifact_id)
    with runtime.store.sessions() as session:
        rows = session.execute(select(Record.id, Record.payload).where(*where).limit(5001)).all()
    if len(rows) > 5000:
        raise RequestAssessmentError('Query matches too many occurrences; provide exact scope/component selectors', 413)
    return [{**payload, 'id': ident} for ident, payload in rows]


def _security_revision(runtime, device_id, release_id):
    with runtime.store.sessions() as session:
        def revision(kinds, owner=None):
            query = select(func.max(Record.updated_at), func.count()).where(Record.kind.in_(kinds))
            if owner is not None:
                query = query.where(Record.owner == owner)
            return tuple(session.execute(query).one())
        return (revision(['reviewed_assessment', 'build_binding', 'release', 'artifact']),
                revision(['finding_summary'], device_id) if device_id else None,
                revision(['package_cve', 'release_finding'], release_id) if release_id else None)


def _record_projection(runtime, kind, ident, fields):
    if not ident:
        return None
    with runtime.store.sessions() as session:
        columns = [Record.payload[field].label(field) for field in fields]
        row = session.execute(select(*columns).where(Record.kind == kind, Record.id == ident)).mappings().first()
        return dict(row) if row else None


def _catalog_context(runtime, payload, device):
    supplied = payload.get('device_context') or {}
    if not isinstance(supplied, dict):
        raise RequestAssessmentError('device_context must be an object')
    for selector in ('device_id', 'artifact_id', 'release_id', 'scope_id', 'scope', 'component_id'):
        if supplied.get(selector) is not None and (not isinstance(supplied[selector], str) or len(supplied[selector]) > 256):
            raise RequestAssessmentError('Invalid context selector: ' + selector)
    if 'request_ai' in supplied and type(supplied['request_ai']) is not bool:
        raise RequestAssessmentError('request_ai must be a boolean')
    selected_id = device.get('artifact_id') if device else supplied.get('artifact_id')
    release_fields = ('release_id', 'artifact_id', 'build_id', 'verification', 'source_revision', 'resolved_commit', 'scanner',
                      'assessment_revision','scan_revision')
    artifact_fields = ('id', 'release_id', 'source_sha256', 'verification')
    release = _record_projection(runtime, 'release', supplied.get('release_id') or payload.get('sonic_version', ''), release_fields)
    artifact = _record_projection(runtime, 'artifact', selected_id, artifact_fields)
    if artifact and not release:
        release = _record_projection(runtime, 'release', artifact.get('release_id', ''), release_fields)
    if not artifact and release and release.get('artifact_id'):
        artifact = _record_projection(runtime, 'artifact', release['artifact_id'], artifact_fields)
    binding = _record_projection(runtime, 'build_binding', (release or {}).get('build_id', ''),
        ('artifact_id', 'build_id', 'verification', 'index_digest', 'sbom_digest', 'manifest_digest',
         'image_digest', 'verified_at', 'revoked_at', 'invalidated_at')) if release else None
    verified = bool(selected_id and artifact and artifact.get('id', selected_id) == selected_id and binding
        and binding.get('verification') == 'signature_verified' and binding.get('artifact_id') == selected_id
        and re.fullmatch(r'[0-9a-fA-F]{64}', artifact.get('source_sha256') or '')
        and binding.get('sbom_digest', '').removeprefix('sha256:') == artifact.get('source_sha256'))
    return release, artifact, binding, verified


def _record_matches(record, item):
    return (record.get('status', 'current') == 'current' and record.get('cve_id') == item['cve_id']
        and record.get('package_name') == item['package_name']
        and (record.get('affected_version') or record.get('installed_version')) == item['affected_version']
        and (not item.get('scope_id') or (record.get('scope_id') or record.get('scope')) == item['scope_id'])
        and (not item.get('component_id') or record.get('component_id') == item['component_id']))


def _current(record, device, context, current_db):
    if not record or not device or record.get('status') != 'current':
        return False
    if record.get('assessment_stale') or (record.get('build_evidence_policy') or 'required') != context.get('build_evidence_policy', 'required'):
        return False
    if record.get('assessment_policy_revision') != context.get('assessment_policy_revision'):
        return False
    desired = device.get('assessment_ruleset_version')
    if desired and record.get('ruleset_version') != desired and record.get('decision_basis') not in {'operator_review', 'artifact_verified'}:
        return False
    pairs = {'inventory_digest': device['inventory_digest'], 'inventory_epoch': device['epoch'], 'build_id': device.get('build_id'),
             'artifact_id': device.get('artifact_id'), 'artifact_verified': bool(device.get('artifact_verified')),
             'binding_revision': device.get('binding_revision') or 'unverified', 'review_revision': device.get('review_revision'),
             'context_hash': context['context_hash']}
    if any(record.get(key, False if key == 'artifact_verified' else 'unverified' if key == 'binding_revision' else None) != value for key, value in pairs.items()):
        return False
    assessed_db = (device.get('scanner') or {}).get('db_revision')
    if not current_db or assessed_db != current_db:
        return False
    if record.get('source_revision') and record['source_revision'] != context.get('source_revision'):
        return False
    return finding_decision_fresh(record, context)


def _unknown(item, reason):
    return {**{key: item.get(key) for key in ('cve_id', 'package_name', 'affected_version', 'scope_id', 'component_id')},
        'risk_score': item.get('cvss_score'), 'severity': item.get('severity') or 'UNKNOWN', 'confidence': None,
        'action_type': 'defer', 'expected_downtime_minutes': None, 'applicability': 'under_investigation',
        'remediation_eligible': False,
        'exposure': 'unknown', 'vex_verdict': None, 'assessed_at': now(), 'rationale': reason,
        'evidence_ids': [], 'assessment_source': 'unverified_query', 'identity_verified': False}


def _recommendation(record, source, identity_verified):
    applicability = record.get('applicability', 'under_investigation')
    action = record.get('action_type')
    if action not in {'defer', 'maintenance_window'}:
        action = 'maintenance_window' if applicability == 'affected' else 'defer'
    return {key: record.get(key) for key in ('cve_id', 'package_name', 'affected_version', 'component_id', 'severity',
        'confidence', 'expected_downtime_minutes', 'assessed_at', 'evidence_ids', 'fixed_versions', 'candidate_fixed_versions',
        'decision_valid_until', 'exposure_valid_until', 'decision_basis', 'vex_justification', 'assessment_state', 'review_required',
        'build_evidence_policy', 'artifact_binding', 'remediation_eligible')} | {
        'scope_id': record.get('scope_id') or record.get('scope'), 'risk_score': record.get('risk_score', record.get('cvss_score')),
        'action_type': action, 'applicability': applicability, 'exposure': record.get('exposure', 'unknown'),
        'vex_verdict': applicability if applicability in {'fixed', 'not_affected'} else None,
        'rationale': record.get('rationale') or record.get('justification') or 'Registered scoped assessment',
        'assessment_source': source, 'identity_verified': identity_verified, 'finding_id': record.get('id')}


def assess_request(runtime, payload, principal, request_started_monotonic=None):
    """Call via run_in_threadpool; start time may come only from server middleware.

    queue_wait_ms includes elapsed request handling before worker entry, including
    authentication and worker-queue wait. Durations end before the audit write;
    middleware remains authoritative for full HTTP response latency.
    """
    started = time.monotonic()
    trusted_start = request_started_monotonic
    duration_basis = 'server_request_entry_to_audit_prepare'
    if (type(trusted_start) not in (float, int) or not math.isfinite(trusted_start)
            or trusted_start < 0 or trusted_start > started):
        trusted_start = started
        duration_basis = 'worker_entry_to_audit_prepare'
    if hasattr(payload, 'model_dump'):
        payload = payload.model_dump()
    if not isinstance(payload, dict):
        raise RequestAssessmentError('Assessment request must be an object')
    if principal.get('role') not in {'admin', 'operator', 'agent'}:
        raise RequestAssessmentError('Authenticated operator or agent required', 403)
    supplied = payload.get('device_context') or {}
    if not isinstance(supplied, dict):
        raise RequestAssessmentError('device_context must be an object')
    for selector in ('device_id', 'artifact_id', 'release_id', 'scope_id', 'scope', 'component_id'):
        if supplied.get(selector) is not None and (not isinstance(supplied[selector], str) or len(supplied[selector]) > 256):
            raise RequestAssessmentError('Invalid context selector: ' + selector)
    device_id = principal.get('device_id') if principal['role'] == 'agent' else supplied.get('device_id')
    if principal['role'] == 'agent' and (not device_id or supplied.get('device_id') not in (None, device_id)):
        raise RequestAssessmentError('Agent assessment must use its enrolled device identity', 403)
    if device_id is not None and not isinstance(device_id, str):
        raise RequestAssessmentError('Invalid device selector')
    requested, order = _canonical(payload)
    device = _device(runtime, device_id) if device_id else None
    if device_id and not device:
        raise RequestAssessmentError('Device inventory is not registered', 404)
    config = runtime.configuration()
    current_db = runtime.scanner_info.get('db_revision')
    context = {'device_id': device_id, 'inventory_digest': (device or {}).get('inventory_digest'),
        'build_evidence_policy': config.get('build_evidence_policy', 'required'),
        'assessment_policy_revision': config.get('assessment_policy_revision'),
        'runtime_facts': assessment_facts((device or {}).get('facts')), 'artifact_verified': bool((device or {}).get('artifact_verified'))}
    context['context_hash'] = stable_hash(applicability_facts(context['runtime_facts']))
    source_revision = runtime._source_revision(device) if device else config.get('source_revision')
    context['source_revision'] = source_revision
    release, artifact, binding, artifact_verified = _catalog_context(runtime, payload, device)
    catalog_artifact = (artifact or {}).get('id') or (release or {}).get('artifact_id')
    security_revision = _security_revision(runtime, device_id, (release or {}).get('release_id'))
    state = {'device': _device_identity(device), 'source_revision': source_revision, 'source_roots': config.get('source_roots'),
             'build_evidence_policy': config.get('build_evidence_policy', 'required'),
             'assessment_policy_revision': config.get('assessment_policy_revision'),
             'advisory_db': current_db, 'advisory_generation': getattr(runtime, 'advisory_generation', 0),
             'security_revision': security_revision,
             'release': release, 'artifact': {key: (artifact or {}).get(key) for key in ('id', 'source_sha256', 'verification')},
             'binding': binding, 'ai': {key: config.get(key) for key in ('ai_enabled', 'ai_provider', 'ai_model', 'ai_api_url')}}
    key = stable_hash(['scoped-assessment-v2', RULESET_VERSION, sorted(requested.items()), payload.get('sonic_version'),
                       stable_hash(supplied),
                       supplied.get('artifact_id'), supplied.get('release_id'), bool(supplied.get('request_ai')),
                       principal.get('id'), principal['role'], device_id, state])
    stripe = int(key[:4], 16) % len(_LOCKS)
    with _LOCKS[stripe]:
        cached = runtime.store.get('assessment_response', key)
        try:
            within_ttl = cached and (datetime.now(timezone.utc) - _date(cached['created_at'])).total_seconds() < runtime.settings.cache_ttl_hours * 3600
        except (KeyError, TypeError, ValueError):
            within_ttl = False
        hit = bool(within_ttl and result_cache_fresh(cached['result'], context))
        if hit:
            # Store.get decodes a fresh JSON object per request; this object is not
            # shared with another session. The output rows are copied once below.
            core = cached['result']
        else:
            # Only a miss hydrates matching rows. The durable metadata revision in
            # the key and the final guard protect updates, deletions and retractions.
            summaries = _matching_rows(runtime, 'finding_summary', requested, owner=device_id) if device else []
            catalog = _matching_rows(runtime, 'package_cve', requested, owner=release['release_id'], artifact_id=catalog_artifact) if release and catalog_artifact else []
            current_catalog = []
            for row in catalog:
                current = runtime.store.get('release_finding', row['id'])
                if (current and current.get('status') == 'current' and current.get('artifact_id') == catalog_artifact
                        and current.get('assessed_at') == row.get('assessed_at')
                        and current.get('assessment_revision') == row.get('assessment_revision') and row.get('status') == 'current'):
                    current_catalog.append(row)
            catalog = current_catalog
            recommendations, queued_ids = [], []
            for case_key in sorted(requested):
                item = requested[case_key]
                matches = [record for record in summaries if _record_matches(record, item)]
                candidates = [record for record in catalog if _record_matches(record, item)]
                rec = _unknown(item, 'No uniquely bound current assessment is available for this package/version/CVE')
                if len(matches) > 1:
                    rec['rationale'] = 'Multiple scoped occurrences match; supply scope_id or component_id'
                    rec['ambiguous_occurrences'] = len(matches)
                elif len(matches) == 1:
                    record = runtime.store.get('finding', matches[0]['id'])
                    if _current(record, device, context, current_db):
                        rec = _recommendation(record, 'registered_device_finding', True)
                        if rec['applicability'] == 'under_investigation':
                            queued_ids.append(record['id'])
                    else:
                        rec['rationale'] = 'Registered finding is stale or its decision/evidence expired; fresh assessment is required'
                        rec['finding_id'] = matches[0]['id']
                        queued_ids.append(matches[0]['id'])
                elif not device and artifact_verified and len(candidates) == 1:
                    record = candidates[0]
                    release_db = (release.get('scanner') or {}).get('db_revision')
                    catalog_current=bool(release.get('scan_revision') and record.get('scan_revision')==release['scan_revision']
                        and not record.get('assessment_stale')
                        and record.get('assessment_policy_revision')==config.get('assessment_policy_revision')
                        and (record.get('build_evidence_policy') or 'required')==config.get('build_evidence_policy', 'required')
                        and record.get('source_revision')==(release.get('resolved_commit') or release.get('source_revision') or None)
                        and record.get('ruleset_version')==RULESET_VERSION)
                    if (not record.get('device_id') and release_db == current_db and current_db
                            and catalog_current and finding_decision_fresh(record) and record.get('decision_basis') != 'operator_review'):
                        rec = _recommendation(record, 'verified_artifact_catalog', True)
                        rec['assessment_scope'] = 'artifact_only; no running-device association established'
                if candidates:
                    rec['package_intelligence'] = [{field: row.get(field) for field in ('artifact_id', 'scope_id', 'component_id',
                        'installed_version', 'available_fix_versions', 'latest_available_version', 'repository_availability')} for row in candidates[:16]]
                    if not rec['identity_verified']:
                        rec['catalog_identity_status'] = 'candidate_information_only; release label is not artifact proof'
                if rec['applicability'] in {'fixed', 'not_affected'} and not rec.get('evidence_ids'):
                    rec = _unknown(item, 'Definitive assessment lacks recorded evidence and cannot be reused')
                if rec['applicability'] in {'fixed', 'not_affected'} and rec.get('decision_basis') not in {'operator_review', 'artifact_verified'}:
                    rec = _unknown(item, 'Exemption has no verified or reviewed decision basis')
                recommendations.append(rec)
            operation_ids = []
            ai_health = runtime.pipeline.ai.health()
            if device and supplied.get('request_ai') is True and config.get('ai_enabled') and ai_health.get('configured') and queued_ids:
                selected = sorted(set(queued_ids))[:10]
                operation = runtime.schedule_scan(device_id, investigate=True, finding_ids=selected)
                operation_ids.append(operation['id'])
            core = {'recommendations': recommendations, 'recommendation_keys': sorted(requested), 'operation_ids': operation_ids,
                    'analysis_status': 'pending' if operation_ids else 'current_lookup', 'unique_candidates': len(requested),
                    'assessment_source_revision': source_revision, 'advisory_db_revision': current_db,
                    'build_evidence_policy': config.get('build_evidence_policy', 'required'),
                    'scope_binding': 'registered_device' if device else 'verified_artifact' if artifact_verified else 'unverified_query'}
            deadlines = [rec[field] for rec in recommendations for field in ('decision_valid_until', 'exposure_valid_until') if rec.get(field)]
            if deadlines:
                core['cache_valid_until'] = min(deadlines, key=_date)
            with runtime.store.lock:
                current_config=runtime.configuration()
                if ((device and _device_identity(_device(runtime, device_id)) != _device_identity(device))
                        or current_config.get('build_evidence_policy', 'required') != state['build_evidence_policy']
                        or current_config.get('assessment_policy_revision') != state['assessment_policy_revision']):
                    raise RequestAssessmentError('Inventory or security context changed during assessment; retry', 409)
                runtime.store.put('assessment_response', key, {'created_at': now(), 'result': core})
    with runtime._metrics_lock:
        runtime.metrics['assessment_cache_hits' if hit else 'assessment_cache_misses'] += 1
    if hasattr(runtime, 'observations'):
        runtime.observations.cache_lookup(hit)
    by_key = dict(zip(core['recommendation_keys'], core['recommendations']))
    result = {key: copy.deepcopy(value) for key, value in core.items() if key not in {'recommendation_keys', 'recommendations'}}
    # These rows are JSON-native by construction/storage. A single C-backed JSON
    # round trip preserves independent duplicate rows without thousands of Python
    # deepcopy traversals. The same canonical bytes also supply the audit digest.
    encoded_recommendations = json.dumps([by_key[case_key] for case_key in order], sort_keys=True,
                                         separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    result['recommendations'] = json.loads(encoded_recommendations)
    result.update(request_id=str(uuid.uuid4()), cached=hit, served_at=now())
    result['provider_circuit_open'] = bool(runtime.pipeline.ai.health().get('circuit_open'))
    with runtime.store.lock:
        current_config=runtime.configuration()
        if ((device and _device_identity(_device(runtime, device_id)) != _device_identity(device))
                or current_config.get('build_evidence_policy', 'required') != state['build_evidence_policy']
                or current_config.get('assessment_policy_revision') != state['assessment_policy_revision']
                or runtime.scanner_info.get('db_revision') != current_db
                or getattr(runtime, 'advisory_generation', 0) != state['advisory_generation']
                or _security_revision(runtime, device_id, (release or {}).get('release_id')) != security_revision):
            raise RequestAssessmentError('Inventory, binding or advisory context changed during assessment; retry', 409)
    submitted_at = now()
    request_status = 'queued' if result['operation_ids'] else 'completed'
    finished = time.monotonic()
    total_ms = max(0, round((finished - trusted_start) * 1000))
    queue_ms = max(0, round((started - trusted_start) * 1000))
    result.update(assessment_duration_ms=total_ms, queue_wait_ms=queue_ms,
                  processing_duration_ms=max(0, total_ms - queue_ms),
                  duration_basis=duration_basis)
    runtime.store.put('request', result['request_id'], {'id': result['request_id'], 'smart_patch_instance_id': device_id,
        'sonic_version': payload.get('sonic_version'), 'cve_count': len(order), 'unique_cve_queries': len(requested),
        'status': request_status, 'submitted_at': submitted_at,
        'outcome': 'queued' if result['operation_ids'] else 'current_lookup',
        'completed_at': None if result['operation_ids'] else submitted_at,
        'timeline': [{'status': request_status, 'at': submitted_at, 'basis': 'request_record'}],
        'assessment_duration_ms': result['assessment_duration_ms'], 'response_cached': hit,
        'queue_wait_ms': result['queue_wait_ms'], 'processing_duration_ms': result['processing_duration_ms'],
        'duration_basis': result['duration_basis'],
        'response_fingerprint': hashlib.sha256(encoded_recommendations.encode()).hexdigest(), 'operation_ids': result['operation_ids'],
        'assessment_source': result['scope_binding']})
    return result
