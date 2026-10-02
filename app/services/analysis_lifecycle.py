"""Durable per-CVE processing state and fair, bounded saved-evidence AI work.

Applicability remains an independent deterministic/reviewed decision. Lifecycle
records are audit observations; only a guarded accepted commit seeds work. No
scanner or provider HTTP call occurs in scheduling, recovery, or state hooks.
"""
import copy
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select

from app.db.store import Record, now, stable_hash
from .assessment import RULESET_VERSION
from .applicability_context import applicability_facts, assessment_facts
from .pipeline import analysis_due, MAX_ANALYSIS_ATTEMPTS


def analysis_identity(runtime, target_kind, target_id):
    from .release_service import retry_identity, release_retry_identity
    if target_kind == 'device':
        target = runtime.store.device(target_id)
        if not target:
            return None
        identity = retry_identity(runtime, target)
        identity['source_revision'] = (target.get('bound_manifest') or {}).get('source_revision') or target.get('sonic_version')
    elif target_kind == 'release':
        target = runtime.store.get('release', target_id)
        if not target:
            return None
        identity = release_retry_identity(runtime, target)
    else:
        raise ValueError('Unknown analysis target kind')
    configuration = runtime.configuration()
    identity.update(ruleset_version=RULESET_VERSION,
                    build_evidence_policy=configuration.get('build_evidence_policy', 'required'),
                    assessment_policy_revision=configuration.get('assessment_policy_revision'),
                    reviewed_revision=stable_hash(runtime.store.list('reviewed_assessment')),
                    source_roots_revision=stable_hash(configuration.get('source_roots', [])))
    return identity


def _finding_id(target_kind, target_id, finding, identity):
    scope = finding.get('scope_id', finding.get('scope'))
    if target_kind == 'device':
        return stable_hash([target_id, finding['component_id'], scope, finding['cve_id']])
    return stable_hash([target_id, identity.get('artifact_id'), scope, finding['component_id'], finding['cve_id']])


def _work_key(target_kind, target_id, finding, identity):
    # Tool observations added by AI do not change the initial input key. Exact
    # scanner evidence and occurrence/version still bind a result to its inputs.
    inputs = sorted([record for record in finding.get('evidence', []) if record.get('type') == 'scanner_match'],
                    key=lambda record: record.get('id', ''))
    return stable_hash([target_kind, target_id, identity, finding.get('component_id'),
                        finding.get('scope_id', finding.get('scope')), finding.get('cve_id'),
                        finding.get('affected_version'), inputs])


def lifecycle_callback(runtime, operation, target_kind, target_id, identity=None):
    """Record transitions separately from authoritative findings/history."""
    captured = copy.deepcopy(identity if identity is not None else analysis_identity(runtime, target_kind, target_id))
    def transition(finding, state, **details):
        expected = copy.deepcopy(captured or {})
        if details.get('scanner_revision'):
            expected['advisory_revision'] = details['scanner_revision']
        ident = _work_key(target_kind, target_id, finding, expected)
        with runtime.store.lock:
            if target_kind=='device' and runtime.store.device(target_id) is None:
                return
            previous = runtime.store.get('analysis_lifecycle', ident) or {}
            if state == 'pending_analysis' and previous.get('analysis_attempts', 0) > finding.get('analysis_attempts', 0):
                finding.update({key: previous[key] for key in ('analysis_attempts','analysis_last_attempt_at','analysis_next_attempt_at','analysis_retry_exhausted','analysis_success') if key in previous})
            event = {'state': state, 'at': now(), 'success': details.get('success'),
                     'attempt': finding.get('analysis_attempts', 0), 'operation_id': operation['id']}
            if details.get('error'):
                event['error'] = str(details['error'])[:500]
            record = {'id': ident, 'target_kind': target_kind, 'target_id': target_id,
                      'finding_id': _finding_id(target_kind, target_id, finding, expected),
                      'component_id': finding.get('component_id'), 'scope': finding.get('scope_id', finding.get('scope')),
                      'cve_id': finding.get('cve_id'), 'package_name': finding.get('package_name'),
                      'package_version': finding.get('affected_version'), 'expected_identity': expected,
                      'assessment_state': state, 'analysis_success': finding.get('analysis_success'),
                      'analysis_attempts': finding.get('analysis_attempts', 0), 'operation_id': operation['id'],
                      'analysis_last_attempt_at': finding.get('analysis_last_attempt_at'),
                      'analysis_next_attempt_at': finding.get('analysis_next_attempt_at'),
                      'analysis_retry_exhausted': finding.get('analysis_retry_exhausted', False),
                      'updated_at': event['at'], 'transitions': [*previous.get('transitions', []), event][-32:]}
            runtime.store.put('analysis_lifecycle', ident, record, target_id)
            runtime.store.operation_log(operation['id'], f"{finding.get('cve_id')} / {finding.get('component_id')} / {record['scope']}: {state}"
                                        + (f" (success={details['success']})" if 'success' in details else ''))
            runtime.store.audit('analysis.state_changed', 'CVE processing state changed',
                                target_id if target_kind == 'device' else None,
                                {'lifecycle_id': ident, 'finding_id': record['finding_id'], 'target_kind': target_kind,
                                 'target_id': target_id, **event})
            work = runtime.store.get('analysis_work', ident)
            if state == 'analyzing' and work:
                # Durable attempt reservation precedes provider I/O. A worker
                # crash cannot restore the budget or lose the next tail item.
                reserved = {**work['finding'], **{key: finding[key] for key in ('analysis_attempts','analysis_last_attempt_at','assessment_state') if key in finding}}
                runtime.store.put('analysis_work', ident, {**work, 'finding': reserved,
                    'status': _status(reserved), 'operation_id': operation['id'], 'updated_at': now()}, work['backlog_id'])
            if (state == 'pending_analysis' and work and work.get('status') == 'completed'
                    and operation.get('operation_type') != 'investigate'
                    and work.get('finding', {}).get('analysis_success') is True):
                return {'reuse': copy.deepcopy(work['finding'])}
            if state == 'pending_analysis':
                progress = work.get('finding', {}) if work else finding
                if int(progress.get('analysis_attempts', 0)) < int(finding.get('analysis_attempts', 0)):
                    progress = finding
                return {'progress': {key: progress[key] for key in ('analysis_attempts','analysis_last_attempt_at','analysis_next_attempt_at','analysis_retry_exhausted','analysis_success','pending_evidence_requests') if key in progress}}
        return None
    return transition



def restore_completed_progress(runtime, target_kind, target_id, result):
    """A matching cache hit must not roll current per-CVE progress backwards."""
    from .pipeline import _reuse_analysis
    restored = copy.deepcopy(result)
    identity = analysis_identity(runtime, target_kind, target_id)
    if identity is None:
        return restored
    evidence = {record['id']: record for record in restored.get('evidence', []) if record.get('id')}
    for finding in restored.get('findings', []):
        if not finding.get('evidence'):
            finding['evidence'] = [evidence[eid] for eid in finding.get('evidence_ids', []) if eid in evidence]
        work = runtime.store.get('analysis_work', _work_key(target_kind, target_id, finding, identity))
        if not work:
            continue
        previous = work.get('finding', {})
        if work.get('status') == 'completed' and previous.get('analysis_success') is True:
            finding['rationale'] = finding.get('justification', finding.get('rationale', ''))
            _reuse_analysis(finding, previous)
            evidence.update({record['id']: record for record in finding.get('evidence', []) if record.get('id')})
        elif previous.get('analysis_attempts', 0) > finding.get('analysis_attempts', 0):
            for key in ('assessment_state', 'analysis_attempts', 'analysis_success', 'analysis_last_attempt_at',
                        'analysis_next_attempt_at', 'analysis_retry_exhausted', 'analysis_error', 'pending_evidence_requests'):
                if key in previous:
                    finding[key] = copy.deepcopy(previous[key])
    restored['evidence'] = list(evidence.values())
    restored['ai_usage'] = {key: 0 for key in restored.get('ai_usage', {})}
    return restored

def provider_ready(runtime):
    configuration = runtime.configuration()
    ai = getattr(runtime.pipeline, 'ai', None)
    return bool(configuration.get('ai_enabled') and configuration.get('ai_max_calls', 4) > 0
                and configuration.get('ai_max_findings', 10) > 0 and ai and ai.health().get('configured')
                and not ai.health().get('circuit_open'))


def _advisory_current(runtime, expected):
    current = runtime.scanner_info.get('db_revision')
    return not current or expected.get('advisory_revision') == current


def _status(finding):
    if finding.get('assessment_state') == 'analyzed':
        return 'completed'
    if int(finding.get('analysis_attempts', 0)) >= MAX_ANALYSIS_ATTEMPTS:
        return 'exhausted'
    return 'waiting' if finding.get('pending_evidence_requests') else 'pending'


def seed_backlog(runtime, target_kind, target_id, *, expected_identity, assessment_revision):
    """Seed only the captured context and revision of an accepted commit.

    Never recapture identity after provider I/O: a settings/inventory change in
    the commit-to-seed gap must not relabel previous evidence as new work.
    """
    with runtime.store.lock:
        identity = analysis_identity(runtime, target_kind, target_id)
        target = runtime.store.device(target_id) if target_kind == 'device' else runtime.store.get('release', target_id)
        if (identity is None or identity != expected_identity or not target
                or target.get('assessment_revision') != assessment_revision):
            return None
        backlog_id = stable_hash([target_kind, target_id, identity])
        finding_kind = 'finding' if target_kind == 'device' else 'release_finding'
        current_findings = [f for f in runtime.store.list(finding_kind, owner=target_id)
                            if f.get('status') == 'current' and f.get('analysis_managed')]
        findings = [f for f in current_findings if f.get('assessment_revision') == assessment_revision]
        if not findings:
            return None
        ids = {_work_key(target_kind, target_id, finding, identity) for finding in current_findings}
        for finding in findings:
            ident = _work_key(target_kind, target_id, finding, identity)
            ids.add(ident)
            previous = runtime.store.get('analysis_work', ident) or {}
            # Successful unknowns and exhausted budgets survive matching rescans.
            if previous.get('status') in ('completed', 'exhausted'):
                continue
            snapshot = copy.deepcopy(finding)
            if int(previous.get('finding', {}).get('analysis_attempts', 0)) > int(snapshot.get('analysis_attempts', 0)):
                snapshot = previous['finding']
            runtime.store.put('analysis_work', ident, {'id': ident, 'backlog_id': backlog_id,
                'target_kind': target_kind, 'target_id': target_id, 'finding_id': finding['id'],
                'expected_identity': identity, 'finding': snapshot, 'status': _status(snapshot),
                'created_at': previous.get('created_at', now()), 'updated_at': now()}, backlog_id)
        # A complete/current scan can remove an occurrence without changing its
        # inventory key (for example a reviewed matcher correction).
        for work in runtime.store.list('analysis_work', owner=backlog_id):
            if work['id'] not in ids and work.get('status') not in ('completed', 'superseded'):
                runtime.store.put('analysis_work', work['id'], {**work, 'status': 'superseded'}, backlog_id)
        previous = runtime.store.get('analysis_backlog', backlog_id) or {}
        runtime.store.put('analysis_backlog', backlog_id, {**previous, 'id': backlog_id,
            'target_kind': target_kind, 'target_id': target_id, 'expected_identity': identity,
            'status': 'pending', 'next_due_at': previous.get('next_due_at', now()),
            'created_at': previous.get('created_at', now())}, target_id)
        return backlog_id


def _ready_work(runtime, backlog, at, limit=100):
    # Filter/order metadata in SQL and hydrate only a bounded batch of evidence.
    payload = Record.payload['finding']
    deadline = payload['analysis_next_attempt_at'].as_string()
    attempts = func.coalesce(payload['analysis_attempts'].as_integer(), 0)
    query = select(Record).where(Record.kind == 'analysis_work', Record.owner == backlog['id'],
        Record.payload['status'].as_string() == 'pending', attempts < MAX_ANALYSIS_ATTEMPTS,
        or_(deadline.is_(None), deadline <= at.isoformat())).order_by(
        attempts, func.coalesce(payload['analysis_last_attempt_at'].as_string(), ''), Record.created_at, Record.id).limit(limit)
    with runtime.store.sessions() as session:
        return [copy.deepcopy(row.payload) for row in session.scalars(query) if analysis_due(row.payload['finding'], at)]


def _has_pending_work(runtime, backlog):
    with runtime.store.sessions() as session:
        return session.scalar(select(Record.id).where(Record.kind == 'analysis_work', Record.owner == backlog['id'],
            Record.payload['status'].as_string().in_(['pending', 'waiting'])).limit(1)) is not None


def advance_analysis_backlog(runtime, timestamp=None):
    if not provider_ready(runtime):
        return []
    timestamp = timestamp or datetime.now(timezone.utc)
    queued = []
    # Oldest dispatch first also prevents busy devices starving other targets.
    with runtime.store.lock, runtime.store.sessions() as session:
        backlogs = [copy.deepcopy(row.payload) for row in session.scalars(select(Record).where(
            Record.kind == 'analysis_backlog', Record.payload['status'].as_string().not_in(['completed', 'superseded']))
            .order_by(Record.updated_at, Record.id).limit(128))]
    for backlog in backlogs:
        if len(queued) >= 8:
            break
        with runtime.store.lock:
            if backlog['target_kind'] == 'device' and runtime.store.device(backlog['target_id']) is None:
                continue
            if (analysis_identity(runtime, backlog['target_kind'], backlog['target_id']) != backlog['expected_identity']
                    or not _advisory_current(runtime, backlog['expected_identity'])):
                runtime.store.put('analysis_backlog', backlog['id'], {**backlog, 'status': 'superseded'}, backlog['target_id'])
                continue
            previous = runtime.store.operation(backlog.get('operation_id')) if backlog.get('operation_id') else None
            if previous and previous['status'] in ('queued', 'in_progress'):
                continue
            if not _ready_work(runtime, backlog, timestamp, limit=1):
                state = 'waiting' if _has_pending_work(runtime, backlog) else 'completed'
                runtime.store.put('analysis_backlog', backlog['id'], {**backlog, 'status': state, 'operation_id': None}, backlog['target_id'])
                continue
            operation = runtime.enqueue('analysis_backlog', {'backlog_id': backlog['id']}, 'analysis-backlog:' + backlog['id'])
            runtime.store.put('analysis_backlog', backlog['id'], {**backlog, 'status': 'queued', 'operation_id': operation['id'],
                              'last_dispatched_at': now()}, backlog['target_id'])
            queued.append(operation)
    return queued


def run_analysis_backlog(runtime, operation):
    backlog = runtime.store.get('analysis_backlog', operation['arguments']['backlog_id'])
    if not backlog:
        raise ValueError('Unknown analysis backlog')
    if not provider_ready(runtime):
        return {'status': 'paused', 'provider_cases_run': 0}
    kind, target_id = backlog['target_kind'], backlog['target_id']
    expected = backlog['expected_identity']
    if kind == 'device' and runtime.store.device(target_id) is None:
        return {'status': 'superseded', 'accepted': False, 'provider_cases_run': 0}
    if analysis_identity(runtime, kind, target_id) != expected or not _advisory_current(runtime, expected):
        runtime.store.put('analysis_backlog', backlog['id'], {**backlog, 'status': 'superseded'}, target_id)
        return {'status': 'superseded', 'accepted': False}
    batch_size = min(int(runtime.configuration().get('ai_max_findings', 10)), 100)
    work = _ready_work(runtime, backlog, datetime.now(timezone.utc), limit=batch_size)
    if not work:
        return {'status': 'waiting', 'provider_cases_run': 0}
    finding_kind = 'finding' if kind == 'device' else 'release_finding'
    selected = []
    for item in work:
        current = runtime.store.get(finding_kind, item['finding_id'])
        if (not current or current.get('status') != 'current'
                or _work_key(kind, target_id, current, expected) != item['id']):
            runtime.store.put('analysis_work', item['id'], {**item, 'status': 'superseded'}, backlog['id'])
            continue
        # Recover a crash after the authoritative result commit but before its
        # work checkpoint: completed unknowns must not call the provider again.
        if (current.get('analysis_attempts', 0) >= item['finding'].get('analysis_attempts', 0)
                and current.get('assessment_state') == 'analyzed' and current.get('analysis_success') is True):
            runtime.store.put('analysis_work', item['id'], {**item, 'finding': current, 'status': 'completed'}, backlog['id'])
            continue
        selected.append(item)
    if not selected:
        return {'status': 'superseded', 'provider_cases_run': 0}
    if kind == 'device':
        target = runtime.store.device(target_id)
        context = {'device_id': target_id, 'runtime_facts': assessment_facts(target.get('facts', [])),
            'inventory_digest': target['inventory_digest'], 'source_revision': runtime._source_revision(target),
            'artifact_id': target.get('artifact_id'), 'artifact_verified': bool(target.get('artifact_verified')),
            'build_id': target.get('build_id'), 'context_hash': stable_hash(applicability_facts(target.get('facts', [])))}
    else:
        from .release_history import release_assessment_identity
        target = runtime.store.get('release', target_id)
        release_expected = release_assessment_identity(target)
        context = {'artifact_id': target.get('artifact_id'), 'artifact_verified': False, 'runtime_facts': [],
                   'source_revision': target.get('resolved_commit') or target.get('source_revision')}
    context['advisory_revision'] = expected.get('advisory_revision')
    context['build_evidence_policy'] = expected.get('build_evidence_policy', 'required')
    context['_analysis_lifecycle'] = lifecycle_callback(runtime, operation, kind, target_id, expected)
    result = runtime.pipeline.retry_findings([copy.deepcopy(w['finding']) for w in selected], context)
    result['source_revision'] = context.get('source_revision')
    outputs = {f['id']: f for f in result['findings']}
    # Use current scanner coverage, never claim another scanner run happened.
    result.update(coverage=target.get('coverage', {}), scanner=target.get('scanner', {}))
    with runtime.store.lock:
        latest_target = runtime.store.device(target_id) if kind == 'device' else runtime.store.get('release', target_id)
        if (analysis_identity(runtime, kind, target_id) != expected or not _advisory_current(runtime, expected)
                or (latest_target or {}).get('assessment_revision') != target.get('assessment_revision')):
            return {'status': 'superseded', 'accepted': False, 'provider_cases_run': len(selected)}
        revision = stable_hash([backlog['id'], operation['id'], now()])
        if kind == 'device':
            guarded = {key: expected.get(key) for key in ('epoch', 'build_id', 'artifact_id', 'artifact_verified',
                'binding_revision', 'review_revision', 'baseline_digest', 'manifest_digest', 'facts_digest')}
            guarded['assessment_revision'] = target.get('assessment_revision')
            accepted = runtime.store.store_findings(target_id, target['inventory_digest'], result, revision, expected_identity=guarded,
                complete_scan=False, assessment_kind='ai_backlog')
        else:
            from .release_history import commit_release_assessment
            accepted = commit_release_assessment(runtime.store, target_id, result, revision,
                expected_identity=release_expected, artifact_id=target['artifact_id'],
                source_revision=context.get('source_revision'), assessment_kind='ai_backlog',
                identity_guard=lambda: analysis_identity(runtime, kind, target_id) == expected
                and _advisory_current(runtime, expected))
        if not accepted:
            return {'status': 'superseded', 'accepted': False, 'provider_cases_run': len(selected)}
        for item in selected:
            output = outputs.get(item['finding_id'], item['finding'])
            runtime.store.put('analysis_work', item['id'], {**item, 'finding': output,
                'status': _status(output), 'updated_at': now()}, backlog['id'])
        runtime.store.put('analysis_backlog', backlog['id'], {**backlog, 'status': 'pending', 'operation_id': operation['id']}, target_id)
    if kind == 'device':
        runtime.queue_evidence_requests(target_id, result.get('evidence_requests', []))
    for name, value in result.get('ai_usage', {}).items():
        if isinstance(value, (int, float)):
            runtime.metrics['ai_' + name] += value
    return {'status': 'completed', 'accepted': True, 'target_kind': kind, 'target_id': target_id,
            'assessment_revision': revision, 'provider_cases_run': len(selected), 'ai_usage': result.get('ai_usage', {}),
            'errors': result.get('errors', [])}
