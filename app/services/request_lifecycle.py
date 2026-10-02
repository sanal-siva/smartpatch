"""Reconcile assessment-request history with already-existing durable operations.

This observer neither enqueues work nor calls providers. Terminal request rows
are immutable; operation outcomes do not retroactively alter the original API
response fingerprint or imply that an applicability verdict was confirmed.
"""
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.store import Record, Operation, now


ACTIVE_REQUEST_STATES = frozenset({'pending', 'queued', 'in_progress'})
MAX_OPERATION_REFERENCES = 16
MAX_TIMELINE_ENTRIES = 32


def _time(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (AttributeError, TypeError, ValueError):
        return None


def _operation_summary(ident, operation):
    if operation is None:
        return {'operation_id': ident, 'status': 'failed', 'outcome': 'operation_missing'}
    status = operation['status']
    errors = operation.get('errors')
    has_errors = bool(errors) or operation.get('coverage_complete') is False
    if status in {'queued', 'in_progress'}:
        outcome = status
    elif status == 'failed':
        outcome = 'failed'
    elif status == 'superseded' or (status == 'completed' and
            (operation.get('accepted') is False or operation.get('result_status') == 'superseded')):
        outcome = 'superseded'
        status = 'completed'
    elif status == 'completed':
        outcome = 'completed_with_errors' if has_errors else 'completed'
    else:
        status, outcome = 'failed', 'invalid_operation_status'
    return {'operation_id': ident, 'status': status, 'outcome': outcome,
            'started_at': operation.get('started_at'),
            'completed_at': operation.get('completed_at'),
            'last_updated_at': operation.get('updated_at'),
            'error_count': len(errors) if isinstance(errors, list) else int(bool(errors)),
            'coverage_complete': operation.get('coverage_complete')}


def _request_state(summaries):
    statuses = {entry['status'] for entry in summaries}
    if 'in_progress' in statuses or ('queued' in statuses and len(statuses) > 1):
        return 'in_progress', 'in_progress'
    if statuses == {'queued'}:
        return 'queued', 'queued'
    if 'failed' in statuses:
        return 'failed', 'failed'
    outcomes = {entry['outcome'] for entry in summaries}
    if 'completed_with_errors' in outcomes:
        return 'completed', 'completed_with_errors'
    if 'superseded' in outcomes:
        return 'completed', 'superseded'
    return 'completed', 'completed'


def reconcile_assessment_requests(runtime, limit=100):
    """Observe a bounded, oldest-polled batch; retain final history unchanged."""
    limit = max(1, min(int(limit), 500))
    counts = {'examined': 0, 'transitioned': 0, 'completed': 0, 'failed': 0}
    with runtime.store.lock, runtime.store.sessions.begin() as session:
        records = list(session.scalars(select(Record).where(Record.kind == 'request',
            Record.payload['status'].as_string().in_(ACTIVE_REQUEST_STATES))
            .order_by(Record.updated_at, Record.id).limit(limit).with_for_update(skip_locked=True)))
        references = {}
        for record in records:
            values = record.payload.get('operation_ids')
            if (isinstance(values, list) and 1 <= len(values) <= MAX_OPERATION_REFERENCES and
                    all(isinstance(value, str) and 1 <= len(value) <= 256 for value in values)):
                references[record.id] = list(dict.fromkeys(values))
        ids = {ident for values in references.values() for ident in values}
        # Project only lifecycle inputs, excluding provider responses and unbounded logs.
        operations = {}
        if ids:
            rows = session.execute(select(Operation.id, Operation.status, Operation.updated_at,
                Operation.payload['started_at'].label('started_at'),
                Operation.payload['completed_at'].label('completed_at'),
                Operation.payload['result']['accepted'].as_boolean().label('accepted'),
                Operation.payload['result']['status'].label('result_status'),
                Operation.payload['result']['errors'].label('errors'),
                Operation.payload['result']['coverage']['complete'].as_boolean().label('coverage_complete'))
                .where(Operation.id.in_(ids))).mappings()
            operations = {row['id']: dict(row) for row in rows}
        observed_at = now()
        for record in records:
            previous = record.payload
            if record.id in references:
                summaries = [_operation_summary(ident, operations.get(ident)) for ident in references[record.id]]
                status, outcome = _request_state(summaries)
            else:
                summaries = []
                status, outcome = 'failed', 'invalid_operation_references'
            updated = {**previous, 'status': status, 'outcome': outcome,
                       'operation_summaries': summaries, 'last_reconciled_at': observed_at}
            timeline = list(previous.get('timeline') or [])
            if not timeline:
                timeline.append({'status': previous.get('status'), 'at': previous.get('submitted_at') or record.created_at,
                                 'basis': 'request_record'})
            if previous.get('status') != status or previous.get('outcome') != outcome:
                timeline.append({'status': status, 'outcome': outcome, 'at': observed_at,
                                 'basis': 'durable_operation_observation'})
                counts['transitioned'] += 1
            updated['timeline'] = timeline[-MAX_TIMELINE_ENTRIES:]
            starts = [_time(item.get('started_at')) for item in summaries]
            starts = [value for value in starts if value is not None]
            submitted = _time(previous.get('submitted_at'))
            if starts and not updated.get('started_at'):
                earliest = min(starts)
                updated['started_at'] = max(earliest, submitted or earliest).isoformat()
            if status in {'completed', 'failed'}:
                # This is the timestamp the terminal state was durably observed.
                # Actual operation timestamps remain available in the summaries.
                updated['completed_at'] = observed_at
                counts[status] += 1
            record.payload, record.updated_at = updated, observed_at
            counts['examined'] += 1
    return counts
