from types import SimpleNamespace

import pytest

from app.db.store import Store, now
from app.services.request_lifecycle import reconcile_assessment_requests


@pytest.fixture
def runtime():
    store = Store('sqlite:///:memory:')
    yield SimpleNamespace(store=store)
    store.close()


def request(runtime, ident='request1', operations=None, status='queued'):
    row = {'id': ident, 'status': status, 'submitted_at': now(), 'operation_ids': operations or [],
           'response_fingerprint': 'original-response-digest', 'assessment_duration_ms': 12}
    runtime.store.put('request', ident, row)
    return row


def operation(runtime):
    return runtime.store.enqueue('investigate', {'device_id': 'test-device', 'finding_ids': ['fixture']})


def test_request_follows_durable_operation_and_terminal_history_is_immutable(runtime):
    job = operation(runtime)
    request(runtime, operations=[job['id']])
    assert reconcile_assessment_requests(runtime)['examined'] == 1
    assert runtime.store.get('request', 'request1')['status'] == 'queued'
    assert runtime.store.claim()['id'] == job['id']
    reconcile_assessment_requests(runtime)
    running = runtime.store.get('request', 'request1')
    assert running['status'] == 'in_progress' and running['started_at']
    runtime.store.update_operation(job['id'], 'completed', result={'accepted': True, 'errors': [], 'coverage': {'complete': True}})
    assert reconcile_assessment_requests(runtime)['completed'] == 1
    completed = runtime.store.get('request', 'request1')
    assert completed['status'] == 'completed' and completed['outcome'] == 'completed'
    assert completed['completed_at'] and completed['response_fingerprint'] == 'original-response-digest'
    assert completed['operation_summaries'][0]['completed_at']
    assert [event['status'] for event in completed['timeline']][-3:] == ['queued', 'in_progress', 'completed']
    runtime.store.update_operation(job['id'], 'failed', error_message='Later alteration must not rewrite completed request history')
    assert reconcile_assessment_requests(runtime)['examined'] == 0
    assert runtime.store.get('request', 'request1') == completed


@pytest.mark.parametrize('status,result,expected_status,outcome', [
    ('failed', None, 'failed', 'failed'),
    ('completed', {'errors': [{'stage': 'ai', 'message': 'provider unavailable'}]}, 'completed', 'completed_with_errors'),
    ('completed', {'coverage': {'complete': False}}, 'completed', 'completed_with_errors'),
    ('completed', {'accepted': False}, 'completed', 'superseded'),
    ('completed', {'status': 'superseded'}, 'completed', 'superseded'),
])
def test_terminal_outcomes_are_explicit_and_do_not_fabricate_success(runtime,status,result,expected_status,outcome):
    job = operation(runtime)
    request(runtime, operations=[job['id']])
    runtime.store.update_operation(job['id'], status, result=result)
    reconcile_assessment_requests(runtime)
    row = runtime.store.get('request', 'request1')
    assert row['status'] == expected_status and row['outcome'] == outcome
    assert row['completed_at']
    assert len(runtime.store.operations()) == 1  # observer never creates work


def test_multiple_operations_remain_active_until_all_are_terminal(runtime):
    first, second = operation(runtime), operation(runtime)
    request(runtime, operations=[first['id'], second['id'], first['id']])
    runtime.store.update_operation(first['id'], 'failed')
    reconcile_assessment_requests(runtime)
    row = runtime.store.get('request', 'request1')
    assert row['status'] == 'in_progress' and not row.get('completed_at')
    assert len(row['operation_summaries']) == 2
    runtime.store.update_operation(second['id'], 'completed', result={'accepted': True})
    reconcile_assessment_requests(runtime)
    assert runtime.store.get('request', 'request1')['status'] == 'failed'


def test_legacy_pending_migrates_and_missing_operations_are_explicit_failures(runtime):
    job = operation(runtime)
    request(runtime, 'legacy', [job['id']], 'pending')
    request(runtime, 'missing', ['removed-operation'], 'pending')
    request(runtime, 'invalid', [], 'pending')
    result = reconcile_assessment_requests(runtime)
    assert result['examined'] == 3 and result['failed'] == 2
    assert runtime.store.get('request', 'legacy')['status'] == 'queued'
    missing = runtime.store.get('request', 'missing')
    assert missing['status'] == 'failed'
    assert missing['operation_summaries'][0]['outcome'] == 'operation_missing'
    assert runtime.store.get('request', 'invalid')['outcome'] == 'invalid_operation_references'


def test_bounded_polling_rotates_active_rows_and_does_not_repeat_timeline(runtime):
    job = operation(runtime)
    for index in range(5):
        request(runtime, str(index), [job['id']])
    assert reconcile_assessment_requests(runtime, limit=2)['examined'] == 2
    assert reconcile_assessment_requests(runtime, limit=2)['examined'] == 2
    assert sum(bool(row.get('last_reconciled_at')) for row in runtime.store.list('request')) == 4
    reconcile_assessment_requests(runtime)
    before = {row['id']: row['timeline'] for row in runtime.store.list('request')}
    reconcile_assessment_requests(runtime)
    assert {row['id']: row['timeline'] for row in runtime.store.list('request')} == before


def test_reference_count_is_bounded(runtime):
    request(runtime, operations=['id'+str(index) for index in range(17)])
    reconcile_assessment_requests(runtime)
    assert runtime.store.get('request','request1')['outcome'] == 'invalid_operation_references'
