"""Late observers must not recreate records for a device which no longer exists."""
from types import SimpleNamespace

import pytest
from sqlalchemy import delete

from app.db.store import Device, Operation, Record, Store, now
from app.services.analysis_lifecycle import advance_analysis_backlog, lifecycle_callback, run_analysis_backlog
from app.services.request_lifecycle import reconcile_assessment_requests


@pytest.fixture
def runtime():
    store = Store('sqlite:///:memory:')
    with store.sessions.begin() as session:
        for ident in ('removed-device', 'retained-device'):
            session.add(Device(id=ident, epoch='epoch', sequence=1,
                inventory_digest='digest', last_seen=now(), payload={'hostname': ident}))
    yield SimpleNamespace(store=store, configuration=lambda: {'ai_enabled': True},
        pipeline=SimpleNamespace(ai=SimpleNamespace(health=lambda: {'configured': True})), scanner_info={})
    store.close()


def test_late_analysis_callback_cannot_recreate_deleted_device_records(runtime):
    operation = runtime.store.enqueue('scan', {'device_id': 'removed-device'})
    assert runtime.store.claim()['id'] == operation['id']
    finding = {'component_id': 'openssl', 'scope': 'host', 'cve_id': 'CVE-2026-10000',
        'package_name': 'openssl', 'affected_version': '1.0', 'analysis_attempts': 1}
    callback = lifecycle_callback(runtime, operation, 'device', 'removed-device', identity={})
    callback(finding, 'pending_analysis')
    with runtime.store.sessions.begin() as session:
        session.execute(delete(Record).where(Record.owner == 'removed-device'))
        session.execute(delete(Operation).where(Operation.id == operation['id']))
        session.execute(delete(Device).where(Device.id == 'removed-device'))
    callback(finding, 'analyzed', success=True)
    runtime.store.update_operation(operation['id'], 'completed', result={'accepted': True})
    runtime.store.recover_jobs()
    assert runtime.store.list('analysis_lifecycle') == []
    assert runtime.store.list('event') == []
    assert runtime.store.operations() == []
    assert runtime.store.device('retained-device') is not None


def test_backlog_observers_ignore_missing_device_without_writes(runtime):
    backlog = {'id': 'stale-backlog', 'target_kind': 'device', 'target_id': 'removed-device',
        'status': 'pending', 'expected_identity': {}, 'created_at': now()}
    runtime.store.put('analysis_backlog', backlog['id'], backlog, 'removed-device')
    with runtime.store.sessions.begin() as session:
        session.execute(delete(Device).where(Device.id == 'removed-device'))
    assert advance_analysis_backlog(runtime) == []
    result = run_analysis_backlog(runtime, {'arguments': {'backlog_id': backlog['id']}})
    assert result['status'] == 'superseded' and result['provider_cases_run'] == 0
    assert runtime.store.get('analysis_backlog', backlog['id']) == backlog
    assert runtime.store.operations() == []


def test_request_observer_ignores_removed_request_and_completes_retained_request(runtime):
    for device_id in ('removed-device', 'retained-device'):
        operation = runtime.store.enqueue('scan', {'device_id': device_id})
        runtime.store.put('request', device_id + '-request', {
            'id': device_id + '-request', 'smart_patch_instance_id': device_id,
            'status': 'queued', 'submitted_at': now(), 'operation_ids': [operation['id']]}, device_id)
        if device_id == 'retained-device':
            runtime.store.update_operation(operation['id'], 'completed', result={'accepted': True})
    with runtime.store.sessions.begin() as session:
        session.execute(delete(Record).where(Record.owner == 'removed-device'))
        session.execute(delete(Operation).where(Operation.payload['arguments']['device_id'].as_string() == 'removed-device'))
        session.execute(delete(Device).where(Device.id == 'removed-device'))
    result = reconcile_assessment_requests(runtime)
    assert result['examined'] == result['completed'] == 1
    assert runtime.store.get('request', 'removed-device-request') is None
    assert runtime.store.get('request', 'retained-device-request')['status'] == 'completed'
