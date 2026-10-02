"""Post-install scheduling contracts; synthetic inventory, no scanner or switch."""
import copy

import pytest

from app.config import Settings
from app.db.store import now
from .test_remediation_batches_acceptance import Fleet, fleet
from .test_remediation_status_api import report_body, send, rows, container_fixture


def scans(fleet, *, active=False):
    return [job for job in fleet.store.operations() if job['operation_type'] == 'scan'
            and (not active or job['status'] in ('queued', 'in_progress'))]


def finish_jobs(fleet):
    # Fleet.scan supplies synthetic committed proof separately from its queue.
    for job in scans(fleet, active=True):
        fleet.store.update_operation(job['id'], 'completed')


def test_cli_report_waits_for_target_then_queues_one_current_scan(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    baseline = len(scans(fleet))
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    send(fleet, 'a', body)
    assert rows(fleet)['items'][0]['central_resolution']['reason_code'] == 'awaiting_inventory'
    send(fleet, 'a', body)
    fleet.runtime.recover_pending_scans()
    assert len(scans(fleet)) == baseline

    fleet.installed_inventory('a')
    current = fleet.store.device('a')
    assert len(scans(fleet)) == baseline + 1
    queued = scans(fleet, active=True)[0]
    assert queued['arguments']['inventory_digest'] == current['inventory_digest']
    send(fleet, 'a', body)
    fleet.runtime.recover_pending_scans()
    assert [job['id'] for job in scans(fleet, active=True)] == [queued['id']]
    assert len(fleet.store.list('maintenance_scan_dispatch', owner='a')) == 1


def test_current_running_scan_is_reused_without_status_regression(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    send(fleet, 'a', body)
    fleet.installed_inventory('a')
    queued = scans(fleet, active=True)[0]
    fleet.store.update_operation(queued['id'], 'in_progress')
    fleet.store.update_device('a', {'scan_status': 'running'})
    fleet.runtime.schedule_scan('a')
    send(fleet, 'a', body)
    assert fleet.store.device('a')['scan_status'] == 'running'
    assert [job['id'] for job in scans(fleet, active=True)] == [queued['id']]


def test_inventory_and_scan_before_cli_receipt_still_need_post_report_acceptance(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    fleet.installed_inventory('a'); fleet.scan('a', []); finish_jobs(fleet)
    baseline = len(scans(fleet))
    send(fleet, 'a', body)
    assert len(scans(fleet)) == baseline + 1
    assert rows(fleet)['items'][0]['state'] == 'pending_reassessment'
    fleet.scan('a', []); finish_jobs(fleet)
    send(fleet, 'a', body)
    assert rows(fleet)['items'][0]['state'] == 'resolved'
    assert len(scans(fleet)) == baseline + 1


@pytest.mark.parametrize('inventory_first', [False, True])
def test_service_receipt_queues_only_when_target_needs_proof(fleet, inventory_first):
    fleet.enroll('a'); finish_jobs(fleet)
    batch = fleet.stage(fleet.create_batch(['a'])); plan = batch['entries'][0]['plan']
    fleet.heartbeat('a', plan['stage_request_id'], 'staged')
    batch = fleet.execute(batch); plan = batch['entries'][0]['plan']
    baseline = len(scans(fleet))
    if inventory_first:
        fleet.installed_inventory('a'); fleet.scan('a', []); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 1, origin='service',
                       service_plan_id=plan['id'], request_id=plan['action_request_id'])
    send(fleet, 'a', body)
    assert len(scans(fleet)) == baseline + int(inventory_first)
    fleet.heartbeat('a', plan['action_request_id'], 'pending_reassessment')
    if inventory_first:
        assert fleet.store.get('plan', plan['id'])['status'] == 'completed'
        assert len(scans(fleet)) == baseline + 1
    else:
        assert not scans(fleet, active=True)
        fleet.installed_inventory('a')
        assert len(scans(fleet)) == baseline + 1
        assert len(scans(fleet, active=True)) == 1


def test_missing_or_wrong_target_does_not_create_reassessment_work(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    send(fleet, 'a', body)
    fleet.devices['a']['target'] = '1.0.1'
    fleet.installed_inventory('a')
    finish_jobs(fleet)
    baseline = len(scans(fleet))
    fleet.runtime.reconcile_maintenance()
    send(fleet, 'a', body)
    assert len(scans(fleet)) == baseline
    assert not fleet.store.list('maintenance_scan_dispatch')
    assert rows(fleet)['items'][0]['state'] == 'pending_reassessment'


def test_replaced_container_cannot_trigger_reassessment_for_old_plan(fleet):
    container_fixture(fleet); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    body['reports'][0]['container_identity'] = copy.deepcopy(body['containers']['container:pmon'])
    send(fleet, 'a', body)
    replacement = copy.deepcopy(body)
    replacement['reports'] = []
    replacement['containers']['container:pmon']['id'] = 'c' * 64
    send(fleet, 'a', replacement)
    fleet.installed_inventory('a'); finish_jobs(fleet)
    baseline = len(scans(fleet))
    fleet.runtime.reconcile_maintenance()
    assert len(scans(fleet)) == baseline
    assert not fleet.store.list('maintenance_scan_dispatch')
    assert rows(fleet)['items'][0]['central_resolution']['reason_code'] == 'container_identity_mismatch'


def test_queued_old_scan_is_updated_while_running_old_scan_keeps_one_successor(fleet):
    fleet.enroll('a')
    old = scans(fleet, active=True)[0]
    fleet.store.update_operation(old['id'], progress_percentage=70,
                                 progress_data={'phase': 'assessing', 'findings_completed': 99})
    fleet.installed_inventory('a')
    updated = scans(fleet, active=True)
    assert len(updated) == 1 and updated[0]['id'] == old['id']
    assert updated[0]['progress_percentage'] == 0 and 'progress_data' not in updated[0]
    assert updated[0]['arguments']['inventory_digest'] == fleet.store.device('a')['inventory_digest']
    fleet.store.update_operation(old['id'], 'in_progress')
    fleet.devices['a']['target'] = '1.2'
    fleet.installed_inventory('a')
    pending = [job for job in scans(fleet, active=True) if job['status'] == 'queued']
    assert len(pending) == 1 and pending[0]['id'] != old['id']
    fleet.devices['a']['target'] = '1.3'
    fleet.installed_inventory('a')
    latest = [job for job in scans(fleet, active=True) if job['status'] == 'queued']
    assert len(latest) == 1 and latest[0]['id'] == pending[0]['id']
    assert latest[0]['arguments']['inventory_digest'] == fleet.store.device('a')['inventory_digest']


def test_failed_attempt_and_report_survive_restart_without_retry_storm(tmp_path):
    config = Settings(_env_file=None, state_dir=tmp_path / 'state',
                      database_url='sqlite:///' + str(tmp_path / 'deferred.sqlite'),
                      jobs_enabled=False, scanner_binary='/not-installed/grype', source_roots=[], ai_enabled=False)
    value = Fleet(config)
    with value.connected() as fleet:
        fleet.enroll('a'); finish_jobs(fleet)
        body = report_body(fleet, 'a', 'pending_reassessment', 2)
        send(fleet, 'a', body)
    with value.connected() as fleet:
        fleet.runtime.recover_pending_scans()
        assert not scans(fleet, active=True)
        fleet.installed_inventory('a')
        job = scans(fleet, active=True)[0]
        fleet.store.update_operation(job['id'], 'failed', error_message='Synthetic scanner failure')
        baseline = len(scans(fleet))
    with value.connected() as fleet:
        fleet.runtime.recover_pending_scans()
        send(fleet, 'a', body)
        assert len(scans(fleet)) == baseline
        assert not scans(fleet, active=True)
        assert rows(fleet)['items'][0]['state'] == 'pending_reassessment'


def test_committed_report_recovers_when_process_stops_before_enqueue(fleet, monkeypatch):
    fleet.enroll('a'); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    fleet.installed_inventory('a'); fleet.scan('a', []); finish_jobs(fleet)
    original = fleet.runtime.reconcile_maintenance
    def stopped(*args, **kwargs):
        raise RuntimeError('Synthetic process interruption after report commit')
    monkeypatch.setattr(fleet.runtime, 'reconcile_maintenance', stopped)
    response = fleet.client.post('/api/v1/agents/remediation', json=body, headers=fleet.devices['a']['headers'])
    assert response.status_code == 500
    assert fleet.store.list('local_remediation')[0]['execution_observed_at']
    assert not scans(fleet, active=True)
    monkeypatch.setattr(fleet.runtime, 'reconcile_maintenance', original)
    fleet.runtime.recover_pending_scans()
    assert len(scans(fleet, active=True)) == 1
    send(fleet, 'a', body)
    assert len(scans(fleet, active=True)) == 1


def test_evidence_change_still_requests_ordinary_security_scan(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    send(fleet, 'a', report_body(fleet, 'a', 'pending_reassessment', 2))
    envelope = {**fleet.devices['a']['envelope'], 'kind': 'heartbeat', 'components': [],
                'facts': [{'collector': 'network', 'scope': 'host', 'status': 'complete',
                           'collected_at': now(), 'value': {'listener': 'new-exposure'}}]}
    response = fleet.client.post('/api/v1/agents/sync', json=envelope, headers=fleet.devices['a']['headers'])
    assert response.status_code == 200, response.text
    assert len(scans(fleet, active=True)) == 1
    assert not fleet.store.list('maintenance_scan_dispatch')


def test_unchanged_delta_is_not_post_install_proof(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    send(fleet, 'a', report_body(fleet, 'a', 'pending_reassessment', 2))
    envelope = {**fleet.devices['a']['envelope'], 'kind': 'delta', 'sequence': 2, 'components': []}
    response = fleet.client.post('/api/v1/agents/sync', json=envelope, headers=fleet.devices['a']['headers'])
    assert response.status_code == 200, response.text
    assert len(scans(fleet, active=True)) == 1  # Ordinary inventory processing is preserved.
    assert not fleet.store.list('maintenance_scan_dispatch')
    assert rows(fleet)['items'][0]['central_resolution']['reason_code'] == 'awaiting_inventory'


def test_old_superseded_worker_does_not_scan_again_after_current_success(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    fleet.installed_inventory('a'); fleet.scan('a', []); finish_jobs(fleet)
    baseline = len(scans(fleet))
    assert fleet.runtime.recover_superseded_scan('a') is None
    assert len(scans(fleet)) == baseline


def test_coalesced_dispatch_marker_cannot_suppress_returned_context(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    send(fleet, 'a', report_body(fleet, 'a', 'pending_reassessment', 2))
    fleet.installed_inventory('a')
    original = scans(fleet, active=True)[0]
    initial_dispatch = fleet.store.list('maintenance_scan_dispatch')[0]['scan_context']
    fleet.store.update_device('a', {'facts': [{'collector': 'network', 'value': 'context-b'}]})
    changed = fleet.runtime.schedule_scan('a')
    assert changed['id'] == original['id']
    fleet.scan('a', []); finish_jobs(fleet)
    fleet.store.update_device('a', {'facts': []})
    fleet.runtime.reconcile_maintenance('a')
    current = scans(fleet, active=True)
    assert len(current) == 1 and current[0]['id'] != original['id']
    dispatch = next(row for row in fleet.store.list('maintenance_scan_dispatch')
                    if row['scan_context'] == initial_dispatch)
    assert dispatch['operation_id'] == current[0]['id']


def test_one_pending_plan_does_not_block_another_ready_plan(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    body['reports'].append({**body['reports'][0], 'local_plan_id': 'later-target', 'target_version': '2.0'})
    send(fleet, 'a', body)
    assert not scans(fleet, active=True)
    fleet.installed_inventory('a')
    assert len(scans(fleet, active=True)) == 1
    requests = fleet.store.list('maintenance_scan_dispatch')
    assert len(requests) == 1
    ready = next(plan for plan in fleet.store.list('local_remediation') if plan['target_version'] == '1.1')
    assert requests[0]['plan_id'] == ready['id']


def test_resolved_db_binds_running_work_and_retires_only_current_duplicate(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    send(fleet, 'a', report_body(fleet, 'a', 'pending_reassessment', 2))
    fleet.installed_inventory('a')
    operation = fleet.store.claim()
    captured = fleet.store.device('a')
    assert operation['arguments']['required_db_revision'] is None
    fleet.runtime.scanner_info = {'status': 'ready', 'db_revision': 'discovered-db'}
    fleet.runtime.reconcile_maintenance('a')
    duplicate = next(job for job in scans(fleet, active=True) if job['status'] == 'queued')
    fleet.runtime.bind_running_scan_context(operation, captured, fleet.runtime.configuration(),
                                           'discovered-db', fleet.runtime.advisory_generation)
    assert [job['id'] for job in scans(fleet, active=True)] == [operation['id']]
    retired = fleet.store.operation(duplicate['id'])
    assert retired['result']['replacement_operation_id'] == operation['id']
    current_marker = next(row for row in fleet.store.list('maintenance_scan_dispatch')
                          if row.get('coalesced_operation_id') == duplicate['id'])
    assert current_marker['operation_id'] == operation['id']
    assert fleet.runtime.schedule_scan('a')['id'] == operation['id']
    assert fleet.store.device('a')['scan_status'] == 'running'


def test_binding_captured_inventory_never_retires_newer_inventory_successor(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    fleet.runtime.schedule_scan('a')
    operation = fleet.store.claim()
    captured = fleet.store.device('a')
    fleet.installed_inventory('a')
    newer = next(job for job in scans(fleet, active=True) if job['status'] == 'queued')
    fleet.runtime.bind_running_scan_context(operation, captured, fleet.runtime.configuration(),
                                           'discovered-db', fleet.runtime.advisory_generation)
    assert fleet.store.operation(newer['id'])['status'] == 'queued'
    assert fleet.store.operation(operation['id'])['arguments']['inventory_digest'] == captured['inventory_digest']
    assert newer['arguments']['inventory_digest'] != captured['inventory_digest']
    assert len(scans(fleet, active=True)) == 2


def test_resolved_db_failure_does_not_retry_same_demand_without_queued_duplicate(fleet):
    fleet.enroll('a'); finish_jobs(fleet)
    body = report_body(fleet, 'a', 'pending_reassessment', 2)
    send(fleet, 'a', body)
    fleet.installed_inventory('a')
    operation = fleet.store.claim()
    captured = fleet.store.device('a')
    assert operation['arguments']['required_db_revision'] is None
    fleet.runtime.scanner_info = {'status': 'ready', 'db_revision': 'discovered-db'}
    assert len(scans(fleet, active=True)) == 1
    fleet.runtime.bind_running_scan_context(operation, captured, fleet.runtime.configuration(),
                                           'discovered-db', fleet.runtime.advisory_generation)
    fleet.store.update_operation(operation['id'], 'failed', error_message='Synthetic actual-DB attempt failure')
    total = len(scans(fleet))
    fleet.runtime.reconcile_maintenance('a')
    send(fleet, 'a', body)
    assert not scans(fleet, active=True)
    assert len(scans(fleet)) == total
    assert {row['operation_id'] for row in fleet.store.list('maintenance_scan_dispatch')} == {operation['id']}
