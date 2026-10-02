"""Durable maintenance completion needs a fresh, scoped central reassessment.

All inventory, CVEs and collector receipts in this file are protocol fixtures.
No package manager, external scanner or switch is contacted.
"""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.db.store import Store, inventory_hash, now
from app.config import Settings
from app.runtime import Runtime


DEVICE = 'maintenance-reassessment-fixture'
PACKAGE = 'smart-patch-testprobe'
CVE = 'CVE-2026-90001'


@pytest.fixture
def store(tmp_path):
    value = Store('sqlite:///' + str(tmp_path / 'maintenance.sqlite'))
    yield value
    value.close()


def component(version='1.0', scope='host', architecture='amd64'):
    return {'component_id': f'{scope}:{PACKAGE}:{architecture}', 'scope': scope,
            'name': PACKAGE, 'version': version, 'architecture': architecture,
            'source_name': PACKAGE, 'source_version': version,
            'distro': {'id': 'debian', 'version_id': '12', 'codename': 'bookworm'}}


def checkpoint(store, components, *, facts=None, collected_at=None):
    previous = store.device(DEVICE)
    envelope = {'schema_version': 1, 'device_id': DEVICE, 'hostname': 'fixture-switch',
                'build_id': 'fixture-build', 'epoch': 'fixture-epoch',
                'sequence': (previous or {}).get('last_sequence', 0) + 1,
                'kind': 'checkpoint', 'collected_at': collected_at or now(),
                'components': components, 'inventory_digest': inventory_hash(components),
                'facts': [] if facts is None else facts}
    result, changed = store.sync(envelope, {'role': 'admin'})
    assert result['resync_required'] is False and changed
    return envelope


def finding(item=None, *, cve=CVE, applicability='affected'):
    item = item or component()
    return {'component_id': item['component_id'], 'scope_id': item['scope'],
            'package_name': item['name'], 'affected_version': item['version'],
            'cve_id': cve, 'severity': 'HIGH', 'applicability': applicability,
            'fixed_versions': ['1.1'], 'component': item,
            'rationale': 'Synthetic maintenance completion fixture'}


def scan(store, findings=(), *, complete=True, revision='after-install', **kwargs):
    device = store.device(DEVICE)
    report = {'findings': list(findings), 'evidence': [], 'errors': [],
              'coverage': {'complete': complete},
              'scanner': {'status': 'complete' if complete else 'partial',
                          'db_revision': 'fixture-db'}}
    assert store.store_findings(DEVICE, device['inventory_digest'], report, revision, **kwargs)


def prepare(store):
    checkpoint(store, [component(), component(scope='container:pmon')])
    scan(store, [finding()], revision='before-install')
    selected = store.list('finding', owner=DEVICE)[0]
    device = store.device(DEVICE)
    plan = {'id': 'fixture-plan', 'device_id': DEVICE, 'scope': 'host',
            'package_name': PACKAGE, 'from_version': '1.0', 'target_version': '1.1',
            'inventory_digest': device['inventory_digest'], 'inventory_epoch': device['epoch'],
            'build_id': device['build_id'], 'finding_ids': [selected['id']],
            'finding_id': selected['id'], 'finding': selected,
            'status': 'queued', 'approved': True, 'execution_eligible': False,
            'created_at': now(), 'action_request_id': 'fixture-execute'}
    store.put('plan', plan['id'], plan, DEVICE)
    store.put('action_request', plan['action_request_id'],
              {'request_id': plan['action_request_id'], 'device_id': DEVICE,
               'action': 'execute_plan', 'plan': copy.deepcopy(plan),
               'status': 'queued', 'created_at': now()}, DEVICE)
    return plan


def receipt(store):
    plan = store.get('plan', 'fixture-plan')
    request = store.get('action_request', plan['action_request_id'])
    fact = {'fact_id': request['request_id'], 'collector': 'remediation',
            'status': 'complete', 'collected_at': now(),
            'value': {'status': 'pending_reassessment',
                      'details': {'maintenance_checks_enabled': False,
                                  'rollback_available': False,
                                  'fixture': 'Protocol fixture, no installation'}}}
    store.put('action_request', request['request_id'],
              {**request, 'status': 'complete', 'result': fact,
               'result_consumed': True, 'result_received_at': now()}, DEVICE)
    store.put('plan', plan['id'], {**plan, 'status': 'pending_reassessment',
                                 'execution_result': fact, 'updated_at': now()}, DEVICE)
    return fact


def install_inventory(store, **kwargs):
    return checkpoint(store, [component('1.1'), component(scope='container:pmon')], **kwargs)


def test_receipt_before_scan_completes_only_after_accepted_current_scan(store):
    prepare(store)
    original_receipt = receipt(store)
    install_inventory(store)
    store.reconcile_maintenance_plans(DEVICE)
    assert store.get('plan', 'fixture-plan')['status'] == 'pending_reassessment'
    scan(store)
    completed = store.get('plan', 'fixture-plan')
    assert completed['status'] == 'completed'
    assert completed['execution_result'] == original_receipt
    assert completed['execution_eligible'] is False
    assert completed['reassessment']['status'] == 'completed'
    assert completed['reassessment']['selected_cves'] == [CVE]
    assert completed['reassessment']['remaining_cves'] == []
    assert completed['reassessment']['scanner_db_revision'] == 'fixture-db'


def test_scan_before_receipt_is_reconciled_after_receipt_arrives(store):
    prepare(store)
    install_inventory(store)
    scan(store)
    assert store.get('plan', 'fixture-plan')['status'] == 'queued'
    original_receipt = receipt(store)
    store.reconcile_maintenance_plans(DEVICE)
    completed = store.get('plan', 'fixture-plan')
    assert completed['status'] == 'completed'
    assert completed['execution_result'] == original_receipt


def test_same_cve_in_another_container_does_not_block_host_completion(store):
    prepare(store)
    receipt(store)
    install_inventory(store)
    scan(store, [finding(component(scope='container:pmon'))])
    assert store.get('plan', 'fixture-plan')['status'] == 'completed'
    remaining = [f for f in store.list('finding', owner=DEVICE) if f['status'] == 'current']
    assert len(remaining) == 1 and remaining[0]['scope'] == 'container:pmon'


@pytest.mark.parametrize('wrong_target', [
    [component(), component('1.1', scope='container:pmon')],
    [component('1.1', architecture='arm64'), component(scope='container:pmon')],
    [component('1.2'), component(scope='container:pmon')],
    [component('1.1', scope='container:pmon')],
])
def test_target_must_match_exact_scope_version_and_architecture(store, wrong_target):
    prepare(store)
    receipt(store)
    checkpoint(store, wrong_target)
    scan(store)
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending.get('reassessment')


@pytest.mark.parametrize('applicability', ['affected', 'under_investigation', 'fixed'])
def test_selected_cve_remaining_on_target_keeps_plan_pending(store, applicability):
    prepare(store)
    receipt(store)
    install_inventory(store)
    scan(store, [finding(component('1.1'), applicability=applicability)])
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'remaining_findings'
    assert pending['reassessment']['remaining_cves'] == [CVE]


def test_partial_scan_cannot_resolve_missing_selected_cve(store):
    prepare(store)
    receipt(store)
    install_inventory(store)
    scan(store, complete=False)
    store.reconcile_maintenance_plans(DEVICE)
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'incomplete_scan'


def test_targeted_ai_reassessment_does_not_replace_authoritative_scan(store):
    prepare(store)
    receipt(store)
    install_inventory(store)
    scan(store, [finding(component('1.1'), applicability='fixed')],
         complete_scan=False, assessment_kind='ai_backlog')
    store.reconcile_maintenance_plans(DEVICE)
    assert store.get('plan', 'fixture-plan')['status'] == 'pending_reassessment'


def test_partial_component_update_does_not_become_full_scan_proof(store):
    prepare(store)
    receipt(store)
    install_inventory(store)
    scan(store, [], complete_scan=False, assessment_kind='scan')
    store.reconcile_maintenance_plans(DEVICE)
    assert store.get('plan', 'fixture-plan')['status'] == 'pending_reassessment'


@pytest.mark.parametrize('scanner', [
    {'status': 'failed', 'db_revision': 'fixture-db'},
    {'status': 'complete', 'db_revision': ''},
])
def test_coverage_flag_without_valid_scanner_result_cannot_complete(store, scanner):
    prepare(store)
    receipt(store)
    install_inventory(store)
    report = {'findings': [], 'evidence': [], 'coverage': {'complete': True}, 'scanner': scanner}
    assert store.store_findings(DEVICE, store.device(DEVICE)['inventory_digest'], report, 'invalid-scan')
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'incomplete_scan'


def test_rejected_scan_of_old_inventory_never_completes_plan(store):
    original = prepare(store)
    receipt(store)
    install_inventory(store)
    proof = copy.deepcopy(store.get('maintenance_scan', DEVICE))
    report = {'findings': [], 'evidence': [], 'coverage': {'complete': True},
              'scanner': {'status': 'complete', 'db_revision': 'fixture-db'}}
    assert not store.store_findings(DEVICE, original['inventory_digest'], report, 'obsolete-scan')
    assert store.get('maintenance_scan', DEVICE) == proof
    assert store.get('plan', 'fixture-plan')['status'] == 'pending_reassessment'


def test_completed_transition_is_idempotent_and_retains_collector_receipt(store):
    prepare(store)
    original_receipt = receipt(store)
    install_inventory(store)
    scan(store)
    completed = store.get('plan', 'fixture-plan')
    assert completed['status'] == 'completed'
    request = store.get('action_request', 'fixture-execute')
    for _ in range(3):
        store.reconcile_maintenance_plans(DEVICE)
    assert store.get('plan', 'fixture-plan') == completed
    assert store.get('action_request', 'fixture-execute') == request
    assert completed['execution_result'] == original_receipt


@pytest.mark.parametrize('change', [
    {'manifest': {'build': 'changed'}},
    {'binding_revision': 'new-binding'},
    {'assessment_policy_revision': 'new-policy'},
    {'facts': [{'collector': 'listeners', 'scope': 'host', 'status': 'observed',
                'value': [{'port': 443, 'address': '0.0.0.0'}]}]},
    {'facts': [{'collector': 'inventory', 'status': 'partial', 'value': {'errors': ['unreadable']}}]},
])
def test_changed_assessment_context_requires_fresh_scan(store, change):
    prepare(store)
    install_inventory(store)
    scan(store)
    store.update_device(DEVICE, change)
    receipt(store)
    result = store.reconcile_maintenance_plans(DEVICE)
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'stale_scan'
    assert result['waiting'] == ['fixture-plan']
    assert result['completed'] == []


def test_ai_only_revision_change_preserves_complete_scan_identity(store):
    prepare(store)
    install_inventory(store)
    scan(store)
    scan(store, [], revision='later-ai-only-revision', complete_scan=False,
         assessment_kind='ai_backlog')
    receipt(store)
    store.reconcile_maintenance_plans(DEVICE)
    assert store.get('plan', 'fixture-plan')['status'] == 'completed'


def test_recovery_needs_new_scan_when_legacy_completed_scan_has_no_identity_snapshot(store):
    prepare(store)
    receipt(store)
    install_inventory(store)
    # A historical device summary is not authoritative scan proof. Do not infer
    # absence of the selected CVE from pre-upgrade no_longer_reported records.
    store.update_device(DEVICE, {'scan_status': 'completed', 'coverage': {'complete': True},
                                'last_scan_at': now(), 'scanner': {'status': 'complete',
                                                               'db_revision': 'fixture-db'}})
    store.put('maintenance_scan', DEVICE, {}, DEVICE)
    finding_row = store.get('plan', 'fixture-plan')['finding']
    store.put('finding', finding_row['id'], {**finding_row, 'status': 'no_longer_reported'}, DEVICE)
    result = store.reconcile_maintenance_plans()
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'awaiting_scan'
    assert DEVICE in result['needs_scan']
    scan(store)
    assert store.get('plan', 'fixture-plan')['status'] == 'completed'


def test_reopen_recovers_scan_before_receipt_without_scanning_again(store):
    prepare(store)
    install_inventory(store)
    scan(store)
    receipt(store)
    reopened = Store(str(store.engine.url))
    try:
        outcome = reopened.reconcile_maintenance_plans()
        assert outcome['completed'] == ['fixture-plan']
        assert reopened.get('plan', 'fixture-plan')['status'] == 'completed'
    finally:
        reopened.close()


def test_runtime_recovery_queues_legacy_reassessment_once_without_worker_or_network(store, tmp_path):
    prepare(store)
    receipt(store)
    install_inventory(store)
    store.update_device(DEVICE, {'scan_status': 'completed', 'coverage': {'complete': True},
                                'last_scan_at': now()})
    store.put('maintenance_scan', DEVICE, {}, DEVICE)
    config = Settings(_env_file=None, database_url=str(store.engine.url),
                      state_dir=tmp_path / 'isolated-runtime-state', source_roots=[],
                      jobs_enabled=False, ai_enabled=False, scanner_binary='/not-installed/grype')
    service = Runtime(config, pipeline_factory=lambda *_: SimpleNamespace())
    try:
        first = service.reconcile_maintenance()
        assert first['needs_scan'] == [DEVICE]
        jobs = service.store.operations()
        assert len(jobs) == 1
        assert jobs[0]['operation_type'] == 'scan'
        assert jobs[0]['arguments']['device_id'] == DEVICE
        assert service.store.device(DEVICE)['scan_status'] == 'queued'
        service.store.update_operation(jobs[0]['id'], 'failed', error_message='Synthetic scanner failure')
        service.reconcile_maintenance()
        assert len(service.store.operations()) == 1
        assert service.store.get('plan', 'fixture-plan')['status'] == 'pending_reassessment'
    finally:
        service.stop()


def test_inventory_before_execute_request_cannot_establish_installation(store):
    prepare(store)
    install_inventory(store)
    request = store.get('action_request', 'fixture-execute')
    later = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    store.put('action_request', request['request_id'], {**request, 'created_at': later}, DEVICE)
    receipt(store)
    scan(store)
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'awaiting_inventory'


@pytest.mark.parametrize('mutation', ['unconsumed', 'failed', 'wrong_device', 'wrong_target'])
def test_successful_bound_execution_receipt_is_required(store, mutation):
    prepare(store)
    receipt(store)
    request = store.get('action_request', 'fixture-execute')
    if mutation == 'unconsumed':
        request['result_consumed'] = False
    elif mutation == 'failed':
        request['result']['value']['status'] = 'failed'
    elif mutation == 'wrong_device':
        request['device_id'] = 'another-switch'
    else:
        request['plan']['target_version'] = '9.9'
    store.put('action_request', request['request_id'], request, DEVICE)
    install_inventory(store)
    scan(store)
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] in {'missing_execution_receipt', 'identity_mismatch'}


@pytest.mark.parametrize(('field', 'replacement'), [
    ('build_id', 'another-build'),
    ('finding_ids', ['another-finding']),
    ('finding_id', 'another-finding'),
])
def test_execution_request_snapshot_must_match_original_build_and_selection(store, field, replacement):
    prepare(store)
    original_receipt = receipt(store)
    request = store.get('action_request', 'fixture-execute')
    request['plan'][field] = replacement
    store.put('action_request', request['request_id'], request, DEVICE)
    install_inventory(store)
    scan(store)
    pending = store.get('plan', 'fixture-plan')
    assert pending['execution_result'] == original_receipt
    assert request['result'] == original_receipt
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'missing_execution_receipt'


@pytest.mark.parametrize('timestamp', ['before_request', None, '2026-09-30T12:00:00'])
def test_scan_completion_must_follow_execution_request_even_when_identity_is_current(store, timestamp):
    prepare(store)
    install_inventory(store)
    scan(store)
    proof = store.get('maintenance_scan', DEVICE)
    original_identity = copy.deepcopy(proof['identity'])
    if timestamp == 'before_request':
        requested = datetime.fromisoformat(store.get('action_request', 'fixture-execute')['created_at'].replace('Z', '+00:00'))
        timestamp = (requested - timedelta(seconds=1)).isoformat()
    store.put('maintenance_scan', DEVICE, {**proof, 'scan_completed_at': timestamp}, DEVICE)
    receipt(store)
    outcome = store.reconcile_maintenance_plans(DEVICE)
    pending = store.get('plan', 'fixture-plan')
    assert store.get('maintenance_scan', DEVICE)['identity'] == original_identity
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'stale_scan'
    assert outcome['completed'] == []


def select_second_finding(store, item=None):
    second_cve = 'CVE-2026-90002'
    scan(store, [finding(), finding(item, cve=second_cve)], revision='before-install-two-cves')
    second = next(row for row in store.list('finding', owner=DEVICE) if row['cve_id'] == second_cve)
    plan = store.get('plan', 'fixture-plan')
    plan['finding_ids'] = [*plan['finding_ids'], second['id']]
    store.put('plan', plan['id'], plan, DEVICE)
    request = store.get('action_request', plan['action_request_id'])
    store.put('action_request', request['request_id'], {**request, 'plan': copy.deepcopy(plan)}, DEVICE)
    return second_cve


@pytest.mark.parametrize('remaining_cve', [None, CVE, 'CVE-2026-90002'])
def test_all_selected_cves_must_be_absent_for_same_package_occurrence(store, remaining_cve):
    prepare(store)
    second_cve = select_second_finding(store)
    receipt(store)
    install_inventory(store)
    findings = [finding(component('1.1'), cve=remaining_cve)] if remaining_cve else []
    scan(store, findings)
    result = store.get('plan', 'fixture-plan')
    assert result['reassessment']['selected_cves'] == sorted([CVE, second_cve])
    if remaining_cve:
        assert result['status'] == 'pending_reassessment'
        assert result['reassessment']['reason_code'] == 'remaining_findings'
        assert result['reassessment']['remaining_cves'] == [remaining_cve]
    else:
        assert result['status'] == 'completed'
        assert result['reassessment']['remaining_cves'] == []


def test_selected_findings_from_mixed_occurrences_cannot_complete_even_with_clean_scan(store):
    prepare(store)
    select_second_finding(store, component(scope='container:pmon'))
    receipt(store)
    install_inventory(store)
    scan(store)
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'selection_unknown'


def test_scanner_alias_for_selected_cve_keeps_plan_pending(store):
    prepare(store)
    receipt(store)
    install_inventory(store)
    aliased = {**finding(component('1.1'), cve='GHSA-synthetic-fixture'),
               'related_vulnerabilities': [{'id': CVE}]}
    scan(store, [aliased])
    pending = store.get('plan', 'fixture-plan')
    assert pending['status'] == 'pending_reassessment'
    assert pending['reassessment']['reason_code'] == 'remaining_findings'
    assert pending['reassessment']['remaining_cves'] == [CVE]
