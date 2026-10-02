"""Fleet-remediation acceptance contracts using only synthetic switch messages.

No real collector, package manager, external scanner, or switch is contacted.
The fake scanner results model committed complete inventory scans, not hardware
qualification or evidence that the fixture package is actually vulnerable.
"""
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db.store import Record, inventory_hash, now
from app.main import create_app
from app.services.retention import archive_expired


CVE = 'SYNTHETIC-FLEET-NOT-A-CVE'
PACKAGE = 'smart-patch-fleet-testprobe'
BASE = '/api/v1/remediation-batches'


class PrivateHeaders(dict):
    def __repr__(self):
        return "{'Authorization': '<temporary fixture credential>'}"


class Fleet:
    def __init__(self, config):
        self.config = config
        self.devices = {}

    @contextmanager
    def connected(self):
        app = create_app(self.config)
        with TestClient(app) as client:
            client.headers['Authorization'] = 'Bearer ' + (
                self.config.state_dir / 'bootstrap-token').read_text().strip()
            self.client = client
            self.runtime = app.state.runtime
            self.store = self.runtime.store
            yield self

    def token(self, role, device_id=None):
        response = self.client.post('/api/v1/tokens', json={
            'description': 'Temporary synthetic fleet fixture',
            'role': role, 'device_id': device_id})
        assert response.status_code == 201, response.text
        return PrivateHeaders(Authorization='Bearer ' + response.json()['token'])

    def enroll(self, ident, version='1.0', target='1.1', scope='host',
               applicability='affected', fixed=True, package=PACKAGE):
        component = {'component_id': f'{scope}:{package}:amd64', 'scope': scope,
                     'name': package, 'version': version, 'architecture': 'amd64',
                     'distro': {'name': 'debian', 'version': '12'}}
        envelope = {'schema_version': 1, 'device_id': ident, 'hostname': ident,
                    'build_id': 'fixture-build-' + ident, 'epoch': 'fixture-epoch-' + ident,
                    'sequence': 1, 'kind': 'checkpoint', 'collected_at': now(),
                    'components': [component], 'inventory_digest': inventory_hash([component])}
        headers = self.token('agent', ident)
        response = self.client.post('/api/v1/agents/sync', json=envelope, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()['resync_required'] is False
        finding = {'component_id': component['component_id'], 'scope_id': scope,
                   'package_name': package, 'affected_version': version,
                   'cve_id': CVE, 'severity': 'HIGH', 'applicability': applicability,
                   'fixed_versions': [target] if fixed else [],
                   'candidate_fixed_versions': [target] if fixed else [],
                   'component': component, 'rationale': 'Synthetic fleet acceptance fixture'}
        self.devices[ident] = {'envelope': envelope, 'headers': headers, 'component': component,
                               'target': target, 'finding_source': finding}
        self.scan(ident, [finding])
        self.devices[ident]['finding'] = self.store.list('finding', owner=ident)[0]
        return self.devices[ident]

    def scan(self, ident, findings=(), complete=True):
        device = self.store.device(ident)
        result = {'findings': list(findings), 'evidence': [], 'errors': [],
                  'coverage': {'complete': complete},
                  'scanner': {'status': 'complete' if complete else 'partial',
                              'db_revision': 'fixture-advisory-db'}}
        assert self.store.store_findings(ident, device['inventory_digest'], result,
                                         'fixture-scan-' + now())

    def heartbeat(self, ident, request_id=None, status=None, fact_status=None, details=None):
        device = self.devices[ident]
        facts = []
        if request_id:
            if fact_status is None:
                fact_status = ('complete' if status in ('staged', 'pending_reassessment', 'rolled_back')
                               else 'denied' if status == 'denied' else 'failed')
            facts = [{'fact_id': request_id, 'collector': 'remediation', 'status': fact_status,
                      'collected_at': now(), 'value': {'status': status,
                          'details': details if details is not None else {
                              'fixture': 'Protocol only; no package operation',
                              'maintenance_checks_enabled': False}}}]
        envelope = {**device['envelope'], 'kind': 'heartbeat', 'components': [],
                    'collected_at': now(), 'facts': facts}
        response = self.client.post('/api/v1/agents/sync', json=envelope, headers=device['headers'])
        assert response.status_code == 200, response.text
        assert response.json()['resync_required'] is False
        return response.json()

    def installed_inventory(self, ident):
        device = self.devices[ident]
        item = {**device['component'], 'version': device['target']}
        envelope = {**device['envelope'], 'kind': 'checkpoint',
                    'sequence': device['envelope']['sequence'] + 1, 'collected_at': now(),
                    'components': [item], 'facts': [], 'inventory_digest': inventory_hash([item])}
        response = self.client.post('/api/v1/agents/sync', json=envelope, headers=device['headers'])
        assert response.status_code == 200, response.text
        assert response.json()['resync_required'] is False
        device['envelope'] = envelope
        device['component'] = item

    def create_batch(self, idents, limit=1):
        response = self.client.post(BASE, json={
            'name': 'Synthetic fleet acceptance',
            'finding_ids': [self.devices[ident]['finding']['id'] for ident in idents],
            'max_concurrent_switches': limit, 'pause_on_failure': True})
        assert response.status_code == 201, response.text
        return response.json()

    def batch(self, ident):
        self.runtime.reconcile_remediation_batches()
        response = self.client.get(BASE + '/' + ident)
        assert response.status_code == 200, response.text
        return response.json()

    def control(self, batch, action, **body):
        current = self.batch(batch['id'])
        response = self.client.post(BASE + '/' + batch['id'] + '/' + action,
                                    json={'expected_revision': current['revision'], **body})
        assert 200 <= response.status_code < 300, response.text
        return response.json()

    def stage(self, batch):
        plans = [entry['plan_id'] for entry in batch['entries'] if entry['eligibility'] == 'eligible']
        return self.control(batch, 'approve-and-stage', confirmed_plan_ids=plans)

    def execute(self, batch):
        entries = [entry for entry in self.batch(batch['id'])['entries']
                   if entry.get('plan_id') and self.store.get('plan', entry['plan_id'])['status'] == 'staged']
        return self.control(batch, 'execute', confirmed_plan_ids=[entry['plan_id'] for entry in entries],
                            confirmed_device_ids=sorted({entry['device_id'] for entry in entries}))

    def requests(self, action, ident=None):
        return [row for row in self.store.list('action_request')
                if row['action'] == action and (ident is None or row['device_id'] == ident)]

    def acknowledge_stages(self, batch):
        consumed = set()
        for _ in range(len(batch['entries']) + 1):
            self.batch(batch['id'])
            pending = [row for row in self.requests('stage_plan') if row['request_id'] not in consumed]
            if not pending:
                break
            for row in pending:
                consumed.add(row['request_id'])
                self.heartbeat(row['device_id'], row['request_id'], 'staged')
        return self.batch(batch['id'])


@pytest.fixture
def fleet(tmp_path):
    config = Settings(_env_file=None, state_dir=tmp_path / 'state',
                      database_url='sqlite:///' + str(tmp_path / 'fleet.sqlite'),
                      jobs_enabled=False, scanner_binary='/not-installed/grype',
                      source_roots=[], ai_enabled=False)
    value = Fleet(config)
    with value.connected():
        yield value


def test_two_switches_require_explicit_execute_and_independent_complete_scans(fleet, tmp_path):
    fleet.enroll('fixture-a', version='1.0', target='1.1')
    fleet.enroll('fixture-b', version='2.0', target='2.1')
    batch = fleet.create_batch(['fixture-a', 'fixture-b'])
    assert not fleet.store.list('action_request')
    assert {entry['device_id']: entry['target_version'] for entry in batch['entries']} == {
        'fixture-a': '1.1', 'fixture-b': '2.1'}
    fleet.stage(batch)
    assert len(fleet.requests('stage_plan')) == 1
    staged = fleet.acknowledge_stages(batch)
    assert len(fleet.requests('stage_plan')) == 2
    assert not fleet.requests('execute_plan')
    assert all(fleet.store.get('plan', entry['plan_id'])['status'] == 'staged'
               for entry in staged['entries'])

    fleet.execute(batch)
    first, = fleet.requests('execute_plan')
    first_device = first['device_id']
    fleet.heartbeat(first_device, first['request_id'], 'pending_reassessment')
    fleet.installed_inventory(first_device)
    fleet.scan(first_device, complete=False)
    assert fleet.batch(batch['id'])['status'] != 'completed'
    assert len(fleet.requests('execute_plan')) == 1, 'Partial scans must not release execution capacity'
    assert fleet.store.get('plan', first['plan']['id'])['status'] == 'pending_reassessment'

    fleet.scan(first_device)
    fleet.batch(batch['id'])
    assert fleet.store.get('plan', first['plan']['id'])['status'] == 'completed'
    second, = [request for request in fleet.requests('execute_plan') if request['device_id'] != first_device]
    assert second['plan']['target_version'] == fleet.devices[second['device_id']]['target']
    # Cold completed members still belong to this active rollout. Retention must
    # preserve their per-switch execution proof and the linked staging receipt.
    old = '2000-01-01T00:00:00Z'
    first_plan = fleet.store.get('plan', first['plan']['id'])
    identities = [('plan', first_plan['id']), ('action_request', first['request_id']),
                  ('action_request', first_plan['stage_request_id'])]
    with fleet.store.sessions.begin() as session:
        for identity in identities:
            row = session.get(Record, identity)
            row.created_at = row.updated_at = old
    archive_expired(fleet.store, tmp_path / 'retention')
    assert all(fleet.store.get(kind, ident) is not None for kind, ident in identities)
    fleet.heartbeat(second['device_id'], second['request_id'], 'pending_reassessment')
    fleet.installed_inventory(second['device_id'])
    fleet.scan(second['device_id'])
    completed = fleet.batch(batch['id'])
    assert completed['status'] == 'completed'
    assert all(fleet.store.get('plan', entry['plan_id'])['reassessment']['remaining_cves'] == []
               for entry in completed['entries'])
    fleet.heartbeat(first_device, first['request_id'], 'pending_reassessment')
    assert fleet.batch(batch['id'])['status'] == 'completed'
    assert len(fleet.requests('execute_plan')) == 2


def test_mixed_selection_keeps_manual_review_and_no_fix_rows_out_of_dispatch(fleet):
    fleet.enroll('eligible-host')
    fleet.enroll('manual-container', scope='container:pmon')
    fleet.enroll('missing-fix', fixed=False)
    fleet.enroll('needs-review', applicability='under_investigation')
    batch = fleet.create_batch(list(fleet.devices))
    entries = {entry['device_id']: entry for entry in batch['entries']}
    assert entries['eligible-host']['eligibility'] == 'eligible'
    assert entries['manual-container']['eligibility'] == 'manual'
    assert entries['missing-fix']['eligibility'] == 'no_fix'
    assert entries['needs-review']['eligibility'] == 'review_required'
    fleet.stage(batch)
    assert {row['device_id'] for row in fleet.requests('stage_plan')} == {'eligible-host'}
    assert not fleet.requests('execute_plan')


def test_operator_can_prepare_but_cannot_approve_execute_or_control_dispatch(fleet):
    fleet.enroll('permission-test')
    operator_headers = fleet.token('operator')
    response = fleet.client.post(BASE, json={
        'finding_ids': [fleet.devices['permission-test']['finding']['id']]}, headers=operator_headers)
    assert response.status_code == 201, response.text
    batch = response.json()
    entry, = batch['entries']
    for action, extra in (
        ('approve-and-stage', {'confirmed_plan_ids': [entry['plan_id']]}),
        ('execute', {'confirmed_plan_ids': [entry['plan_id']], 'confirmed_device_ids': ['permission-test']}),
        ('pause', {}), ('resume', {}), ('stop', {}),
    ):
        response = fleet.client.post(BASE + '/' + batch['id'] + '/' + action,
                                     json={'expected_revision': batch['revision'], **extra}, headers=operator_headers)
        assert response.status_code == 403, (action, response.text)
    assert not fleet.store.list('action_request')


def test_pause_preserves_already_dispatched_work_and_resume_stages_remaining_switch(fleet):
    fleet.enroll('pause-a')
    fleet.enroll('pause-b')
    batch = fleet.create_batch(['pause-a', 'pause-b'])
    fleet.stage(batch)
    first, = fleet.requests('stage_plan')
    fleet.control(batch, 'pause')
    delivered = fleet.heartbeat(first['device_id'])['action_requests']
    assert [row['request_id'] for row in delivered] == [first['request_id']]
    fleet.heartbeat(first['device_id'], first['request_id'], 'staged')
    assert fleet.batch(batch['id'])['status'] == 'paused'
    assert len(fleet.requests('stage_plan')) == 1
    fleet.control(batch, 'resume')
    assert len(fleet.requests('stage_plan')) == 2
    assert not fleet.requests('execute_plan')


@pytest.mark.parametrize('mutation', ['review', 'expiry'])
def test_revoked_or_expired_queued_context_is_never_delivered(fleet, mutation):
    fleet.enroll('stale-a')
    fleet.enroll('stale-b')
    batch = fleet.create_batch(['stale-a', 'stale-b'])
    fleet.stage(batch)
    first, = fleet.requests('stage_plan')
    if mutation == 'review':
        fleet.store.update_device(first['device_id'], {'review_revision': 'review-retracted'})
    else:
        plan = fleet.store.get('plan', first['plan']['id'])
        fleet.store.put('plan', plan['id'], {**plan, 'expires_at': '2000-01-01T00:00:00Z'}, plan['device_id'])
    delivered = fleet.heartbeat(first['device_id'])
    assert delivered['action_requests'] == []
    current = fleet.batch(batch['id'])
    assert current['status'] == 'paused'
    assert not fleet.requests('execute_plan')
    assert len(fleet.requests('stage_plan')) == 1


def test_batch_owned_plan_cannot_bypass_batch_confirmation_or_duplicate_dispatch(fleet):
    fleet.enroll('owned-plan')
    batch = fleet.create_batch(['owned-plan'])
    plan_id = batch['entries'][0]['plan_id']
    for action, body in [('approve', {}), ('stage', {}),
                         ('execute', {'confirmed_device_id': 'owned-plan'}),
                         ('validate-target', {'target_version': '1.1'})]:
        response = fleet.client.post('/api/v1/plans/' + plan_id + '/' + action, json=body)
        assert response.status_code == 409, (action, response.text)
    body = {'expected_revision': batch['revision'], 'confirmed_plan_ids': [plan_id]}
    response = fleet.client.post(BASE + '/' + batch['id'] + '/approve-and-stage', json=body)
    assert 200 <= response.status_code < 300, response.text
    duplicate = fleet.client.post(BASE + '/' + batch['id'] + '/approve-and-stage', json=body)
    assert 200 <= duplicate.status_code < 300, duplicate.text
    assert duplicate.json()['revision'] == response.json()['revision']
    stale_control = fleet.client.post(BASE + '/' + batch['id'] + '/pause',
                                      json={'expected_revision': batch['revision']})
    assert stale_control.status_code == 409, stale_control.text
    assert len(fleet.requests('stage_plan')) == 1
    fleet.acknowledge_stages(batch)
    current = fleet.batch(batch['id'])
    wrong = fleet.client.post(BASE + '/' + batch['id'] + '/execute', json={
        'expected_revision': current['revision'], 'confirmed_plan_ids': [plan_id],
        'confirmed_device_ids': ['another-switch']})
    assert wrong.status_code == 422, wrong.text
    assert not fleet.requests('execute_plan')


@pytest.mark.parametrize('reported_status', ['unknown', 'unexpected-new-collector-status'])
def test_unknown_outcome_retains_device_reservation_across_batch_and_single_plan(fleet, reported_status):
    device = fleet.enroll('unknown-outcome')
    standalone = fleet.client.post('/api/v1/plans', json={
        'device_id': 'unknown-outcome', 'finding_ids': [device['finding']['id']]})
    assert standalone.status_code == 201, standalone.text
    standalone_id = standalone.json()['id']
    approved = fleet.client.post('/api/v1/plans/' + standalone_id + '/approve', json={})
    assert approved.status_code == 200, approved.text
    first_batch = fleet.create_batch(['unknown-outcome'])
    second_batch = fleet.create_batch(['unknown-outcome'])
    fleet.stage(first_batch)
    first, = fleet.requests('stage_plan')
    fleet.heartbeat(first['device_id'], first['request_id'], reported_status)
    assert fleet.batch(first_batch['id'])['status'] == 'paused'
    fleet.stage(second_batch)
    fleet.batch(second_batch['id'])
    assert len(fleet.requests('stage_plan')) == 1, 'Unknown outcomes cannot free the switch for another batch'
    response = fleet.client.post('/api/v1/plans/' + standalone_id + '/stage', json={})
    assert response.status_code == 409, response.text
    assert len(fleet.requests('stage_plan')) == 1


@pytest.mark.parametrize('reported_status', ['failed', 'rollback_failed'])
def test_failure_pauses_next_install_and_resume_never_retries_the_failed_install(fleet, reported_status):
    fleet.enroll('failure-a')
    fleet.enroll('failure-b')
    batch = fleet.create_batch(['failure-a', 'failure-b'])
    fleet.stage(batch)
    fleet.acknowledge_stages(batch)
    fleet.execute(batch)
    first, = fleet.requests('execute_plan')
    fleet.heartbeat(first['device_id'], first['request_id'], reported_status)
    current = fleet.batch(batch['id'])
    assert current['status'] == 'paused'
    assert len(fleet.requests('execute_plan')) == 1
    fleet.control(batch, 'resume')
    executions = fleet.requests('execute_plan')
    assert len(executions) == 2
    assert len(fleet.requests('execute_plan', first['device_id'])) == 1
    assert fleet.store.get('plan', first['plan']['id'])['status'] == reported_status


@pytest.mark.parametrize(('status', 'fact_status', 'details'), [
    ('pending_reassessment', 'failed', {'error': 'Inconsistent synthetic outcome'}),
    ('denied', 'denied', 'Interrupted maintenance action requires operator recovery; it will not be replayed'),
    ('failed', 'observed', {'error': 'Nonterminal receipt cannot establish a final outcome'}),
    (['failed'], 'failed', {'error': 'Malformed status must remain an unknown outcome'}),
])
def test_ambiguous_execution_receipt_holds_capacity_and_keeps_original_evidence(fleet, status, fact_status, details):
    fleet.enroll('ambiguous-a')
    fleet.enroll('ambiguous-b')
    batch = fleet.create_batch(['ambiguous-a', 'ambiguous-b'])
    fleet.stage(batch)
    fleet.acknowledge_stages(batch)
    fleet.execute(batch)
    first, = fleet.requests('execute_plan')
    fleet.heartbeat(first['device_id'], first['request_id'], status, fact_status=fact_status, details=details)
    assert fleet.batch(batch['id'])['status'] == 'paused'
    assert fleet.store.get('plan', first['plan']['id'])['status'] == 'unknown'
    receipt = fleet.store.get('action_request', first['request_id'])['result']
    assert receipt['status'] == fact_status
    assert receipt['value'] == {'status': status, 'details': details}
    fleet.control(batch, 'resume')
    assert len(fleet.requests('execute_plan')) == 1, 'Ambiguous outcomes must retain the occupied rollout slot'


def test_stop_keeps_dispatched_receipt_but_never_launches_unstarted_children(fleet):
    fleet.enroll('stop-a')
    fleet.enroll('stop-b')
    batch = fleet.create_batch(['stop-a', 'stop-b'])
    fleet.stage(batch)
    first, = fleet.requests('stage_plan')
    fleet.control(batch, 'stop')
    fleet.heartbeat(first['device_id'], first['request_id'], 'staged')
    current = fleet.batch(batch['id'])
    assert current['status'] == 'stopped'
    assert len(fleet.requests('stage_plan')) == 1
    assert not fleet.requests('execute_plan')
    assert fleet.store.get('action_request', first['request_id'])['result_consumed'] is True
    response = fleet.client.post(BASE + '/' + batch['id'] + '/resume',
                                 json={'expected_revision': current['revision']})
    assert response.status_code == 409, response.text
    assert len(fleet.requests('stage_plan')) == 1


@pytest.mark.parametrize('legacy_interruption', [False, True])
def test_standalone_plan_cannot_restage_after_uncertain_execution(fleet, legacy_interruption):
    device = fleet.enroll('uncertain-standalone')
    response = fleet.client.post('/api/v1/plans', json={
        'device_id': 'uncertain-standalone', 'finding_ids': [device['finding']['id']]})
    assert response.status_code == 201, response.text
    plan_id = response.json()['id']
    base = '/api/v1/plans/' + plan_id
    assert fleet.client.post(base + '/approve', json={}).status_code == 200
    staged = fleet.client.post(base + '/stage', json={})
    assert staged.status_code == 202, staged.text
    fleet.heartbeat('uncertain-standalone', staged.json()['stage_request_id'], 'staged')
    executed = fleet.client.post(base + '/execute', json={'confirmed_device_id': 'uncertain-standalone'})
    assert executed.status_code == 202, executed.text
    kwargs = {'status': 'unknown'} if not legacy_interruption else {
        'status': 'denied', 'fact_status': 'denied',
        'details': 'Interrupted maintenance action requires operator recovery; it will not be replayed'}
    fleet.heartbeat('uncertain-standalone', executed.json()['action_request_id'], **kwargs)
    assert fleet.store.get('plan', plan_id)['status'] == 'unknown'
    retried = fleet.client.post(base + '/stage', json={})
    assert retried.status_code == 409, retried.text
    assert len(fleet.requests('stage_plan')) == len(fleet.requests('execute_plan')) == 1


def test_restart_keeps_paused_batch_request_and_does_not_duplicate_actions(tmp_path):
    config = Settings(_env_file=None, state_dir=tmp_path / 'state',
                      database_url='sqlite:///' + str(tmp_path / 'restart.sqlite'),
                      jobs_enabled=False, scanner_binary='/not-installed/grype',
                      source_roots=[], ai_enabled=False)
    value = Fleet(config)
    with value.connected() as fleet:
        fleet.enroll('restart-a')
        fleet.enroll('restart-b')
        batch = fleet.create_batch(['restart-a', 'restart-b'])
        fleet.stage(batch)
        first, = fleet.requests('stage_plan')
        paused = fleet.control(batch, 'pause')
    with value.connected() as reopened:
        current = reopened.batch(batch['id'])
        assert current['status'] == 'paused'
        assert current['revision'] == paused['revision']
        assert [row['request_id'] for row in reopened.requests('stage_plan')] == [first['request_id']]
        delivered = reopened.heartbeat(first['device_id'])['action_requests']
        assert [row['request_id'] for row in delivered] == [first['request_id']]
        reopened.heartbeat(first['device_id'], first['request_id'], 'staged')
        assert len(reopened.requests('stage_plan')) == 1
        resumed = reopened.control(current, 'resume')
        assert resumed['revision'] > paused['revision']
        assert len(reopened.requests('stage_plan')) == 2
