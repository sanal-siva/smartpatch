"""Transactional fleet control tests; no package-manager or network execution."""
from concurrent.futures import ThreadPoolExecutor
import pytest
from tests.integration.test_remediation_batches_acceptance import fleet, BASE


def test_create_and_control_retries_do_not_duplicate_outbox(fleet):
    fleet.enroll('idempotent')
    body = {'finding_ids': [fleet.devices['idempotent']['finding']['id']], 'idempotency_key': 'stable-client-operation'}
    created = fleet.client.post(BASE, json=body)
    batch = created.json()
    assert created.status_code == 201
    assert fleet.client.post(BASE, json=body).json()['id'] == batch['id']
    changed = fleet.client.post(BASE, json={**body, 'max_concurrent_switches': 2})
    assert changed.status_code == 409
    stage = {'expected_revision': batch['revision'], 'confirmed_plan_ids': [batch['entries'][0]['plan_id']]}
    endpoint = BASE + '/' + batch['id'] + '/approve-and-stage'
    first = fleet.client.post(endpoint, json=stage)
    assert first.status_code == 202, first.text
    repeated = fleet.client.post(endpoint, json=stage)
    assert repeated.status_code == 202, repeated.text
    assert repeated.json()['revision'] == first.json()['revision']
    assert len(fleet.requests('stage_plan')) == 1
    request, = fleet.requests('stage_plan')
    fleet.heartbeat('idempotent', request['request_id'], 'staged')
    current = fleet.batch(batch['id'])
    execute = {'expected_revision': current['revision'], 'confirmed_plan_ids': stage['confirmed_plan_ids'],
               'confirmed_device_ids': ['idempotent']}
    endpoint = BASE + '/' + batch['id'] + '/execute'
    assert fleet.client.post(endpoint, json=execute).status_code == 202
    assert fleet.client.post(endpoint, json=execute).status_code == 202
    assert len(fleet.requests('execute_plan')) == 1


def test_all_approval_children_and_outbox_rollback_if_one_became_stale(fleet):
    fleet.enroll('atomic-a'); fleet.enroll('atomic-b')
    batch = fleet.create_batch(['atomic-a', 'atomic-b'])
    fleet.store.update_device('atomic-b', {'review_revision': 'retracted-after-preview'})
    response = fleet.client.post(BASE + '/' + batch['id'] + '/approve-and-stage', json={
        'expected_revision': batch['revision'], 'confirmed_plan_ids': [e['plan_id'] for e in batch['entries']]})
    assert response.status_code == 409, response.text
    assert not fleet.store.list('action_request')
    assert all(fleet.store.get('plan', e['plan_id'])['approved'] is False for e in batch['entries'])
    assert fleet.batch(batch['id'])['status'] == 'draft'
    assert not [event for event in fleet.store.list('event') if event['type'] == 'plan.approved']


def test_concurrent_batches_reserve_only_one_action_per_device(fleet):
    fleet.enroll('same-device')
    batches = [fleet.create_batch(['same-device']) for _ in range(2)]
    def approve(batch):
        return fleet.client.post(BASE + '/' + batch['id'] + '/approve-and-stage', json={
            'expected_revision': batch['revision'], 'confirmed_plan_ids': [batch['entries'][0]['plan_id']]})
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(approve, batches))
    assert [r.status_code for r in results] == [202, 202]
    assert len(fleet.requests('stage_plan')) == 1
    for _ in range(3):
        fleet.runtime.reconcile_remediation_batches()
    assert len(fleet.requests('stage_plan')) == 1
    assert sorted(fleet.store.get('plan', b['entries'][0]['plan_id'])['status'] for b in batches) == ['approved', 'staging_queued']


def test_draft_refresh_supersedes_children_and_rejects_old_confirmation(fleet):
    fleet.enroll('refresh')
    batch = fleet.create_batch(['refresh'])
    old = batch['entries'][0]
    updated = fleet.client.post(BASE + '/' + batch['id'] + '/refresh', json={'expected_revision': 1})
    assert updated.status_code == 200, updated.text
    new = updated.json()['entries'][0]
    assert new['id'] == old['id'] and new['plan_id'] != old['plan_id']
    assert fleet.store.get('plan', old['plan_id'])['status'] == 'superseded'
    stale = fleet.client.post(BASE + '/' + batch['id'] + '/approve-and-stage', json={
        'expected_revision': 1, 'confirmed_plan_ids': [old['plan_id']]})
    assert stale.status_code == 409
    wrong = fleet.client.patch(BASE + '/' + batch['id'], json={
        'expected_revision': 2, 'target_versions': {'unselected-entry': '9.9'}})
    assert wrong.status_code == 422
    # Atomic rollback preserves the current child even though replacement began.
    assert fleet.store.get('plan', new['plan_id'])['status'] == 'draft'


def test_draft_target_override_uses_server_advisory_resolution(fleet):
    fleet.enroll('target')
    finding = fleet.devices['target']['finding']
    fleet.store.put('finding', finding['id'], {**finding, 'fixed_versions': ['1.1', '1.2'],
                    'candidate_fixed_versions': ['1.1', '1.2']}, 'target')
    batch = fleet.create_batch(['target'])
    entry = batch['entries'][0]
    updated = fleet.client.patch(BASE + '/' + batch['id'], json={
        'expected_revision': 1, 'target_versions': {entry['id']: '1.2'}})
    assert updated.status_code == 200, updated.text
    assert updated.json()['entries'][0]['target_version'] == '1.2'
    invalid = fleet.client.patch(BASE + '/' + batch['id'], json={
        'expected_revision': 2, 'target_versions': {entry['id']: '0.1'}})
    assert invalid.status_code == 200, invalid.text
    assert invalid.json()['entries'][0]['eligibility'] == 'error'
    assert not fleet.store.list('action_request')


def test_get_never_dispatches_or_updates_state(fleet):
    fleet.enroll('read-only')
    batch = fleet.create_batch(['read-only'])
    frozen = fleet.store.get('remediation_batch', batch['id'])
    before = len(fleet.store.list('event'))
    for _ in range(3):
        assert fleet.client.get(BASE + '/' + batch['id']).status_code == 200
        assert fleet.client.get(BASE).status_code == 200
    assert fleet.store.get('remediation_batch', batch['id']) == frozen
    assert len(fleet.store.list('event')) == before
    assert not fleet.store.list('action_request')


@pytest.mark.parametrize('value', [0, 11, '2', True])
def test_invalid_concurrency_rejected(fleet, value):
    fleet.enroll('limit')
    response = fleet.client.post(BASE, json={'finding_ids': [fleet.devices['limit']['finding']['id']],
                                           'max_concurrent_switches': value})
    assert response.status_code == 422
    assert not fleet.store.list('remediation_batch')


def test_execute_confirmation_does_not_authorize_later_staging_results(fleet):
    fleet.enroll('subset-a'); fleet.enroll('subset-b')
    batch = fleet.create_batch(['subset-a', 'subset-b'], limit=2)
    fleet.stage(batch)
    a = next(row for row in fleet.requests('stage_plan') if row['device_id'] == 'subset-a')
    b = next(row for row in fleet.requests('stage_plan') if row['device_id'] == 'subset-b')
    fleet.heartbeat('subset-a', a['request_id'], 'staged')
    fleet.execute(batch)
    fleet.heartbeat('subset-b', b['request_id'], 'staged')
    fleet.runtime.reconcile_remediation_batches()
    assert [row['device_id'] for row in fleet.requests('execute_plan')] == ['subset-a']


def test_receipt_and_plan_outcome_commit_atomically(fleet, monkeypatch):
    from app.services.maintenance_commands import TransactionStore
    fleet.enroll('atomic-receipt')
    batch = fleet.create_batch(['atomic-receipt'])
    fleet.stage(batch)
    request, = fleet.requests('stage_plan')
    original = TransactionStore.put
    def interrupted(self, kind, ident, payload, owner=None):
        if kind == 'plan' and payload.get('status') == 'staged':
            raise RuntimeError('Synthetic crash before plan outcome commit')
        return original(self, kind, ident, payload, owner)
    monkeypatch.setattr(TransactionStore, 'put', interrupted)
    device = fleet.devices['atomic-receipt']
    envelope = {**device['envelope'], 'kind': 'heartbeat', 'components': [], 'facts': [{
        'fact_id': request['request_id'], 'collector': 'remediation', 'status': 'complete',
        'value': {'status': 'staged'}}]}
    response = fleet.client.post('/api/v1/agents/sync', json=envelope, headers=device['headers'])
    assert response.status_code == 500  # API error handler contains the injected crash.
    assert not fleet.store.get('action_request', request['request_id']).get('result_consumed')
    assert fleet.store.get('plan', request['plan']['id'])['status'] == 'staging_queued'
    monkeypatch.setattr(TransactionStore, 'put', original)
    fleet.heartbeat('atomic-receipt', request['request_id'], 'staged')
    assert fleet.store.get('action_request', request['request_id'])['result_consumed'] is True
    assert fleet.store.get('plan', request['plan']['id'])['status'] == 'staged'


def test_standalone_plan_cannot_restage_its_unknown_previous_outcome(fleet):
    fleet.enroll('unknown-own-plan')
    created = fleet.client.post('/api/v1/plans', json={'device_id': 'unknown-own-plan',
        'finding_ids': [fleet.devices['unknown-own-plan']['finding']['id']]})
    plan = created.json()
    base = '/api/v1/plans/' + plan['id']
    assert fleet.client.post(base + '/approve').status_code == 200
    queued = fleet.client.post(base + '/stage')
    assert queued.status_code == 202, queued.text
    fleet.heartbeat('unknown-own-plan', queued.json()['stage_request_id'], 'unknown')
    restage = fleet.client.post(base + '/stage')
    assert restage.status_code == 409, restage.text
    assert len(fleet.requests('stage_plan')) == 1


def test_retention_releases_replaced_draft_child_but_keeps_current_child(fleet, tmp_path):
    from app.db.store import Record
    from app.services.retention import archive_expired
    fleet.enroll('retained-draft')
    batch = fleet.create_batch(['retained-draft'])
    old_plan = batch['entries'][0]['plan_id']
    refreshed = fleet.client.post(BASE + '/' + batch['id'] + '/refresh', json={'expected_revision': 1}).json()
    current_plan = refreshed['entries'][0]['plan_id']
    with fleet.store.sessions.begin() as session:
        for ident in (old_plan, current_plan):
            row = session.get(Record, ('plan', ident))
            row.created_at = row.updated_at = '2000-01-01T00:00:00Z'
    archive_expired(fleet.store, tmp_path / 'archive')
    assert fleet.store.get('plan', old_plan) is None
    assert fleet.store.get('plan', current_plan) is not None


def test_unknown_reservation_survives_policy_invalidation_and_new_plan(fleet):
    from app.services.maintenance_commands import transaction, device_busy
    fleet.enroll('uncertain-policy')
    batch = fleet.create_batch(['uncertain-policy'])
    fleet.stage(batch)
    stage, = fleet.requests('stage_plan')
    fleet.heartbeat('uncertain-policy', stage['request_id'], 'staged')
    fleet.execute(batch)
    execution, = fleet.requests('execute_plan')
    fleet.heartbeat('uncertain-policy', execution['request_id'], 'unknown')
    assert fleet.store.get('plan', execution['plan']['id'])['outcome_unknown'] is True
    assert fleet.store.get('action_request', execution['request_id'])['outcome_unknown'] is True
    fleet.runtime.save_configuration({'build_evidence_policy': 'optional'})
    plan = fleet.store.get('plan', execution['plan']['id'])
    assert plan['status'] == 'requires_revalidation' and plan['outcome_unknown'] is True
    with transaction(fleet.runtime) as service:
        assert device_busy(service, 'uncertain-policy') == plan['id']
    # Fresh metadata and fresh approval cannot establish what the old install did.
    from app.services.assessment import RULESET_VERSION
    fleet.scan('uncertain-policy', [{**fleet.devices['uncertain-policy']['finding_source'],
        'build_evidence_policy': 'optional', 'ruleset_version': RULESET_VERSION}])
    fleet.devices['uncertain-policy']['finding'] = fleet.store.list('finding', owner='uncertain-policy')[0]
    new = fleet.create_batch(['uncertain-policy'])
    assert new['entries'][0]['eligibility'] == 'eligible'
    waiting = fleet.stage(new)
    assert waiting['entries'][0]['plan']['status'] == 'approved'
    assert len(fleet.requests('stage_plan')) == 1
    resumed = fleet.control(batch, 'resume')
    assert resumed['status'] not in ('completed', 'completed_with_failures', 'stopped')
    stopped = fleet.control(batch, 'stop')
    assert stopped['status'] == 'stopping'
    assert fleet.client.post('/api/v1/plans/' + plan['id'] + '/stage').status_code == 409
