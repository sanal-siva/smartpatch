"""Policy changes use real APIs and isolated Store state; scanner evidence is synthetic."""
import pytest

from app.db.store import now
from tests.integration.test_workspace_api import service, enroll
from tests.unit.test_optional_build_evidence import candidate


def assess_reported_inventory(runtime, device_id):
    def scan(scope):
        item = candidate()
        component = scope['components'][0]
        item.update(component=component, component_id=component['id'], affected_version=component['version'],
                    fixed_versions=['7.88.1-11'])
        return {'findings': [item], 'evidence': [{'id': 'scanner-evidence', 'type': 'scanner_match',
                'source': 'synthetic-test-fixture'}], 'components_scanned': 1, 'missing_versions': [],
                'scanner': {'version': 'synthetic', 'database': {'checksum': 'test-db'}}}
    runtime.pipeline.scanner.scan_scope = scan
    runtime.pipeline.scanner.status = lambda: {'status': 'ready', 'version': 'synthetic', 'db_revision': 'test-db'}
    operation = runtime.schedule_scan(device_id)
    result = runtime._job_scan(runtime.store.operation(operation['id']))
    assert result['accepted'], result
    return runtime.store.list('finding', owner=device_id)[0]


def test_policy_setting_is_admin_only_and_validated(service):
    client, runtime, _ = service
    assert client.get('/api/v1/settings').json()['build_evidence_policy'] == 'required'
    token = client.post('/api/v1/tokens', json={'description': 'Reader', 'role': 'operator'}).json()['token']
    assert client.put('/api/v1/settings', json={'build_evidence_policy': 'optional'},
                      headers={'Authorization': 'Bearer ' + token}).status_code == 403
    assert client.put('/api/v1/settings', json={'build_evidence_policy': 'ignore_everything'}).status_code == 422
    assert runtime.configuration()['build_evidence_policy'] == 'required'


def test_unverified_inventory_policy_round_trip_review_and_legacy_collector_guard(service, monkeypatch):
    client, runtime, _ = service
    token, envelope, _ = enroll(client)
    device_id = envelope['device_id']
    strict = assess_reported_inventory(runtime, device_id)
    assert strict['applicability'] == 'under_investigation'
    response = client.put('/api/v1/settings', json={'build_evidence_policy': 'optional'})
    assert response.status_code == 200, response.text
    finding = assess_reported_inventory(runtime, device_id)
    assert finding['applicability'] == 'affected' and finding['artifact_verified'] is False
    assert finding['decision_basis'] == 'inventory_advisory_match'
    listed = client.get('/api/v1/findings?applicability=affected').json()['findings']
    assert len(listed) == 1 and listed[0]['build_evidence_policy'] == 'optional'
    assert listed[0]['artifact_binding'] == 'unverified'
    heartbeat = {**envelope, 'kind': 'heartbeat', 'components': [], 'collected_at': now()}
    synced = client.post('/api/v1/agents/sync', json=heartbeat, headers={'Authorization': 'Bearer ' + token})
    assert synced.status_code == 200, synced.text
    wire = synced.json()['findings'][0]
    assert wire['applicability'] == 'affected' and wire['remediation_eligible'] is False
    assert wire['fixed_versions'] == [] and wire['candidate_fixed_versions'] == ['7.88.1-11']
    plan = client.post('/api/v1/plans', json={'device_id': device_id, 'finding_ids': [finding['id']]}).json()
    assert plan['staging_eligible'] is False
    assert client.post('/api/v1/plans/' + plan['id'] + '/approve').status_code == 409
    reviewed = client.post('/api/v1/findings/' + finding['id'] + '/review', json={
        'applicability': 'affected', 'justification': 'Synthetic scoped review accepts this advisory match for this occurrence.',
        'evidence_ids': ['scanner-evidence']})
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()['decision_basis'] == 'operator_review' and reviewed.json()['remediation_eligible'] is True
    reviewed_plan = client.post('/api/v1/plans', json={'device_id': device_id, 'finding_ids': [finding['id']]}).json()
    assert reviewed_plan['staging_eligible'] is True
    assert client.post('/api/v1/plans/' + reviewed_plan['id'] + '/approve').status_code == 200
    # A policy switch during a target recheck must not revive its old approved plan.
    from app.services import maintenance_jobs
    resolve = maintenance_jobs.resolve_maintenance_targets
    def switch_policy_during_recheck(*args, **kwargs):
        result = resolve(*args, **kwargs)
        runtime.save_configuration({'build_evidence_policy': 'required'})
        return result
    monkeypatch.setattr(maintenance_jobs, 'resolve_maintenance_targets', switch_policy_during_recheck)
    with pytest.raises(ValueError, match='policy changed during target validation'):
        runtime._job_plan_validate({'arguments': {'plan_id': reviewed_plan['id']}})
    assert runtime.store.get('plan', reviewed_plan['id'])['status'] == 'requires_revalidation'
    assert not client.get('/api/v1/findings?applicability=affected').json()['findings']
    stale = client.get('/api/v1/findings/' + finding['id']).json()
    assert stale['assessment_stale'] is True and stale['applicability'] == 'under_investigation'
    assert client.post('/api/v1/plans/' + reviewed_plan['id'] + '/stage').status_code == 409
    restored = assess_reported_inventory(runtime, device_id)
    assert restored['build_evidence_policy'] == 'required'
    assert restored['applicability'] == 'under_investigation' and restored['artifact_verified'] is False
