"""Policy transitions cannot reuse assessments, approvals or frozen AI work."""
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.db.store import inventory_hash, now
from app.runtime import Runtime
from app.services.analysis_lifecycle import analysis_identity
from app.services.external_agent import (ExternalAgentError, create_external_session,
    project_external_analysis, submit_external_analysis)
from app.services.maintenance_policy import resolve_maintenance_targets
from app.services.pipeline import AnalysisPipeline
from app.services.release_service import retry_identity, release_retry_identity
from app.services.request_assessment import assess_request, RequestAssessmentError
from tests.unit.test_analysis_services import finding


ADMIN = {'id': 'fixture-admin', 'role': 'admin'}


class Factory:
    def __init__(self):
        self.scans = 0
        self.during_scan = None

    def __call__(self, roots, binary, configuration):
        pipeline = AnalysisPipeline(roots, binary, configuration)

        def scan(scope):
            self.scans += 1
            if self.during_scan:
                callback, self.during_scan = self.during_scan, None
                callback()
            return {'findings': [finding()], 'evidence': [{'id': 'scan-1', 'type': 'scanner_match',
                'data': {'namespace': 'debian:distro:debian:12'}}], 'scope_id': scope['id'],
                'components_scanned': 1, 'missing_versions': [],
                'scanner': {'version': 'fixture', 'database': {'checksum': 'db1'}}}

        pipeline.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'}, scan_scope=scan)
        return pipeline


@pytest.fixture
def runtime(tmp_path):
    factory = Factory()
    settings = Settings(database_url='sqlite:///' + str(tmp_path / 'smart_patch.db'), state_dir=tmp_path,
        jobs_enabled=False, ai_enabled=False, bootstrap_token='fixture-only')
    service = Runtime(settings, pipeline_factory=factory)
    service.start()
    service.test_factory = factory
    service.scanner_info = {'status': 'ready', 'db_revision': 'db1'}
    components = [{'component_id': 'openssl-host', 'scope': 'host', 'name': 'openssl', 'version': '3.0.1-1',
        'architecture': 'amd64', 'source_name': 'openssl', 'source_version': '3.0.1-1',
        'distro': {'id': 'debian', 'version_id': '12'}}]
    service.store.sync({'device_id': 'leaf', 'epoch': 'one', 'sequence': 1, 'kind': 'checkpoint',
        'build_id': 'build-a', 'sonic_version': 'test-release', 'collected_at': now(),
        'components': components, 'inventory_digest': inventory_hash(components)}, ADMIN)
    yield service
    service.stop()


def run_scan(runtime):
    operation = runtime.schedule_scan('leaf')
    claimed = runtime.store.claim()
    assert claimed['id'] == operation['id']
    result = runtime._job_scan(claimed)
    runtime.store.update_operation(operation['id'], 'completed', result=result)
    return result


def stored_finding(runtime):
    return runtime.store.list('finding', owner='leaf')[0]


def query(runtime):
    return assess_request(runtime, {'sonic_version': 'test-release', 'device_context': {'device_id': 'leaf'},
        'vulnerabilities': [{'cve_id': 'CVE-2026-1234', 'package_name': 'openssl',
                            'affected_version': '3.0.1-1', 'scope_id': 'host'}]}, ADMIN)


def submission(bundle):
    return {'snapshot_hash': bundle['snapshot_hash'], 'cve_id': bundle['finding']['cve_id'],
        'component_id': bundle['finding']['component_id'], 'scope_id': bundle['finding']['scope_id'],
        'proposed_applicability': 'under_investigation', 'rationale': 'Exact source and artifact evidence is still unavailable.',
        'evidence_ids': ['scan-1'], 'unknowns': ['No verified artifact binding']}


def test_assessment_cache_is_partitioned_by_policy_and_round_trip_revision(runtime):
    assert run_scan(runtime)['accepted']
    assert stored_finding(runtime)['applicability'] == 'under_investigation'
    assert run_scan(runtime)['accepted']
    assert runtime.test_factory.scans == 1
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    assert runtime.configuration(public=True)['build_evidence_policy'] == 'optional'
    assert run_scan(runtime)['accepted']
    current = stored_finding(runtime)
    assert current['applicability'] == 'affected' and current['artifact_binding'] == 'unverified'
    assert current['decision_basis'] == 'inventory_advisory_match'
    runtime.save_configuration({'build_evidence_policy': 'required'})
    assert run_scan(runtime)['accepted']
    assert stored_finding(runtime)['applicability'] == 'under_investigation'
    assert runtime.test_factory.scans == 3


def test_legacy_lookup_cannot_reuse_optional_verdict_after_policy_change(runtime):
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    run_scan(runtime)
    first = query(runtime)
    assert first['recommendations'][0]['applicability'] == 'affected'
    assert query(runtime)['cached']
    runtime.save_configuration({'build_evidence_policy': 'required'})
    changed = query(runtime)
    assert not changed['cached']
    assert changed['recommendations'][0]['applicability'] == 'under_investigation'
    assert changed['build_evidence_policy'] == 'required'


def test_inflight_scan_cannot_commit_after_policy_changes_away_and_back(runtime):
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    def transition():
        runtime.save_configuration({'build_evidence_policy': 'required'})
        runtime.save_configuration({'build_evidence_policy': 'optional'})
    runtime.test_factory.during_scan = transition
    assert run_scan(runtime)['accepted'] is False
    assert runtime.store.list('finding') == []


def test_device_release_retry_and_backlog_identities_include_policy_revision(runtime):
    runtime.store.put('release', 'rel', {'release_id': 'rel', 'artifact_id': 'artifact', 'scanner': {'db_revision': 'db1'}})
    def snapshots():
        return [analysis_identity(runtime, 'device', 'leaf'), analysis_identity(runtime, 'release', 'rel'),
            retry_identity(runtime, runtime.store.device('leaf')), release_retry_identity(runtime, runtime.store.get('release', 'rel'))]
    before = snapshots()
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    optional = snapshots()
    runtime.save_configuration({'build_evidence_policy': 'required'})
    returned = snapshots()
    for original, changed, back in zip(before, optional, returned):
        assert original['build_evidence_policy'] == 'required'
        assert changed['build_evidence_policy'] == 'optional'
        assert original != changed and original != back


def test_policy_change_revokes_reviews_plans_actions_and_release_projections(runtime):
    run_scan(runtime)
    runtime.store.put('reviewed_assessment', 'review', {'id': 'review', 'verification': 'reviewed'})
    runtime.store.put('plan', 'plan', {'id': 'plan', 'device_id': 'leaf', 'status': 'staged',
        'approved': True, 'staging_eligible': True, 'execution_eligible': True}, 'leaf')
    runtime.store.put('action_request', 'action', {'request_id': 'action', 'device_id': 'leaf', 'status': 'queued'}, 'leaf')
    runtime.store.put('release', 'rel', {'release_id': 'rel', 'status': 'analyzed'})
    for kind in ('release_finding', 'package_cve'):
        runtime.store.put(kind, 'finding', {'id': 'finding', 'release_id': 'rel', 'status': 'current', 'applicability': 'fixed'}, 'rel')
    runtime.store.put('package', 'pkg', {'id': 'pkg', 'release_id': 'rel', 'cves_fixed': ['CVE-2026-1234']}, 'rel')
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    assert runtime.store.get('reviewed_assessment', 'review')['verification'] == 'invalidated'
    plan = runtime.store.get('plan', 'plan')
    assert plan['status'] == 'requires_revalidation' and not plan['approved'] and not plan['execution_eligible']
    assert runtime.store.get('action_request', 'action')['status'] == 'superseded'
    assert stored_finding(runtime)['assessment_stale']
    assert runtime.store.list('finding_summary')[0]['assessment_stale']
    for kind in ('release_finding', 'package_cve'):
        assert runtime.store.get(kind, 'finding')['assessment_stale']
    assert runtime.store.get('package', 'pkg')['cves_fixed'] == []


def test_external_sessions_and_archived_proposals_are_bound_to_policy(runtime):
    run_scan(runtime)
    fid = stored_finding(runtime)['id']
    archived = create_external_session(runtime, fid, ADMIN)
    submit_external_analysis(runtime, archived['session_id'], submission(archived), ADMIN)
    opened = create_external_session(runtime, fid, ADMIN)
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    with pytest.raises(ExternalAgentError) as error:
        submit_external_analysis(runtime, opened['session_id'], submission(opened), ADMIN)
    assert error.value.status_code == 409
    proposal = project_external_analysis(runtime, stored_finding(runtime))['latest_external_analysis']
    assert proposal['stale'] and 'build_evidence_policy_changed' in proposal['stale_reasons']


def test_startup_policy_change_invalidates_saved_findings_even_without_workers(runtime):
    run_scan(runtime)
    runtime.settings.build_evidence_policy = 'optional'
    runtime.start()
    device = runtime.store.device('leaf')
    assert device['scan_status'] == 'pending'
    assert device['assessment_build_evidence_policy'] == 'optional'
    assert stored_finding(runtime)['assessment_stale']


def test_inventory_advisory_targets_require_review_even_when_fix_version_exists(runtime):
    runtime.save_configuration({'build_evidence_policy': 'optional'})
    run_scan(runtime)
    current = stored_finding(runtime)
    resolution = resolve_maintenance_targets([current])
    assert resolution['applicability_review_required'] is True
    assert all(option['execution_eligible'] is False for option in resolution['target_options'])
    reviewed = {**current, 'decision_basis': 'operator_review'}
    assert resolve_maintenance_targets([reviewed])['applicability_review_required'] is False


def test_policy_change_during_lookup_rejects_response(runtime, monkeypatch):
    run_scan(runtime)
    original = runtime.store.put
    def save_and_change(kind, ident, value, owner=None):
        original(kind, ident, value, owner)
        if kind == 'assessment_response':
            runtime.save_configuration({'build_evidence_policy': 'optional'})
    monkeypatch.setattr(runtime.store, 'put', save_and_change)
    with pytest.raises(RequestAssessmentError) as error:
        query(runtime)
    assert error.value.status_code == 409
