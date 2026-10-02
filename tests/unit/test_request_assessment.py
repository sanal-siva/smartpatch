import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from app.config import Settings
from app.db.store import now, inventory_hash, stable_hash
from app.runtime import Runtime
from app.services.request_assessment import assess_request, RequestAssessmentError


ADMIN = {'id': 'admin', 'role': 'admin'}
AGENT = {'id': 'agent', 'role': 'agent', 'device_id': 'leaf1'}


class PipelineFixture:
    def __init__(self, *args):
        self.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'})
        self.ai = SimpleNamespace(health=lambda: {'configured': False, 'circuit_open': False})


@pytest.fixture
def runtime(tmp_path):
    settings = Settings(database_url='sqlite:///' + str(tmp_path / 'state.db'), state_dir=tmp_path,
                        jobs_enabled=False, bootstrap_token='fixture-only')
    runtime = Runtime(settings, pipeline_factory=PipelineFixture)
    runtime.scanner_info = {'status': 'ready', 'db_revision': 'db1'}
    components = [{'component_id': scope + ':openssl', 'scope': scope, 'name': 'openssl', 'version': '1.0',
                   'architecture': 'amd64'} for scope in ('host', 'bgp')]
    runtime.store.sync({'device_id': 'leaf1', 'epoch': 'e1', 'sequence': 1, 'kind': 'checkpoint', 'build_id': 'build-a',
        'sonic_version': 'test-build', 'collected_at': now(), 'components': components,
        'inventory_digest': inventory_hash(components)}, ADMIN)
    records = []
    for scope in ('host', 'bgp'):
        records.append({'cve_id': 'CVE-2026-0001', 'package_name': 'openssl', 'affected_version': '1.0',
            'scope_id': scope, 'component_id': scope + ':openssl', 'cvss_score': 7.5, 'risk_score': 7.5,
            'fixed_versions': ['1.1'], 'applicability': 'not_affected' if scope == 'host' else 'under_investigation',
            'decision_basis': 'operator_review' if scope == 'host' else None,
            'decision_valid_until': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat() if scope == 'host' else None,
            'vex_justification': 'vulnerable_code_not_present' if scope == 'host' else None,
            'rationale': 'Recorded scoped assessment', 'evidence_ids': ['scan1'], 'action_type': 'defer', 'exposure': 'unknown',
            'component': {'name': 'openssl', 'version': '1.0', 'ecosystem': 'deb', 'source_name': 'openssl', 'source_version': '1.0'}})
    digest = runtime.store.device('leaf1')['inventory_digest']
    runtime.store.store_findings('leaf1', digest, {'findings': records, 'evidence': [{'id': 'scan1', 'type': 'scanner_match'}],
                                 'coverage': {'complete': True}, 'scanner': {'db_revision': 'db1'}}, 'r1')
    yield runtime
    runtime.stop()


def payload(scope='host', **context):
    item = {'cve_id': 'CVE-2026-0001', 'package_name': 'openssl', 'affected_version': '1.0', 'cvss_score': 1.0}
    if scope is not None:item['scope_id'] = scope
    return {'sonic_version': 'test-build', 'vulnerabilities': [item], 'device_context': context}


def test_bound_agent_gets_current_scoped_record_and_real_cache_hit(runtime):
    first = assess_request(runtime, payload(), AGENT)
    recommendation = first['recommendations'][0]
    assert recommendation['applicability'] == 'not_affected'
    assert recommendation['vex_verdict'] == 'not_affected'
    assert recommendation['risk_score'] == 7.5  # server evidence overrides caller CVSS
    assert recommendation['scope_id'] == 'host'
    assert first['cached'] is False
    second = assess_request(runtime, payload(), AGENT)
    assert second['cached'] is True
    assert runtime.metrics['assessment_cache_hits'] == 1
    assert runtime.metrics['assessment_cache_misses'] == 1


def test_latency_includes_server_observed_worker_wait_and_ignores_client_timestamps(runtime):
    # The local monotonic stand-in avoids changing other modules' clocks.
    timer=SimpleNamespace(monotonic=iter([105.0,105.125]).__next__)
    data=payload(request_started_monotonic=0,queue_wait_ms=999999)
    with patch('app.services.request_assessment.time',timer):
        result=assess_request(runtime,data,AGENT,request_started_monotonic=100.0)
    assert result['assessment_duration_ms']==5125
    assert result['processing_duration_ms']==125 and result['queue_wait_ms']==5000
    assert result['duration_basis']=='server_request_entry_to_audit_prepare'
    record=runtime.store.get('request',result['request_id'])
    for field in ('assessment_duration_ms','processing_duration_ms','queue_wait_ms','duration_basis'):
        assert record[field]==result[field]
    timer=SimpleNamespace(monotonic=iter([200.0,200.050]).__next__)
    with patch('app.services.request_assessment.time',timer):
        direct=assess_request(runtime,data,AGENT)
    assert direct['queue_wait_ms']==0 and direct['assessment_duration_ms']==50
    assert direct['duration_basis']=='worker_entry_to_audit_prepare'


def test_action_receipt_reuses_review_cache_but_real_evidence_invalidates_it(runtime):
    assert assess_request(runtime,payload(),AGENT)['recommendations'][0]['applicability']=='not_affected'
    receipt={'collector':'remediation','status':'complete','collected_at':now(),
             'value':{'action':'stage_plan','status':'staged'}}
    runtime.store.update_device('leaf1',{'facts':[receipt]})
    result=assess_request(runtime,payload(),AGENT)
    assert result['cached'] is True
    assert result['recommendations'][0]['applicability']=='not_affected'
    runtime.store.update_device('leaf1',{'facts':[receipt,{'collector':'services','status':'observed',
        'collected_at':now(),'value':{'lldpd':'running'}}]})
    result=assess_request(runtime,payload(),AGENT)
    assert result['cached'] is False
    assert result['recommendations'][0]['applicability']=='under_investigation'


def test_scope_ambiguity_is_unknown_and_caller_trust_flags_are_ignored(runtime):
    data = payload(None, artifact_verified=True, applicability='not_affected')
    result = assess_request(runtime, data, AGENT)
    assert result['recommendations'][0]['applicability'] == 'under_investigation'
    assert result['recommendations'][0]['ambiguous_occurrences'] == 2
    assert result['recommendations'][0]['vex_verdict'] is None


def test_agent_cannot_query_another_device(runtime):
    with pytest.raises(RequestAssessmentError) as error:
        assess_request(runtime, payload(device_id='other'), AGENT)
    assert error.value.status_code == 403


def test_operator_explicit_device_selector_uses_server_identity(runtime):
    result = assess_request(runtime, payload(device_id='leaf1'), ADMIN)
    assert result['recommendations'][0]['assessment_source'] == 'registered_device_finding'
    unbound = assess_request(runtime, payload(artifact_verified=True), ADMIN)
    assert unbound['recommendations'][0]['applicability'] == 'under_investigation'


def test_cached_exemption_expires_without_any_input_change(runtime):
    first = assess_request(runtime, payload(), AGENT)
    assert first['recommendations'][0]['applicability'] == 'not_affected'
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    class FutureDatetime(datetime):
        @classmethod
        def now(cls, tz=None):return future
    with patch('app.services.assessment.datetime', FutureDatetime):
        second = assess_request(runtime, payload(), AGENT)
    assert second['cached'] is False
    assert second['recommendations'][0]['vex_verdict'] is None
    assert second['recommendations'][0]['applicability'] == 'under_investigation'


def test_binding_and_advisory_changes_prevent_stale_reuse(runtime):
    assess_request(runtime, payload(), AGENT)
    runtime.store.update_device('leaf1', {'binding_revision': 'revoked'})
    changed = assess_request(runtime, payload(), AGENT)
    assert changed['cached'] is False
    assert changed['recommendations'][0]['applicability'] == 'under_investigation'
    runtime.scanner_info['db_revision'] = 'db2'
    assert assess_request(runtime, payload(), AGENT)['recommendations'][0]['vex_verdict'] is None


def test_source_change_prevents_old_source_bound_decision(runtime):
    fid = stable_hash(['leaf1', 'host:openssl', 'host', 'CVE-2026-0001'])
    record = runtime.store.get('finding', fid)
    runtime.store.put('finding', fid, {**record, 'source_revision': 'source-a'}, 'leaf1')
    with patch.object(runtime, '_source_revision', return_value='source-a'):
        assert assess_request(runtime, payload(), AGENT)['recommendations'][0]['vex_verdict'] == 'not_affected'
    with patch.object(runtime, '_source_revision', return_value='source-b'):
        assert assess_request(runtime, payload(), AGENT)['recommendations'][0]['vex_verdict'] is None


def test_duplicate_queries_compute_once_and_preserve_order(runtime):
    data = payload()
    data['vulnerabilities'] *= 5
    response = assess_request(runtime, data, AGENT)
    assert len(response['recommendations']) == 5
    assert response['unique_candidates'] == 1
    assert len(runtime.store.list('assessment_response')) == 1


def test_concurrent_identical_requests_have_one_cache_miss(runtime):
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: assess_request(runtime, payload(), AGENT), range(8)))
    assert sum(not item['cached'] for item in results) == 1
    assert runtime.metrics['assessment_cache_misses'] == 1
    assert len(runtime.store.list('request')) == 8


def test_circuit_open_returns_only_fresh_exact_cached_result(runtime):
    assess_request(runtime, payload(), AGENT)
    runtime.pipeline.ai.health = lambda: {'configured': True, 'circuit_open': True}
    result = assess_request(runtime, payload(), AGENT)
    assert result['cached'] is True and result['provider_circuit_open'] is True
    assert result['recommendations'][0]['vex_verdict'] == 'not_affected'
    assert runtime.store.operations() == []


def test_optional_ai_is_queued_for_selected_registered_case_not_inline(runtime):
    runtime.store.put('settings', 'service', {'ai_enabled': True})
    runtime.pipeline.ai.health = lambda: {'configured': True, 'circuit_open': False}
    result = assess_request(runtime, payload('bgp', request_ai=True), AGENT)
    assert result['analysis_status'] == 'pending'
    assert len(result['operation_ids']) == 1
    history=runtime.store.get('request',result['request_id'])
    assert history['status']=='queued' and history['outcome']=='queued'
    assert history['timeline'][0]['status']=='queued'
    operation = runtime.store.operation(result['operation_ids'][0])
    assert operation['arguments']['finding_ids'] == [stable_hash(['leaf1', 'bgp:openssl', 'bgp', 'CVE-2026-0001'])]
    repeated = assess_request(runtime, payload('bgp', request_ai=True), AGENT)
    assert repeated['cached'] is True
    assert repeated['operation_ids'] == result['operation_ids']


def add_catalog(runtime):
    from app.services.assessment import RULESET_VERSION
    release = {'release_id': 'release-test', 'artifact_id': 'artifact-a', 'build_id': 'signed-build', 'scanner': {'db_revision': 'db1'},
               'scan_revision':'catalog-scan1','assessment_revision':'catalog-scan1','source_revision':'a'*40}
    runtime.store.put('release', 'release-test', release)
    runtime.store.put('artifact', 'artifact-a', {'id': 'artifact-a', 'release_id': 'release-test', 'source_sha256': 'a' * 64})
    runtime.store.put('build_binding', 'signed-build', {'verification': 'signature_verified', 'artifact_id': 'artifact-a',
        'sbom_digest': 'sha256:' + 'a' * 64, 'index_digest': 'sha256:' + 'b' * 64})
    row = {'id': 'pkg-cve', 'release_id': 'release-test', 'artifact_id': 'artifact-a', 'status': 'current', 'assessed_at': now(),
        'scan_revision':'catalog-scan1','assessment_revision':'catalog-scan1','source_revision':'a'*40,'ruleset_version':RULESET_VERSION,
        'cve_id': 'CVE-2026-0001', 'package_name': 'openssl', 'affected_version': '1.0', 'installed_version': '1.0',
        'scope_id': 'host', 'component_id': 'component-release', 'applicability': 'fixed', 'decision_basis': 'artifact_verified',
        'evidence_ids': ['verified-patch'], 'fixed_versions': ['1.1'], 'latest_available_version': '1.2'}
    runtime.store.put('package_cve', row['id'], row, 'release-test')
    runtime.store.put('release_finding', row['id'], row, 'release-test')
    return row


def test_release_label_alone_never_grants_vex_but_explicit_verified_artifact_can(runtime):
    add_catalog(runtime)
    data = payload()
    data['sonic_version'] = 'release-test'
    response = assess_request(runtime, data, ADMIN)
    assert response['recommendations'][0]['applicability'] == 'under_investigation'
    assert response['recommendations'][0]['package_intelligence'][0]['latest_available_version'] == '1.2'
    data['device_context']['artifact_id'] = 'artifact-a'
    verified = assess_request(runtime, data, ADMIN)
    assert verified['recommendations'][0]['vex_verdict'] == 'fixed'
    assert verified['recommendations'][0]['assessment_source'] == 'verified_artifact_catalog'


def test_historical_catalog_copy_and_mismatched_artifact_are_excluded(runtime):
    row = add_catalog(runtime)
    runtime.store.put('release_finding', row['id'], {**row, 'status': 'no_longer_reported'}, 'release-test')
    data = payload(artifact_id='artifact-a');data['sonic_version'] = 'release-test'
    response = assess_request(runtime, data, ADMIN)
    assert response['recommendations'][0]['vex_verdict'] is None
    assert 'package_intelligence' not in response['recommendations'][0]


@pytest.mark.parametrize('changed',[
    {'scan_revision':'later-partial-scan'}, {'source_revision':'b'*40}, {'ruleset_version':'old-rules'}])
def test_retained_catalog_verdict_requires_current_scan_source_and_ruleset(runtime,changed):
    row=add_catalog(runtime)
    data=payload(artifact_id='artifact-a');data['sonic_version']='release-test'
    assert assess_request(runtime,data,ADMIN)['recommendations'][0]['vex_verdict']=='fixed'
    # A previous occurrence retained after a partial scan remains visible as
    # package information, but must not become an authoritative suppression.
    for kind in ('package_cve','release_finding'):
        runtime.store.put(kind,row['id'],{**row,**changed},'release-test')
    result=assess_request(runtime,data,ADMIN)['recommendations'][0]
    assert result['applicability']=='under_investigation' and result['vex_verdict'] is None
    assert result['package_intelligence']


def test_unrelated_ai_subset_revision_does_not_stale_current_catalog_scan(runtime):
    add_catalog(runtime)
    release=runtime.store.get('release','release-test')
    runtime.store.put('release','release-test',{**release,'assessment_revision':'other-cve-analysis'})
    data=payload(artifact_id='artifact-a');data['sonic_version']='release-test'
    assert assess_request(runtime,data,ADMIN)['recommendations'][0]['vex_verdict']=='fixed'


def test_never_returns_auto_heal_without_policy(runtime):
    fid = stable_hash(['leaf1', 'host:openssl', 'host', 'CVE-2026-0001'])
    record = runtime.store.get('finding', fid)
    runtime.store.put('finding', fid, {**record, 'action_type': 'auto_heal'}, 'leaf1')
    assert assess_request(runtime, payload(), AGENT)['recommendations'][0]['action_type'] == 'defer'


def test_complete_context_is_cache_bound_without_trusting_its_flags(runtime):
    first = assess_request(runtime, payload(site='one'), AGENT)
    assert first['cached'] is False
    second = assess_request(runtime, payload(site='two', artifact_verified=True), AGENT)
    assert second['cached'] is False
    assert second['recommendations'][0]['assessment_source'] == 'registered_device_finding'


def test_review_revision_changes_invalidate_previous_lookup(runtime):
    assess_request(runtime, payload(), AGENT)
    runtime.store.update_device('leaf1', {'review_revision': 'new-review'})
    response = assess_request(runtime, payload(), AGENT)
    assert response['cached'] is False
    assert response['recommendations'][0]['vex_verdict'] is None


def test_warm_request_does_not_hydrate_matching_findings_or_catalog(runtime):
    assess_request(runtime, payload(), AGENT)
    with patch('app.services.request_assessment._matching_rows', side_effect=AssertionError('Warm lookup must not hydrate matching rows')):
        result = assess_request(runtime, payload(), AGENT)
    assert result['cached'] is True
    assert result['recommendations'][0]['vex_verdict'] == 'not_affected'


def test_direct_finding_update_invalidates_warm_key_without_device_change(runtime):
    assess_request(runtime, payload(), AGENT)
    fid = stable_hash(['leaf1', 'host:openssl', 'host', 'CVE-2026-0001'])
    record = runtime.store.get('finding', fid)
    runtime.store.put('finding', fid, {**record, 'applicability': 'under_investigation',
        'decision_basis': None, 'decision_valid_until': None, 'rationale': 'Review was retracted'}, 'leaf1')
    result = assess_request(runtime, payload(), AGENT)
    assert result['cached'] is False
    assert result['recommendations'][0]['vex_verdict'] is None


def test_response_rows_are_independent_and_canonical_audit_digest_matches(runtime):
    data = payload();data['vulnerabilities'] *= 2
    result = assess_request(runtime, data, AGENT)
    audit = runtime.store.get('request', result['request_id'])
    assert audit['response_fingerprint'] == stable_hash(result['recommendations'])
    result['recommendations'][0]['evidence_ids'].append('client-only-change')
    assert 'client-only-change' not in result['recommendations'][1]['evidence_ids']
    again = assess_request(runtime, data, AGENT)
    assert again['cached'] is True
    assert 'client-only-change' not in again['recommendations'][0]['evidence_ids']


def test_policy_upgrade_invalidates_old_automatic_lookup_but_preserves_fresh_review(runtime):
    from app.services.assessment import RULESET_VERSION
    fid = stable_hash(['leaf1', 'host:openssl', 'host', 'CVE-2026-0001'])
    reviewed = runtime.store.get('finding', fid)
    automatic = {**reviewed, 'applicability': 'affected', 'decision_basis': None,
                 'decision_valid_until': None, 'ruleset_version': 'old-policy'}
    runtime.store.put('finding', fid, automatic, 'leaf1')
    assert assess_request(runtime, payload(), AGENT)['recommendations'][0]['applicability'] == 'affected'
    runtime.store.update_device('leaf1', {'assessment_ruleset_version': RULESET_VERSION, 'scan_status': 'pending'})
    changed = assess_request(runtime, payload(), AGENT)
    assert changed['cached'] is False
    assert changed['recommendations'][0]['applicability'] == 'under_investigation'
    runtime.store.put('finding', fid, {**reviewed, 'ruleset_version': 'old-policy'}, 'leaf1')
    assert assess_request(runtime, payload(), AGENT)['recommendations'][0]['vex_verdict'] == 'not_affected'
