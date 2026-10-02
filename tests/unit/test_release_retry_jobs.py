import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from app.config import Settings
from app.db.store import inventory_hash, stable_hash
from app.runtime import Runtime
from app.services.release_service import advance_retry_schedule, advance_release_retries, retry_identity
from app.services.sbom_parser import scope_to_sbom, normalize_inventory


class PipelineFixture:
    def __init__(self, *args):
        self.calls = []
        self.retry_calls = []
        self.retry_failure = True
        self.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'})
    def analyze(self, inventory, context):
        self.calls.append((copy.deepcopy(inventory), copy.deepcopy(context)))
        scope = next(s for s in inventory['scopes'] if s['components'])
        component = scope['components'][0]
        return {'findings': [{'id': 'candidate', 'cve_id': 'CVE-2026-1234', 'scope_id': scope['id'],
            'component_id': component['id'], 'component': component, 'package_name': component['name'],
            'affected_version': component['version'], 'distro': scope['distro'], 'fixed_versions': ['3.0.2-1'],
            'applicability': 'under_investigation', 'assessment_state': 'analyzed', 'evidence_ids': ['scan1']}],
            'evidence': [{'id': 'scan1', 'type': 'scanner_match'}], 'errors': [], 'ai_usage': {},
            'coverage': {'complete': True, 'scopes_scanned': len(inventory['scopes'])}, 'scanner': {'db_revision': 'db1'}}
    def retry_findings(self, findings, context):
        self.retry_calls.append(copy.deepcopy(context))
        output = copy.deepcopy(findings)
        for finding in output:
            finding['assessment_state'] = 'retry_needed' if self.retry_failure else 'analyzed'
        return {'findings': output, 'evidence': [{'id': 'scan1', 'type': 'scanner_match'}], 'ai_usage': {'calls': 1},
                'errors': [{'stage': 'ai', 'message': 'temporary outage'}] if self.retry_failure else []}


@pytest.fixture
def runtime(tmp_path):
    config = Settings(database_url='sqlite:///:memory:', state_dir=tmp_path, jobs_enabled=False,
                      bootstrap_token='test-admin', ai_enabled=True, ai_model='fixture-model', ai_api_key='fixture-key')
    instance = Runtime(config, pipeline_factory=PipelineFixture)
    yield instance
    instance.stop()


def enqueue(runtime, kind, args):
    item = runtime.enqueue(kind, args)
    return runtime.store.claim()


def register_device(runtime):
    components = [{'component_id': 'host:openssl', 'scope': 'host', 'name': 'openssl', 'version': '3.0.1-1',
                   'architecture': 'amd64', 'distro': {'id': 'debian', 'version_id': '12'}}]
    envelope = {'device_id': 'leaf1', 'epoch': 'one', 'sequence': 1, 'kind': 'checkpoint', 'build_id': 'build-a',
                'inventory_digest': inventory_hash(components), 'components': components, 'collected_at': '2026-09-29T00:00:00Z'}
    runtime.store.sync(envelope, {'role': 'admin', 'id': 'fixture'})
    device = runtime.store.device('leaf1')
    result = runtime.pipeline.analyze(runtime.to_inventory(device), {})
    result['findings'][0]['assessment_state'] = 'retry_needed'
    result['errors'] = [{'stage': 'ai', 'message': 'temporary outage'}]
    runtime.store.store_findings('leaf1', device['inventory_digest'], result, 'initial')
    return envelope, result


def test_retry_identity_ignores_action_receipt_but_preserves_inventory_quality(runtime):
    register_device(runtime)
    device=runtime.store.device('leaf1')
    before=retry_identity(runtime,device)
    receipt={'collector':'remediation','status':'complete','value':{'status':'staged'}}
    device['facts']=[receipt]
    assert retry_identity(runtime,device)==before
    device['facts'].append({'collector':'inventory','status':'unknown'})
    assert retry_identity(runtime,device)!=before


def test_release_upload_is_actually_scanned_and_findings_persist(runtime):
    inventory = normalize_inventory({'scopes': [{'id': 'host', 'components': [{'id': 'openssl', 'name': 'openssl',
        'version': '3.0.1-1', 'ecosystem': 'deb', 'properties': {'smart-patch:distro:name': 'debian', 'smart-patch:distro:version': '12'}}]}]})
    document = scope_to_sbom(inventory['scopes'][0])
    artifact = stable_hash(document)
    runtime.store.put('artifact', artifact, {'sbom': document})
    runtime.store.put('release', 'custom:test', {'release_id': 'custom:test', 'artifact_id': artifact})
    result = runtime._job_release_sync(enqueue(runtime, 'release_sync', {'release_id': 'custom:test'}))
    assert result['findings_count'] == 1
    assert len(runtime.pipeline.calls) == 1
    assert runtime.pipeline.calls[0][1]['artifact_verified'] is False
    row = runtime.store.list('release_finding')[0]
    assert row['artifact_id'] == artifact and row['evidence'][0]['id'] == 'scan1'
    package_cve = runtime.store.list('package_cve')[0]
    assert package_cve['available_fix_versions'] == ['3.0.2-1']
    assert package_cve['latest_available_version'] is None
    history=runtime.store.list('release_assessment_history',owner=row['id'])
    assert len(history)==1 and history[0]['assessment_revision']==result['assessment_revision']
    assert runtime.store.get('evidence_snapshot',history[0]['evidence_digests'][0])==row['evidence'][0]


def test_source_clone_registers_only_explicit_pin(runtime):
    runtime.store.put('release', 'custom:test', {'release_id': 'custom:test', 'source_url': 'https://github.com/sonic-net/sonic-buildimage',
        'source_revision': 'a' * 40, 'branch': 'master'})
    class Source:
        def __init__(self, url, path):
            self.path = Path(path)
            self.resolved_commit = 'a' * 40
        def clone_repo(self, branch, commit):
            self.path.mkdir(parents=True)
            assert commit == 'a' * 40
            return True
    with patch('app.services.release_service.GitHubSync', Source):
        result = runtime._job_source_clone(enqueue(runtime, 'source_clone', {'release_id': 'custom:test'}))
    assert result['resolved_commit'] == 'a' * 40
    assert result['source_root'] in runtime.configuration()['source_roots']
    assert result['artifact_verified'] is False


def test_source_clone_without_commit_rejected(runtime):
    runtime.store.put('release', 'custom:test', {'release_id': 'custom:test', 'branch': 'master'})
    with pytest.raises(ValueError, match='pinned commit'):
        runtime._job_source_clone(enqueue(runtime, 'source_clone', {'release_id': 'custom:test'}))


def test_release_sync_preserves_uploaded_raw_digest(runtime):
    document = scope_to_sbom(normalize_inventory({'scopes': [{'id': 'host', 'components': [{'id': 'openssl', 'name': 'openssl',
        'version': '3.0.1-1', 'ecosystem': 'deb', 'arch': 'amd64', 'properties': {'smart-patch:distro:name': 'debian', 'smart-patch:distro:version': '12'}}]}]})['scopes'][0])
    artifact = stable_hash(document)
    runtime.store.put('artifact', artifact, {'sbom': document, 'source_sha256': 'a' * 64})
    runtime.store.put('release', 'custom:raw', {'release_id': 'custom:raw', 'artifact_id': artifact})
    runtime._job_release_sync(enqueue(runtime, 'release_sync', {'release_id': 'custom:raw'}))
    assert runtime.store.get('artifact', artifact)['source_sha256'] == 'a' * 64


def test_canonical_same_but_raw_changed_invalidates_binding(runtime, tmp_path):
    import hashlib
    document = scope_to_sbom(normalize_inventory({'scopes': [{'id': 'host', 'components': [{'id': 'openssl', 'name': 'openssl',
        'version': '3.0.1-1', 'ecosystem': 'deb', 'arch': 'amd64', 'properties': {'smart-patch:distro:name': 'debian', 'smart-patch:distro:version': '12'}}]}]})['scopes'][0])
    artifact = stable_hash(document)
    path = tmp_path / 'changed.json'
    raw = json.dumps(document, indent=3).encode()
    path.write_bytes(raw)
    runtime.store.put('artifact', artifact, {'sbom': document, 'source_sha256': 'a' * 64, 'verification': 'signature_verified'})
    runtime.store.put('build_binding', 'build-a', {'build_id': 'build-a', 'artifact_id': artifact, 'verification': 'signature_verified'})
    runtime.store.put('release', 'custom:raw', {'release_id': 'custom:raw', 'sbom_source': str(path)})
    runtime._job_release_sync(enqueue(runtime, 'release_sync', {'release_id': 'custom:raw'}))
    assert runtime.store.get('artifact', artifact)['source_sha256'] == hashlib.sha256(raw).hexdigest()
    assert runtime.store.get('artifact', artifact)['verification'] == 'unverified'
    assert runtime.store.get('build_binding', 'build-a')['verification'] == 'source_changed'


def test_retry_is_bounded_backoff_and_reuses_matching(runtime):
    envelope, result = register_device(runtime)
    device = runtime.store.device('leaf1')
    runtime.schedule_analysis_retry(device, result, {})
    record = runtime.store.list('analysis_retry')[0]
    for attempt in range(1, 6):
        operation = enqueue(runtime, 'retry_analysis', {'device_id': 'leaf1', 'retry_id': record['id']})
        response = runtime._job_retry_analysis(operation)
        runtime.store.update_operation(operation['id'], 'completed')
        assert response['retry_attempt'] == attempt
        saved = runtime.store.get('analysis_retry', record['id'])
        assert datetime.fromisoformat(saved['next_attempt_at']) > datetime.now(timezone.utc)
    assert saved['status'] == 'exhausted'
    assert len(runtime.pipeline.calls) == 1  # only original match; retries do not rerun Grype
    assert len(runtime.pipeline.retry_calls) == 5
    response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'device_id': 'leaf1', 'retry_id': record['id']}))
    assert response['retry_state'] == 'exhausted'
    assert len(runtime.pipeline.retry_calls) == 5


def test_retry_does_not_apply_to_new_epoch(runtime):
    envelope, result = register_device(runtime)
    runtime.schedule_analysis_retry(runtime.store.device('leaf1'), result, {})
    record = runtime.store.list('analysis_retry')[0]
    runtime.store.sync({**envelope, 'epoch': 'two'}, {'role': 'admin', 'id': 'fixture'})
    response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'device_id': 'leaf1', 'retry_id': record['id']}))
    assert response['retry_state'] == 'superseded'
    assert runtime.pipeline.retry_calls == []


def test_retry_identity_includes_binding_and_rejects_changed_artifact(runtime):
    _, result = register_device(runtime)
    device = runtime.store.device('leaf1')
    identity = retry_identity(runtime, device)
    assert identity['artifact_id'] is None
    assert identity['artifact_verified'] is False
    assert identity['binding_revision'] == 'unverified'
    runtime.schedule_analysis_retry(device, result, identity)
    record = runtime.store.list('analysis_retry')[0]
    runtime.store.update_device('leaf1', {'artifact_id': 'artifact-new', 'artifact_verified': True, 'binding_revision': 'signed-new'})
    response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'device_id': 'leaf1', 'retry_id': record['id']}))
    assert response['retry_state'] == 'superseded'
    assert runtime.pipeline.retry_calls == []


def test_binding_change_during_retry_rejects_result(runtime):
    _, result = register_device(runtime)
    runtime.schedule_analysis_retry(runtime.store.device('leaf1'), result, {})
    record = runtime.store.list('analysis_retry')[0]
    original = runtime.pipeline.retry_findings
    def binding_changes(findings, context):
        output = original(findings, context)
        runtime.store.update_device('leaf1', {'binding_revision': 'revoked-during-analysis'})
        return output
    with patch.object(runtime.pipeline, 'retry_findings', side_effect=binding_changes):
        response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'device_id': 'leaf1', 'retry_id': record['id']}))
    assert response['accepted'] is False
    assert response['retry_state'] == 'superseded'


def test_successful_retry_updates_processing_state_and_keeps_unknown_verdict(runtime):
    _, result = register_device(runtime)
    runtime.schedule_analysis_retry(runtime.store.device('leaf1'), result, {})
    record = runtime.store.list('analysis_retry')[0]
    runtime.pipeline.retry_failure = False
    response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'device_id': 'leaf1', 'retry_id': record['id']}))
    assert response['retry_state'] == 'completed'
    finding = runtime.store.list('finding')[0]
    assert finding['assessment_state'] == 'analyzed'
    assert finding['applicability'] == 'under_investigation'


def test_scheduler_waits_until_retry_due(runtime):
    _, result = register_device(runtime)
    runtime.schedule_analysis_retry(runtime.store.device('leaf1'), result, {})
    record = runtime.store.list('analysis_retry')[0]
    advance_retry_schedule(runtime)
    assert runtime.store.operations() == []
    runtime.store.put('analysis_retry', record['id'], {**record, 'next_attempt_at': (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()}, 'leaf1')
    advance_retry_schedule(runtime)
    assert runtime.store.operations()[0]['operation_type'] == 'retry_analysis'


def test_release_retry_reuses_evidence_and_preserves_artifact_scope(runtime):
    release = {'release_id': 'custom:test', 'artifact_id': 'artifact1', 'scanner': {'db_revision': 'db1'}}
    runtime.store.put('release', release['release_id'], release)
    finding = {'id': 'f1', 'release_id': release['release_id'], 'artifact_id': 'artifact1',
               'status': 'current', 'assessment_state': 'retry_needed', 'applicability': 'under_investigation',
               'evidence': [{'id': 'scan1'}], 'evidence_ids': ['scan1']}
    runtime.store.put('release_finding', 'f1', finding, release['release_id'])
    advance_release_retries(runtime)
    record = runtime.store.list('release_analysis_retry')[0]
    operation = enqueue(runtime, 'retry_analysis', {'release_id': release['release_id'], 'retry_id': record['id']})
    response = runtime._job_retry_analysis(operation)
    runtime.store.update_operation(operation['id'], 'completed')
    assert response['retry_state'] == 'retry_needed'
    runtime.pipeline.retry_failure = False
    response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'release_id': release['release_id'], 'retry_id': record['id']}))
    assert response['retry_state'] == 'completed'
    assert runtime.pipeline.calls == []
    assert runtime.store.get('release_finding', 'f1')['artifact_id'] == 'artifact1'
    histories=runtime.store.list('release_assessment_history',owner='f1')
    assert len(histories)==2
    assert {history['assessment_kind'] for history in histories}=={'ai_retry'}
    assert len({history['assessment_revision'] for history in histories})==2


@pytest.mark.parametrize('change',['release_source','provider','review','advisory_generation'])
def test_release_scan_rejects_results_when_source_or_policy_changes_in_flight(runtime,change):
    document=scope_to_sbom(normalize_inventory({'scopes':[{'id':'host','components':[{
        'id':'test','name':'test','version':'1.0','ecosystem':'deb'}]}]})['scopes'][0])
    artifact=stable_hash(document)
    runtime.store.put('artifact',artifact,{'sbom':document})
    release={'release_id':'custom:guard','artifact_id':artifact,'source_revision':'original'}
    runtime.store.put('release',release['release_id'],release)
    original=runtime.pipeline.analyze
    def changed(inventory,context):
        output=original(inventory,context)
        if change=='release_source':runtime.store.put('release',release['release_id'],{**release,'source_revision':'replacement'})
        elif change=='provider':runtime.save_configuration({'ai_model':'new-model'})
        elif change=='review':runtime.store.put('reviewed_assessment','new-review',{'id':'new-review'})
        else:runtime.advisory_generation+=1
        return output
    with patch.object(runtime.pipeline,'analyze',side_effect=changed):
        response=runtime._job_release_sync(enqueue(runtime,'release_sync',{'release_id':release['release_id']}))
    assert response['accepted'] is False and response['status']=='superseded'
    assert runtime.store.list('release_assessment_history')==[]
    assert runtime.store.list('release_finding')==[]
    assert runtime.store.list('package')==[]


@pytest.mark.parametrize('change',['provider','artifact'])
def test_release_commit_to_seed_race_cannot_rebind_saved_work_to_new_context(runtime,change):
    from app.services.release_history import commit_release_assessment
    document=scope_to_sbom(normalize_inventory({'scopes':[{'id':'host','components':[{
        'id':'test','name':'test','version':'1.0','ecosystem':'deb'}]}]})['scopes'][0])
    artifact=stable_hash(document)
    runtime.store.put('artifact',artifact,{'sbom':document})
    runtime.store.put('release','custom:seed-race',{'release_id':'custom:seed-race','artifact_id':artifact})
    original=runtime.pipeline.analyze
    def managed(inventory,context):
        output=original(inventory,context)
        output['findings'][0].update(analysis_managed=True,assessment_state='pending_analysis',analysis_attempts=0)
        return output
    def commit_then_change(*args,**kwargs):
        accepted=commit_release_assessment(*args,**kwargs)
        assert accepted
        if change=='provider':runtime.save_configuration({'ai_model':'replacement-model'})
        else:
            release=runtime.store.get('release','custom:seed-race')
            runtime.store.put('release','custom:seed-race',{**release,'artifact_id':'replacement-artifact'})
        return accepted
    with patch.object(runtime.pipeline,'analyze',side_effect=managed),patch('app.services.release_service.commit_release_assessment',side_effect=commit_then_change):
        response=runtime._job_release_sync(enqueue(runtime,'release_sync',{'release_id':'custom:seed-race'}))
    assert response['accepted'] is True  # The preceding commit was valid.
    assert runtime.store.list('analysis_work')==[]
    assert runtime.store.list('analysis_backlog')==[]


def test_release_seed_binds_newly_observed_scanner_revision(runtime):
    document=scope_to_sbom(normalize_inventory({'scopes':[{'id':'host','components':[{
        'id':'test','name':'test','version':'1.0','ecosystem':'deb'}]}]})['scopes'][0])
    artifact=stable_hash(document)
    runtime.store.put('artifact',artifact,{'sbom':document})
    runtime.store.put('release','custom:new-db',{'release_id':'custom:new-db','artifact_id':artifact,'scanner':{'db_revision':'old-db'}})
    original=runtime.pipeline.analyze
    def managed(inventory,context):
        output=original(inventory,context)
        output['findings'][0].update(analysis_managed=True,assessment_state='pending_analysis',analysis_attempts=0)
        return output
    with patch.object(runtime.pipeline,'analyze',side_effect=managed):
        response=runtime._job_release_sync(enqueue(runtime,'release_sync',{'release_id':'custom:new-db'}))
    assert response['accepted']
    work=runtime.store.list('analysis_work')[0]
    assert work['expected_identity']['advisory_revision']=='db1'
    assert work['expected_identity']['artifact_id']==artifact


def test_release_retry_rejects_replaced_artifact(runtime):
    release = {'release_id': 'custom:test', 'artifact_id': 'artifact1'}
    runtime.store.put('release', release['release_id'], release)
    runtime.store.put('release_finding', 'f1', {'id': 'f1', 'status': 'current', 'assessment_state': 'retry_needed'}, release['release_id'])
    advance_release_retries(runtime)
    record = runtime.store.list('release_analysis_retry')[0]
    runtime.store.put('release', release['release_id'], {**release, 'artifact_id': 'artifact2'})
    response = runtime._job_retry_analysis(enqueue(runtime, 'retry_analysis', {'release_id': release['release_id'], 'retry_id': record['id']}))
    assert response['retry_state'] == 'superseded'
    assert runtime.pipeline.retry_calls == []
