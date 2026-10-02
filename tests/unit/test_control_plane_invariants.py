"""Cross-layer invariants: agent identity, durable state and assessment freshness."""
import copy
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from app.api.models import SyncEnvelope
from app.config import Settings
from app.db.store import Store, inventory_hash, stable_hash
from app.main import create_app
from app.runtime import Runtime
from app.services.assessment import AssessmentEngine
from app.services.pipeline import AnalysisPipeline


def component(scope='host', version='3.0.1-1'):
    return {'component_id': f'{scope}:openssl', 'scope': scope, 'name': 'openssl', 'version': version,
            'architecture': 'amd64', 'source_name': 'openssl', 'source_version': version,
            'distro': {'id': 'debian', 'version_id': '12.9', 'codename': 'bookworm'}}


def checkpoint(device='leaf1', epoch='epoch1', sequence=1, components=None):
    components = [component()] if components is None else components
    return {'schema_version': 1, 'device_id': device, 'hostname': device,
            'sonic_version': 'master.0-abcdef1', 'build_id': 'build-a', 'epoch': epoch,
            'sequence': sequence, 'kind': 'checkpoint', 'inventory_digest': inventory_hash(components),
            'collected_at': '2026-09-29T00:00:00Z', 'components': components}


@pytest.fixture
def store():
    value = Store('sqlite:///:memory:')
    yield value
    value.close()


def agent(store, device_id=None):
    issued = store.issue_token('test agent', 'agent', device_id)
    return store.authenticate(issued['token'])


def test_token_usage_writes_coalesce_but_revocation_is_immediate(store):
    token=store.issue_token('usage bookkeeping fixture','operator')
    assert store.authenticate(token['token'])
    first=store.tokens()[0]['last_used_at']
    for _ in range(5):assert store.authenticate(token['token'])
    assert store.tokens()[0]['last_used_at']==first
    store.revoke(token['token_id'])
    assert store.authenticate(token['token']) is None


def test_operator_cannot_impersonate_a_collector(store):
    token=store.issue_token('operator fixture','operator')
    with pytest.raises(PermissionError,match='credentials'):
        store.sync(checkpoint(),store.authenticate(token['token']))
    assert store.devices()==[]


def enqueue_scan(runtime, device='leaf1'):
    operation = runtime.schedule_scan(device)
    return runtime.store.claim()


class RecordingPipeline:
    def __init__(self, *args):
        self.calls = []
        self.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'})
    def analyze(self, inventory, context):
        self.calls.append((copy.deepcopy(inventory), copy.deepcopy(context)))
        return {'findings': [], 'evidence': [], 'coverage': {'complete': True, 'scopes_total': len(inventory['scopes']),
                 'scopes_scanned': len(inventory['scopes']), 'components_total': 1, 'errors': []},
                'scanner': {'status': 'complete', 'db_revision': 'db1'}, 'errors': [], 'ai_usage': {}}


@pytest.fixture
def runtime(tmp_path):
    config = Settings(database_url='sqlite:///:memory:', state_dir=tmp_path, jobs_enabled=False,
                      source_roots=[], bootstrap_token='test-bootstrap-value')
    value = Runtime(config, pipeline_factory=RecordingPipeline)
    yield value
    value.stop()


def test_sync_durable_ack_duplicate_gap_and_bad_digest(store):
    identity = agent(store)
    original = checkpoint()
    result, changed = store.sync(original, identity)
    assert result == {'ack_sequence': 1, 'resync_required': False} and changed
    assert store.authenticate(store.issue_token('bound', 'agent', 'leaf1')['token'])['device_id'] == 'leaf1'
    again, changed = store.sync(original, identity)
    assert again['ack_sequence'] == 1 and not changed
    delta = {**original, 'kind': 'delta', 'sequence': 3, 'components': []}
    result, changed = store.sync(delta, identity)
    assert result['resync_required'] and not changed
    assert store.device('leaf1')['last_sequence'] == 1
    corrupt = {**original, 'kind': 'delta', 'sequence': 2, 'inventory_digest': '0' * 64}
    with pytest.raises(ValueError, match='digest'):
        store.sync(corrupt, identity)
    assert store.device('leaf1')['last_sequence'] == 1


def test_committed_inventory_is_recovered_after_api_stops_before_enqueue(runtime):
    identity=agent(runtime.store)
    envelope=checkpoint()
    runtime.store.sync(envelope,identity)
    assert not runtime.store.operations()
    # The exact retry is acknowledged without treating it as new inventory.
    _,changed=runtime.store.sync(envelope,identity)
    assert changed is False
    recovered=runtime.recover_pending_scans()
    assert len(recovered)==1
    assert recovered[0]['arguments']['device_id']=='leaf1'
    assert runtime.store.device('leaf1')['scan_status']=='queued'
    assert runtime.recover_pending_scans()==[]
    assert len(runtime.store.operations())==1


def test_enqueue_before_status_update_is_recovered_without_duplicate_work(runtime,monkeypatch):
    runtime.store.sync(checkpoint(),agent(runtime.store))
    original=runtime.store.update_device
    def stopped(*args,**kwargs):
        raise RuntimeError('simulated API process stop after durable enqueue')
    monkeypatch.setattr(runtime.store,'update_device',stopped)
    with pytest.raises(RuntimeError,match='process stop'):
        runtime.schedule_scan('leaf1')
    assert runtime.store.device('leaf1')['scan_status']=='pending'
    queued=runtime.store.operations()[0]
    monkeypatch.setattr(runtime.store,'update_device',original)
    recovered=runtime.recover_pending_scans()
    assert recovered[0]['id']==queued['id']
    assert len(runtime.store.operations())==1


def test_assessment_history_preserves_same_verdict_with_changed_evidence(store):
    envelope=checkpoint();store.sync(envelope,agent(store))
    candidate={'component_id':component()['component_id'],'scope_id':'host','package_name':'openssl',
               'affected_version':component()['version'],'cve_id':'CVE-TEST-HISTORY','severity':'HIGH',
               'applicability':'under_investigation','evidence_ids':['same-external-id']}
    for revision,value in [('r1','initial advisory'),('r2','corrected advisory')]:
        result={'findings':[candidate],'coverage':{'complete':True},'source_revision':'a'*40,
                'evidence':[{'id':'same-external-id','data':{'text':value}}]}
        assert store.store_findings('leaf1',envelope['inventory_digest'],result,revision)
    current=store.list('finding',owner='leaf1')[0]
    history=store.list('assessment_history',owner=current['id'])
    assert {row['assessment_revision'] for row in history}=={'r1','r2'}
    texts={store.get('evidence_snapshot',row['evidence_digests'][0])['data']['text'] for row in history}
    assert texts=={'initial advisory','corrected advisory'}
    assert store.query_findings()['total']==1


def test_saved_evidence_subset_updates_only_selected_finding_and_preserves_scan_freshness(store):
    from sqlalchemy import event
    envelope=checkpoint();store.sync(envelope,agent(store))
    candidates=[{'component_id':component()['component_id'],'scope_id':'host','package_name':'openssl',
        'affected_version':component()['version'],'cve_id':f'CVE-2026-{1000+i}','severity':'HIGH',
        'applicability':'under_investigation','evidence_ids':['scanner']} for i in range(4)]
    original={'findings':candidates,'coverage':{'complete':True},'scanner':{'db_revision':'db1'},
              'evidence':[{'id':'scanner','data':{'text':'original exact scanner observation'}}]}
    assert store.store_findings('leaf1',envelope['inventory_digest'],original,'scan-r1')
    findings=store.list('finding',owner='leaf1');chosen=findings[0];before=store.device('leaf1')
    untouched={row['id']:row for row in findings[1:]}
    def guard(_session,instance):
        from app.db.store import Record
        if isinstance(instance,Record) and instance.kind=='finding':assert instance.id==chosen['id']
    event.listen(store.sessions,'loaded_as_persistent',guard)
    try:
        assert store.store_findings('leaf1',envelope['inventory_digest'],{
            'findings':[{**chosen,'assessment_state':'analyzed','analysis_attempts':1,'analysis_success':True}],
            'coverage':{'complete':True},'scanner':{'db_revision':'must-not-replace-scan'}},'analysis-r2',
            expected_identity={'assessment_revision':'scan-r1'},complete_scan=False,assessment_kind='ai_backlog')
    finally:event.remove(store.sessions,'loaded_as_persistent',guard)
    current=store.device('leaf1')
    for field in ('last_scan_at','scan_status','coverage','scanner'):assert current[field]==before[field]
    assert current['assessment_revision']=='analysis-r2'
    assert len(store.list('assessment_history'))==5
    assert store.get('finding_summary',chosen['id'])['analysis_success'] is True
    for ident,row in untouched.items():assert store.get('finding',ident)==row
    assert not store.store_findings('leaf1',envelope['inventory_digest'],{'findings':[chosen]},'stale-r3',
        expected_identity={'assessment_revision':'scan-r1'},complete_scan=False,assessment_kind='ai_backlog')


def test_scan_started_before_operator_review_cannot_commit_over_it(runtime):
    envelope=checkpoint();runtime.store.sync(envelope,agent(runtime.store))
    original=runtime.pipeline.analyze
    def reviewed_during_scan(inventory,context):
        runtime.store.update_device('leaf1',{'review_revision':'review-recorded-during-scan'})
        return original(inventory,context)
    runtime.pipeline.analyze=reviewed_during_scan
    operation=enqueue_scan(runtime)
    result=runtime._job_scan(operation)
    assert result['accepted'] is False
    assert runtime.store.device('leaf1').get('assessment_revision') is None


@pytest.mark.parametrize('collector,accepted', [('remediation',True),('maintenance_action',True),
                                              ('inventory',False),('listeners',False)])
def test_inflight_scan_ignores_receipts_but_guards_collection_quality_and_runtime_evidence(runtime,collector,accepted):
    identity=agent(runtime.store);envelope=checkpoint()
    runtime.store.sync(envelope,identity)
    original=runtime.pipeline.analyze
    fact={'collector':collector,'status':'unknown','collected_at':datetime.now(timezone.utc).isoformat(),
          'value':{'action':'stage_plan','status':'staged'}}
    def receipt_during_scan(inventory,context):
        _,changed=runtime.store.sync({**envelope,'kind':'heartbeat','components':[],'facts':[fact]},identity)
        assert changed is (not accepted)
        return original(inventory,context)
    runtime.pipeline.analyze=receipt_during_scan
    operation=enqueue_scan(runtime)
    assert runtime._job_scan(operation)['accepted'] is accepted
    if accepted:
        runtime.store.update_operation(operation['id'],'completed')
        runtime.pipeline.analyze=original
        repeated=enqueue_scan(runtime)
        assert runtime._job_scan(repeated)['accepted'] is True
        assert len(runtime.pipeline.calls)==1  # action-only changes also reuse the full assessment cache


def test_ruleset_upgrade_marks_existing_inventory_pending_once(runtime):
    envelope=checkpoint();runtime.store.sync(envelope,agent(runtime.store))
    runtime.store.update_device('leaf1',{'scan_status':'completed'})
    assert runtime.ensure_ruleset_current()==['leaf1']
    from app.services.assessment import RULESET_VERSION
    device=runtime.store.device('leaf1')
    assert device['assessment_ruleset_version']==RULESET_VERSION and device['scan_status']=='pending'
    assert runtime.ensure_ruleset_current()==[]
    recovered=runtime.recover_pending_scans()
    assert len(recovered)==1 and recovered[0]['operation_type']=='scan'


def test_delta_removal_reconstructs_scope_exact_inventory(store):
    identity = agent(store)
    host, bgp = component(), component('bgp')
    original = checkpoint(components=[host, bgp])
    store.sync(original, identity)
    delta = {**original, 'kind': 'delta', 'sequence': 2, 'components': [], 'removed': [host['component_id']],
             'inventory_digest': inventory_hash([bgp])}
    store.sync(delta, identity)
    assert store.device('leaf1')['components'] == [bgp]


def test_sequence_reuse_with_different_payload_is_rejected(store):
    identity = agent(store)
    source = checkpoint()
    store.sync(source, identity)
    with pytest.raises(ValueError, match='different content'):
        store.sync({**source, 'hostname': 'changed'}, identity)


def test_retired_epoch_replay_requires_resync(store):
    identity = agent(store)
    original = checkpoint()
    store.sync(original, identity)
    store.sync(checkpoint(epoch='epoch2'), identity)
    result, changed = store.sync(original, identity)
    assert result['resync_required'] and not changed
    assert store.device('leaf1')['epoch'] == 'epoch2'


def test_agent_cannot_forge_artifact_verification(store):
    source = checkpoint()
    source['artifact_verified'] = True
    store.sync(source, agent(store))
    assert store.device('leaf1')['artifact_verified'] is False


def test_unbound_new_token_cannot_take_over_existing_device(store):
    store.sync(checkpoint(), agent(store))
    attacker = agent(store)
    with pytest.raises(PermissionError):
        store.sync(checkpoint(epoch='attacker-epoch'), attacker)
    assert store.device('leaf1')['epoch'] == 'epoch1'


def test_explicitly_bound_wrong_device_token_is_rejected(store):
    with pytest.raises(PermissionError):
        store.sync(checkpoint('leaf2'), agent(store, 'leaf1'))


def test_token_values_never_listed_and_revocation_is_enforced(store):
    issued = store.issue_token('agent', 'agent')
    assert issued['token'] not in json.dumps(store.tokens())
    assert store.authenticate(issued['token'])
    store.revoke(issued['token_id'])
    assert store.authenticate(issued['token']) is None


def test_jobs_deduplicate_only_active_work_and_recover(store):
    first = store.enqueue('scan', {'device_id': 'leaf1'}, 'same')
    assert store.enqueue('scan', {'device_id': 'leaf1'}, 'same')['id'] == first['id']
    assert store.claim()['status'] == 'in_progress'
    assert store.operation(first['id'])['attempts'] == 1
    store.recover_jobs()
    assert store.operation(first['id'])['status'] == 'queued'
    assert store.claim()['attempts'] == 2
    store.update_operation(first['id'], 'completed', result={'coverage': {'complete': True}})
    assert store.enqueue('scan', {'device_id': 'leaf1'}, 'same')['id'] != first['id']
    assert store.operation('missing') is None


def report(scope='host'):
    return {'findings': [{'cve_id': 'CVE-2026-1234', 'component_id': f'{scope}:openssl', 'scope_id': scope,
                         'package_name': 'openssl', 'affected_version': '3.0.1-1', 'applicability': 'under_investigation',
                         'evidence_ids': ['scan1'], 'severity': 'HIGH'}],
            'evidence': [{'id': 'scan1', 'type': 'scanner_match', 'data': {'real': 'fixture'}}],
            'coverage': {'complete': True}, 'scanner': {'db_revision': 'db1'}, 'errors': []}


def test_same_cve_in_two_scopes_stays_two_findings(store):
    source = checkpoint(components=[component(), component('bgp')])
    store.sync(source, agent(store))
    result = report()
    result['findings'].extend(report('bgp')['findings'])
    assert store.store_findings('leaf1', source['inventory_digest'], result, 'revision1')
    findings = store.list('finding', owner='leaf1')
    assert len(findings) == 2
    assert {f['scope'] for f in findings} == {'host', 'bgp'}
    assert all(f['evidence'][0]['id'] == 'scan1' for f in findings)


def test_partial_scan_does_not_remove_unresolved_findings(store):
    source = checkpoint()
    store.sync(source, agent(store))
    store.store_findings('leaf1', source['inventory_digest'], report(), 'first')
    store.store_findings('leaf1', source['inventory_digest'], {'findings': [], 'coverage': {'complete': False}}, 'second')
    assert store.list('finding')[0]['status'] == 'current'
    assert store.device('leaf1')['scan_status'] == 'partial'


def test_changed_inventory_rejects_inflight_results(store):
    identity = agent(store)
    original = checkpoint()
    store.sync(original, identity)
    changed = checkpoint(sequence=2, components=[component(version='3.0.2-1')])
    store.sync(changed, identity)
    assert store.store_findings('leaf1', original['inventory_digest'], report(), 'old-revision') is False
    assert store.list('finding') == []


def test_same_inventory_new_epoch_rejects_inflight_context(store):
    identity = agent(store)
    original = checkpoint()
    store.sync(original, identity)
    snapshot = store.device('leaf1')
    expected = {'epoch': snapshot['epoch'], 'build_id': snapshot.get('build_id'),
                'baseline_digest': snapshot.get('baseline_digest'), 'manifest_digest': stable_hash(snapshot.get('manifest', {})),
                'facts_digest': stable_hash(snapshot.get('facts', []))}
    store.sync({**original, 'epoch': 'epoch2'}, identity)
    assert not store.store_findings('leaf1', original['inventory_digest'], report(), 'old-revision', expected_identity=expected)
    assert store.list('finding') == []


def test_multiple_scanner_sources_merge_without_losing_evidence():
    from app.services.pipeline import merge_candidate_matches
    item = report()['findings'][0]
    item.update(advisory_namespace='nvd:cpe', match_details=[{'type': 'cpe-match'}],
                fixed_versions=[], distro={'name': 'debian', 'version': '12'})
    distro = {**item, 'advisory_namespace': 'debian:distro:debian:12',
              'evidence_ids': ['scan2'], 'match_details': [{'type': 'exact-direct-match'}], 'fixed_versions': ['3.0.2-1']}
    result = merge_candidate_matches([item, distro])
    assert len(result) == 1
    assert result[0]['evidence_ids'] == ['scan1', 'scan2']
    assert result[0]['fixed_versions'] == ['3.0.2-1']


def test_cache_reused_only_for_same_build_and_advisory(runtime):
    identity = agent(runtime.store)
    original = checkpoint()
    runtime.store.sync(original, identity)
    first = enqueue_scan(runtime)
    runtime._job_scan(first)
    runtime.store.update_operation(first['id'], 'completed')
    second = enqueue_scan(runtime)
    runtime._job_scan(second)
    runtime.store.update_operation(second['id'], 'completed')
    assert len(runtime.pipeline.calls) == 1
    # The package hash is identical, but a different image can carry different patches.
    runtime.store.sync({**original, 'epoch': 'epoch2', 'build_id': 'build-b'}, identity)
    third = enqueue_scan(runtime)
    runtime._job_scan(third)
    assert len(runtime.pipeline.calls) == 2


def test_expired_context_does_not_reuse_cached_exposure(runtime):
    identity = agent(runtime.store)
    source = checkpoint()
    source['facts'] = [{'name': 'exposure', 'scope_id': 'host', 'component_id': 'host:openssl',
                        'collected_at': datetime.now(timezone.utc).isoformat(), 'ttl_seconds': 1,
                        'value': 'constrained', 'status': 'observed', 'inventory_digest': source['inventory_digest']}]
    runtime.store.sync(source, identity)
    first = enqueue_scan(runtime)
    runtime._job_scan(first)
    runtime.store.update_operation(first['id'], 'completed')
    with patch('app.runtime.age_seconds', return_value=5):
        runtime._job_scan(enqueue_scan(runtime))
    assert len(runtime.pipeline.calls) == 2


def test_new_advisory_generation_queues_distinct_work_and_rejects_old_scan(runtime):
    runtime.store.sync(checkpoint(), agent(runtime.store))
    old = enqueue_scan(runtime)
    original = runtime.pipeline.analyze
    queued = []
    def advisory_arrives(inventory, context):
        result = original(inventory, context)
        runtime.advisory_generation += 1
        runtime.scanner_info = {'status': 'ready', 'db_revision': 'db-new'}
        queued.append(runtime.schedule_scan('leaf1'))
        return result
    with patch.object(runtime.pipeline, 'analyze', side_effect=advisory_arrives):
        result = runtime._job_scan(old)
    assert result['accepted'] is False
    assert queued[0]['id'] != old['id']
    assert queued[0]['arguments']['advisory_generation'] == 1
    assert queued[0]['arguments']['required_db_revision'] == 'db-new'
    assert runtime.store.operation(queued[0]['id'])['status'] == 'queued'
    assert runtime.store.device('leaf1').get('assessment_revision') is None


def test_wire_fields_preserve_identity_and_normalize_debian_release():
    source = checkpoint(components=[component(), component('bgp')])
    parsed = SyncEnvelope.model_validate(source).model_dump(exclude_unset=True)
    assert inventory_hash(parsed['components']) == source['inventory_digest']
    normalized = Runtime.to_inventory(parsed)
    assert [scope['distro']['version'] for scope in normalized['scopes']] == ['12', '12']
    assert {p['id'] for scope in normalized['scopes'] for p in scope['components']} == {'host:openssl', 'bgp:openssl'}


def test_compatibility_api_claims_cannot_create_verified_verdict():
    item = {'cve_id': 'CVE-2026-1234', 'package_name': 'openssl', 'affected_version': '3.0.1-1',
            'cvss_score': 8.0, 'scope_id': 'host', 'component_id': 'host:openssl',
            'match_details': [{'type': 'exact-direct-match'}], 'advisory_namespace': 'debian:distro:debian:12',
            'distro': {'name': 'debian', 'version': '12'}}
    result = AssessmentEngine().assess([item], 'build-a', {'artifact_verified': True})
    assert result['recommendations'][0]['applicability'] == 'under_investigation'
    assert result['recommendations'][0]['evidence_ids'] == []


def test_http_auth_roles_and_unknown_operation(tmp_path):
    config = Settings(database_url='sqlite:///:memory:', state_dir=tmp_path, jobs_enabled=False,
                      bootstrap_token='test-admin-secret', source_roots=[])
    app = create_app(config)
    with TestClient(app) as client:
        admin = {'Authorization': 'Bearer test-admin-secret'}
        issued = client.post('/api/v1/tokens', headers=admin, json={'description': 'agent', 'role': 'agent'}).json()
        headers = {'Authorization': 'Bearer ' + issued['token']}
        assert client.get('/api/v1/settings', headers=headers).status_code == 403
        assert client.get('/api/v1/tokens', headers=headers).status_code == 403
        assert client.get('/api/v1/settings', headers={'Authorization': 'Bearer bogus'}).status_code == 401
        assert client.get('/api/v1/operations/not-real', headers=admin).status_code == 404
        assert 'test-admin-secret' not in client.get('/api/v1/settings', headers=admin).text
        assert 'test-admin-secret' not in client.get('/api/v1/tokens', headers=admin).text


@pytest.mark.skipif(not os.getenv('SMART_PATCH_TEST_REAL_GRYPE'), reason='Opt-in real central Grype integration')
def test_real_grype_accepts_agent_wire():
    base = Path(__file__).resolve().parents[2]
    binary = base / '.tools/grype-0.112.0/grype'
    env = {'GRYPE_DB_CACHE_DIR': str(base / '.state/grype-db'), 'GRYPE_DB_AUTO_UPDATE': 'false'}
    pipeline = AnalysisPipeline(scanner_binary=str(binary), settings={'scanner_env': env, 'ai_enabled': False})
    source = checkpoint()
    result = pipeline.analyze(Runtime.to_inventory(source), {'inventory_digest': source['inventory_digest']})
    assert result['coverage']['complete'], result['errors']
    assert result['scanner']['version'] == '0.112.0'
    assert result['findings']
    assert all(f['component_id'] == 'host:openssl' for f in result['findings'])
    assert all(f['applicability'] == 'under_investigation' for f in result['findings'])
