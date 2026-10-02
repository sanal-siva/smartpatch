import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.db.store import inventory_hash
from app.runtime import Runtime
from app.services.analysis_lifecycle import advance_analysis_backlog, analysis_identity, seed_backlog
from app.services.pipeline import AnalysisPipeline
from tests.unit.test_analysis_services import finding


class Provider:
    def __init__(self):
        self.calls = []
        self.configured = True
        self.circuit_open = False
        self.failures = set()
        self.during = None
    def health(self):
        return {'configured': self.configured, 'circuit_open': self.circuit_open}
    def investigate(self, item, evidence, tools):
        self.calls.append((copy.deepcopy(item), copy.deepcopy(evidence)))
        if self.during:
            self.during(item)
        if item['cve_id'] in self.failures:
            return {'success': False, 'state': 'retry_needed', 'error': 'fixture provider outage', 'usage': {'calls': 1}}
        return {'success': True, 'state': 'analyzed', 'usage': {'calls': 1}, 'proposal': {
            'applicability': 'under_investigation', 'rationale': 'Source proof unavailable',
            'evidence_ids': ['scan-1'], 'unknowns': ['patch applicability']}}


class Factory:
    def __init__(self, count=4):
        self.provider = Provider()
        self.scans = 0
        self.count = count
    def __call__(self, roots, binary, settings):
        pipeline = AnalysisPipeline(roots, binary, {**settings, 'ai_max_findings': 1})
        pipeline.ai = self.provider
        def scan(scope):
            self.scans += 1
            candidates = [{**finding(), 'id': str(i), 'cve_id': f'CVE-2026-{1000+i}'} for i in range(self.count)]
            return {'findings': candidates, 'evidence': [{'id': 'scan-1', 'type': 'scanner_match', 'raw': {'exact': 'saved bytes'}}],
                    'scope_id': scope['id'], 'components_scanned': 1, 'missing_versions': [],
                    'scanner': {'version': 'fixture', 'database': {'checksum': 'db1'}}}
        pipeline.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'}, scan_scope=scan)
        return pipeline


def make_runtime(tmp_path, count=4, file_db=False):
    factory = Factory(count)
    settings = Settings(database_url='sqlite:///' + str(tmp_path / 'db.sqlite') if file_db else 'sqlite://',
                        state_dir=tmp_path, bootstrap_token='test-admin', jobs_enabled=False,
                        ai_enabled=True, ai_api_key='fixture-only', ai_model='fixture-model')
    runtime = Runtime(settings, pipeline_factory=factory)
    runtime.store.put('settings', 'service', {'ai_max_findings': 1})
    runtime.test_factory = factory
    return runtime


@pytest.fixture
def runtime(tmp_path):
    instance = make_runtime(tmp_path)
    yield instance
    instance.stop()


def register(runtime):
    components = [{'component_id': 'openssl-host', 'scope': 'host', 'name': 'openssl', 'version': '3.0.1-1',
                   'architecture': 'amd64', 'distro': {'id': 'debian', 'version_id': '12'}}]
    envelope = {'device_id': 'leaf1', 'epoch': 'one', 'sequence': 1, 'kind': 'checkpoint', 'build_id': 'build-a',
                'inventory_digest': inventory_hash(components), 'components': components,
                'collected_at': datetime.now(timezone.utc).isoformat()}
    runtime.store.sync(envelope, {'role': 'admin', 'id': 'fixture'})
    return envelope


def scan(runtime):
    operation = runtime.enqueue('scan', {'device_id': 'leaf1'})
    claimed = runtime.store.claim()
    assert claimed['id'] == operation['id']
    result = runtime._job_scan(claimed)
    runtime.store.update_operation(claimed['id'], 'completed', result=result)
    return result


def tick(runtime):
    queued = advance_analysis_backlog(runtime)
    if not queued:
        return None
    operation = runtime.store.claim()
    assert operation['operation_type'] == 'analysis_backlog'
    result = runtime._job_analysis_backlog(operation)
    runtime.store.update_operation(operation['id'], 'completed', result=result)
    return result


def test_all_initial_pending_states_are_durable_before_first_provider_call(runtime):
    register(runtime)
    observed = []
    def during(item):
        rows = runtime.store.list('analysis_lifecycle')
        observed.extend(rows)
        assert len(rows) == 4
        assert sum(row['assessment_state'] == 'pending_analysis' for row in rows) == 3
        assert sum(row['assessment_state'] == 'analyzing' for row in rows) == 1
    runtime.test_factory.provider.during = during
    scan(runtime)
    states = runtime.store.list('analysis_lifecycle')
    analyzed = next(row for row in states if row['assessment_state'] == 'analyzed')
    assert [event['state'] for event in analyzed['transitions']] == ['pending_analysis', 'analyzing', 'analyzed']
    assert analyzed['analysis_success'] is True
    assert runtime.store.operations()[0]['logs']
    assert observed


def test_automatic_backlog_covers_tail_without_grype_or_repeat_unknowns(runtime):
    register(runtime);scan(runtime)
    initial_calls = len(runtime.test_factory.provider.calls)
    assert initial_calls == 1
    for _ in range(4):
        tick(runtime)
    assert len(runtime.test_factory.provider.calls) == 4
    assert len({item['cve_id'] for item, _ in runtime.test_factory.provider.calls}) == 4
    assert runtime.test_factory.scans == 1
    assert {f['assessment_state'] for f in runtime.store.list('finding')} == {'analyzed'}
    assert {f['applicability'] for f in runtime.store.list('finding')} == {'under_investigation'}
    assert all(proof == [{'id': 'scan-1', 'type': 'scanner_match', 'raw': {'exact': 'saved bytes'}}]
               for _, proof in runtime.test_factory.provider.calls)
    assert tick(runtime) is None


def test_failed_head_does_not_starve_untouched_tail(runtime):
    runtime.test_factory.provider.failures.add('CVE-2026-1000')
    register(runtime);scan(runtime)
    for _ in range(3):tick(runtime)
    assert len(runtime.test_factory.provider.calls) == 4
    assert len({item['cve_id'] for item, _ in runtime.test_factory.provider.calls}) == 4
    failed = next(row for row in runtime.store.list('finding') if row['cve_id'] == 'CVE-2026-1000')
    assert failed['assessment_state'] == 'retry_needed'
    assert failed['analysis_success'] is False
    lifecycle = next(row for row in runtime.store.list('analysis_lifecycle') if row['cve_id'] == failed['cve_id'])
    assert [event['state'] for event in lifecycle['transitions']] == ['pending_analysis', 'analyzing', 'analyzed', 'retry_needed']
    assert lifecycle['transitions'][-2]['success'] is False


@pytest.mark.parametrize('mode', ['disabled', 'unconfigured', 'zero_findings', 'zero_calls'])
def test_paused_provider_never_enqueues_or_calls(runtime, mode):
    register(runtime);scan(runtime)
    initial = len(runtime.test_factory.provider.calls)
    if mode == 'disabled':runtime.store.put('settings', 'service', {'ai_enabled': False})
    elif mode == 'unconfigured':runtime.test_factory.provider.configured = False
    else:runtime.store.put('settings', 'service', {'ai_max_findings' if mode == 'zero_findings' else 'ai_max_calls': 0})
    assert advance_analysis_backlog(runtime) == []
    assert len(runtime.test_factory.provider.calls) == initial


def test_matching_rescan_reuses_successful_unknown_without_resetting_tail(runtime):
    register(runtime);scan(runtime)
    tick(runtime)
    before = len(runtime.test_factory.provider.calls)
    # Force matching rather than result-cache reuse, preserving exact inputs.
    operation = runtime.enqueue('scan', {'device_id': 'leaf1'})
    claimed = runtime.store.claim()
    from unittest.mock import patch
    original_get = runtime.store.get
    with patch.object(runtime.store, 'get', side_effect=lambda kind, ident: None if kind == 'cache' else original_get(kind, ident)):
        result = runtime._job_scan(claimed)
    runtime.store.update_operation(operation['id'], 'completed', result=result)
    assert len(runtime.test_factory.provider.calls) == before + 1  # next untouched case, never successful head
    for _ in range(3):tick(runtime)
    assert len(runtime.test_factory.provider.calls) == 4


def test_context_change_during_provider_does_not_overwrite_current_findings(runtime):
    register(runtime);scan(runtime)
    before = copy.deepcopy(runtime.store.list('finding'))
    runtime.test_factory.provider.during = lambda item: runtime.store.update_device('leaf1', {'binding_revision': 'new-reviewed-binding'})
    result = tick(runtime)
    assert result['accepted'] is False
    assert runtime.store.list('finding') == before
    assert advance_analysis_backlog(runtime) == []


def test_restart_recovers_queued_saved_evidence_work_without_matching(tmp_path):
    runtime = make_runtime(tmp_path, file_db=True)
    register(runtime);scan(runtime)
    operations = advance_analysis_backlog(runtime)
    claimed = runtime.store.claim()
    assert claimed['id'] == operations[0]['id']
    runtime.stop()
    resumed = make_runtime(tmp_path, file_db=True)
    try:
        resumed.start()  # recover_jobs runs even with worker threads disabled
        operation = resumed.store.claim()
        assert operation['id'] == claimed['id']
        result = resumed._job_analysis_backlog(operation)
        assert result['accepted'] is True
        assert resumed.test_factory.scans == 0
        assert len(resumed.test_factory.provider.calls) == 1
    finally:resumed.stop()


def test_actual_attempt_is_reserved_before_provider_io_and_survives_crash(runtime):
    register(runtime);scan(runtime)
    def crash(item):raise KeyboardInterrupt('simulate process interruption after durable reservation')
    runtime.test_factory.provider.during = crash
    queued = advance_analysis_backlog(runtime)
    operation = runtime.store.claim()
    with pytest.raises(KeyboardInterrupt):runtime._job_analysis_backlog(operation)
    reserved = [row for row in runtime.store.list('analysis_work') if row.get('operation_id') == operation['id']]
    assert len(reserved) == 1
    assert reserved[0]['finding']['analysis_attempts'] == 1
    runtime.store.recover_jobs()
    runtime.test_factory.provider.during = None
    recovered = runtime.store.claim()
    runtime._job_analysis_backlog(recovered)
    # Least-attempted selection gives an untouched CVE the next turn after crash.
    assert runtime.test_factory.provider.calls[-1][0]['cve_id'] != reserved[0]['finding']['cve_id']


def test_exhausted_budget_survives_rescan(runtime):
    register(runtime);scan(runtime)
    work = next(w for w in runtime.store.list('analysis_work') if w['status'] == 'pending')
    expired = {**work['finding'], 'analysis_attempts': 5, 'analysis_retry_exhausted': True,
               'assessment_state': 'retry_needed', 'analysis_success': False}
    runtime.store.put('analysis_work', work['id'], {**work, 'status': 'exhausted', 'finding': expired}, work['backlog_id'])
    seed_backlog(runtime, 'device', 'leaf1', expected_identity=analysis_identity(runtime,'device','leaf1'),
                 assessment_revision=runtime.store.device('leaf1')['assessment_revision'])
    assert runtime.store.get('analysis_work', work['id'])['finding']['analysis_attempts'] == 5
    for _ in range(4):tick(runtime)
    assert all(item['cve_id'] != expired['cve_id'] for item, _ in runtime.test_factory.provider.calls)


@pytest.mark.parametrize('change', ['review', 'provider', 'advisory', 'ruleset', 'assessment_revision'])
def test_changed_analysis_context_rejects_delayed_backlog_result(runtime, monkeypatch, change):
    register(runtime);scan(runtime)
    before = copy.deepcopy(runtime.store.list('finding'))
    def mutate(item):
        if change == 'review':runtime.store.put('reviewed_assessment', 'new-review', {'id': 'new-review'})
        elif change == 'provider':runtime.store.put('settings', 'service', {'ai_model': 'different-model'})
        elif change == 'advisory':runtime.scanner_info['db_revision'] = 'db-new'
        elif change == 'ruleset':monkeypatch.setattr('app.services.analysis_lifecycle.RULESET_VERSION', 'new-policy')
        else:runtime.store.update_device('leaf1', {'assessment_revision': 'concurrent-new-assessment'})
    runtime.test_factory.provider.during = mutate
    result = tick(runtime)
    assert result['accepted'] is False
    assert runtime.store.list('finding') == before


def test_breaker_open_does_not_enqueue_pending_work(runtime):
    register(runtime);scan(runtime)
    runtime.test_factory.provider.circuit_open = True
    assert advance_analysis_backlog(runtime) == []
    assert len(runtime.test_factory.provider.calls) == 1


def test_each_cve_has_at_most_five_provider_attempts_even_after_rescan(tmp_path):
    runtime = make_runtime(tmp_path, count=1)
    try:
        runtime.test_factory.provider.failures.add('CVE-2026-1000')
        register(runtime);scan(runtime)
        for _ in range(4):
            work = runtime.store.list('analysis_work')[0]
            due = {**work['finding'], 'analysis_next_attempt_at': '2000-01-01T00:00:00Z'}
            runtime.store.put('analysis_work', work['id'], {**work, 'finding': due}, work['backlog_id'])
            assert tick(runtime)['accepted']
        assert len(runtime.test_factory.provider.calls) == 5
        assert runtime.store.list('analysis_work')[0]['status'] == 'exhausted'
        assert tick(runtime) is None
        assert scan(runtime)['accepted']
        assert len(runtime.test_factory.provider.calls) == 5
        assert runtime.store.list('analysis_work')[0]['finding']['analysis_attempts'] == 5
    finally:runtime.stop()


def test_cache_hit_preserves_completed_tail_and_never_recounts_provider_usage(runtime):
    register(runtime);scan(runtime)
    for _ in range(4):tick(runtime)
    assert len(runtime.test_factory.provider.calls) == 4
    result = scan(runtime)
    assert result['accepted']
    assert runtime.metrics['cache_hits'] == 1
    assert runtime.test_factory.scans == 1
    assert len(runtime.test_factory.provider.calls) == 4
    assert all(value == 0 for value in result['ai_usage'].values())
    assert {row['assessment_state'] for row in runtime.store.list('finding')} == {'analyzed'}
    assert tick(runtime) is None


@pytest.mark.parametrize('change', ['provider', 'review', 'source_roots', 'advisory'])
def test_initial_scan_cannot_seed_old_results_under_changed_analysis_identity(runtime, change):
    register(runtime)
    def mutate(item):
        if change == 'provider':runtime.store.put('settings','service',{'ai_model':'changed'})
        elif change == 'review':runtime.store.put('reviewed_assessment','new',{'id':'new'})
        elif change == 'source_roots':runtime.store.put('settings','service',{'source_roots':['/tmp/new-source-context']})
        else:runtime.scanner_info['db_revision']='new-advisories'
    runtime.test_factory.provider.during=mutate
    result=scan(runtime)
    assert result['accepted'] is False
    assert runtime.store.list('finding') == []
    assert runtime.store.list('analysis_work') == []


def test_backlog_hydrates_and_writes_only_selected_findings(runtime, monkeypatch):
    register(runtime);scan(runtime)
    history_before = len(runtime.store.list('assessment_history'))
    scan_time = runtime.store.device('leaf1')['last_scan_at']
    original = runtime.store.list
    def bounded(kind, *args, **kwargs):
        assert kind not in ('analysis_work', 'finding', 'release_finding'), 'Backlog must use bounded SQL/point reads'
        return original(kind, *args, **kwargs)
    monkeypatch.setattr(runtime.store, 'list', bounded)
    assert tick(runtime)['accepted']
    assert len(original('assessment_history')) == history_before + 1
    assert len(original('finding')) == 4
    assert runtime.store.device('leaf1')['last_scan_at'] == scan_time
    assert original('assessment_history')[0]['assessment_kind'] in ('scan', 'ai_backlog')


def test_release_backlog_uses_scoped_saved_evidence_and_subset_history(runtime):
    from app.db.store import stable_hash
    from app.services.sbom_parser import normalize_inventory, scope_to_sbom
    document = scope_to_sbom(normalize_inventory({'scopes': [{'id': 'host', 'components': [{
        'id': 'openssl-host', 'name': 'openssl', 'version': '3.0.1-1', 'ecosystem': 'deb', 'arch': 'amd64',
        'properties': {'smart-patch:distro:name': 'debian', 'smart-patch:distro:version': '12'}}]}]})['scopes'][0])
    artifact = stable_hash(document)
    runtime.store.put('artifact', artifact, {'sbom': document})
    runtime.store.put('release', 'custom:backlog', {'release_id': 'custom:backlog', 'artifact_id': artifact})
    operation = runtime.enqueue('release_sync', {'release_id': 'custom:backlog'})
    claimed = runtime.store.claim()
    result = runtime._job_release_sync(claimed)
    runtime.store.update_operation(operation['id'], 'completed', result=result)
    assert len(runtime.store.list('release_finding')) == 4
    assert len(runtime.store.list('release_assessment_history')) == 4
    for _ in range(4):tick(runtime)
    assert len(runtime.test_factory.provider.calls) == 4
    assert runtime.test_factory.scans == 1
    findings = runtime.store.list('release_finding')
    assert {row['assessment_state'] for row in findings} == {'analyzed'}
    assert {row['applicability'] for row in findings} == {'under_investigation'}
    assert len(runtime.store.list('release_assessment_history')) == 7
    assert {row['analysis_attempts'] for row in runtime.store.list('package_cve')} == {1}


@pytest.mark.parametrize('change', ['binding', 'provider', 'review', 'source_roots', 'assessment_revision'])
def test_commit_to_seed_race_never_relabels_old_findings(runtime, monkeypatch, change):
    import app.services.analysis_lifecycle as lifecycle
    register(runtime)
    original = lifecycle.seed_backlog
    received = []
    def mutate_then_seed(service, kind, ident, **kwargs):
        received.append(kwargs)
        if change == 'binding':service.store.update_device(ident, {'binding_revision': 'changed-after-commit'})
        elif change == 'provider':service.store.put('settings','service',{'ai_model':'changed-after-commit'})
        elif change == 'review':service.store.put('reviewed_assessment','late-review',{'id':'late-review'})
        elif change == 'source_roots':service.store.put('settings','service',{'source_roots':['/tmp/new-context']})
        else:service.store.update_device(ident, {'assessment_revision':'concurrent-newer-assessment'})
        assert original(service, kind, ident, **kwargs) is None
    monkeypatch.setattr(lifecycle, 'seed_backlog', mutate_then_seed)
    result = scan(runtime)
    assert result['accepted']  # Result commit was valid; only later work seed is rejected.
    assert received[0]['assessment_revision'] == result['assessment_revision']
    assert runtime.store.list('analysis_work') == []
    assert runtime.store.list('analysis_backlog') == []


def test_seed_ignores_prior_revision_rows_retained_by_partial_scan(runtime):
    register(runtime);scan(runtime)
    expected = analysis_identity(runtime, 'device', 'leaf1')
    previous = runtime.store.list('finding')[0]
    # Emulate a retained historical-context finding without creating prior work
    # for its new scanner evidence key. It was not assessed in this revision.
    stale = {**previous, 'assessment_revision': 'older-context',
             'evidence': [{'id':'old-proof','type':'scanner_match','raw':{'old':True}}],
             'evidence_ids':['old-proof']}
    runtime.store.put('finding', stale['id'], stale, 'leaf1')
    before = {row['id'] for row in runtime.store.list('analysis_work')}
    seed_backlog(runtime, 'device', 'leaf1', expected_identity=expected,
                 assessment_revision=runtime.store.device('leaf1')['assessment_revision'])
    assert {row['id'] for row in runtime.store.list('analysis_work')} == before
