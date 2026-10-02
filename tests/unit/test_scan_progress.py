"""Scan work counters must be truthful, bounded and visible before slow saves."""
import copy
from types import SimpleNamespace

from app.config import Settings
from app.db.store import inventory_hash
from app.runtime import Runtime
from app.services.pipeline import AnalysisPipeline
from app.services.scan_progress import ScanProgress, matching_counts
from app.services.scanner import ScanError


def test_progress_coalesces_findings_retains_latest_and_never_claims_completion():
    writes = []
    clock = [0.0]
    store = SimpleNamespace(update_operation=lambda ident, **data: writes.append(data))
    progress = ScanProgress(store, 'job', clock=lambda: clock[0])
    progress.emit({'phase': 'preparing'})
    progress.emit({'phase': 'matching', 'scopes_completed': 0, 'scopes_total': 2})
    progress.emit({'phase': 'matching', 'scopes_completed': 2, 'force': True})
    progress.emit({'phase': 'assessing', 'findings_completed': 0, 'findings_total': 1000})
    for count in range(1, 1001):
        clock[0] += .001
        progress.emit({'phase': 'assessing', 'findings_completed': count})
    progress.emit({'phase': 'saving', 'saving_step': 0})
    assert writes[-1]['progress_data']['findings_completed'] == 1000
    assert writes[-1]['progress_percentage'] == 92
    assert len(writes) < 10  # Not one database transaction per finding.
    percentages = [row['progress_percentage'] for row in writes]
    assert percentages == sorted(percentages)
    assert all(value < 100 for value in percentages)
    # Already-persisted records cannot mutate with later counters.
    assert writes[3]['progress_data']['findings_completed'] == 0


def test_matching_work_differs_from_logical_coverage_and_legacy_cache_reuse():
    assert matching_counts({'components_scanned': 20, 'components_matched': 1,
                            'components_reused': 19, 'components_removed': 2}) == {
        'components_matched': 1, 'components_reused': 19, 'components_removed': 2}
    assert matching_counts({'components_scanned': 20, 'cache_hit': True})['components_matched'] == 0
    assert matching_counts({'components_scanned': 20, 'cache_hit': True})['components_reused'] == 20
    assert matching_counts({'components_scanned': 20})['components_matched'] == 20


def test_pipeline_reports_each_scope_and_assessment_without_copying_callback():
    events, hooks, lifecycle = [], [], []

    class ProgressCallback:
        def __deepcopy__(self, memo):
            raise AssertionError('Progress callback must be removed before copying context')

        def __call__(self, event):
            events.append(copy.deepcopy(event))

    scopes = [{'id': name, 'distro': {'name': 'debian', 'version': '12'},
               'components': [{'id': name + '-pkg', 'name': 'demo', 'version': '1', 'ecosystem': 'deb'}]}
              for name in ('host', 'container:one', 'container:broken')]
    pipeline = AnalysisPipeline(settings={'ai_enabled': False},
                                pre_hook=lambda inventory, context: hooks.append(context))

    def scan(scope):
        if scope['id'] == 'container:broken':
            raise ScanError('Synthetic unavailable scope')
        findings = [{'id': scope['id'] + '-finding', 'scope_id': scope['id'], 'component_id': scope['components'][0]['id'],
                     'cve_id': 'CVE-TEST-1000', 'evidence_ids': [], 'applicability': 'affected'}]
        return {'components_scanned': 1, 'cache_hit': scope['id'] == 'container:one',
                'missing_versions': [], 'findings': findings, 'evidence': [],
                'scanner': {'version': 'synthetic', 'database': {'checksum': 'db-1'}}}

    pipeline.scanner.scan_scope = scan
    pipeline.engine.evaluate = lambda candidate, *args: copy.deepcopy(candidate)
    result = pipeline.analyze({'scopes': scopes}, {'_progress': ProgressCallback(),
        '_analysis_lifecycle': lambda finding, state, **kwargs: lifecycle.append((finding['id'], state))})
    assert '_progress' not in hooks[0] and '_analysis_lifecycle' not in hooks[0]
    assert result['coverage']['complete'] is False
    assert result['coverage']['components_scanned'] == 2
    assert result['coverage']['components_matched'] == 1
    assert result['coverage']['components_reused'] == 1
    finished = [event for event in events if event.get('force') and event['phase'] == 'matching']
    assert [event['scopes_completed'] for event in finished] == [1, 2, 3]
    assert finished[-1]['scan_mode'] == 'failed'
    assert len(lifecycle) == 2
    assert any(event.get('findings_completed') == 1 for event in events)
    assert any(event.get('findings_completed') == 2 for event in events)
    assert events[-1]['phase'] == 'saving'


class RecordingPipeline:
    def __init__(self, *args):
        self.calls = 0
        self.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'})

    def analyze(self, inventory, context):
        copy.deepcopy(context)  # Extension-pipeline compatibility.
        self.calls += 1
        context['_progress']({'phase': 'matching', 'scopes_total': 1, 'scopes_completed': 1,
                              'packages_total': 1, 'packages_matched': 1, 'packages_reused': 0})
        return {'findings': [], 'evidence': [], 'coverage': {'complete': True, 'scopes_total': 1,
                'scopes_scanned': 1, 'components_total': 1, 'components_scanned': 1,
                'components_matched': 1, 'components_reused': 0, 'errors': []},
                'scanner': {'status': 'complete', 'db_revision': 'db1',
                            'scope_work': [{'components_matched': 1}]}, 'errors': [], 'ai_usage': {}}


def test_runtime_announces_saving_before_cache_write_and_cached_run_has_zero_matching(tmp_path, monkeypatch):
    runtime = Runtime(Settings(database_url='sqlite:///:memory:', state_dir=tmp_path,
                              jobs_enabled=False, source_roots=[]), pipeline_factory=RecordingPipeline)
    try:
        components = [{'component_id': 'host:demo', 'scope': 'host', 'name': 'demo', 'version': '1',
                       'architecture': 'amd64', 'distro': {'id': 'debian', 'version_id': '12'}}]
        envelope = {'schema_version': 1, 'device_id': 'leaf', 'hostname': 'leaf',
                    'sonic_version': 'test-build', 'build_id': 'test-build', 'epoch': 'epoch',
                    'sequence': 1, 'kind': 'checkpoint', 'inventory_digest': inventory_hash(components),
                    'collected_at': '2026-10-01T00:00:00Z', 'components': components}
        issued = runtime.store.issue_token('test', 'agent')
        runtime.store.sync(envelope, runtime.store.authenticate(issued['token']))
        first = runtime.schedule_scan('leaf')
        original_put = runtime.store.put
        cache_writes = []

        def put(kind, ident, value, *args, **kwargs):
            if kind == 'cache':
                current = runtime.store.operation(first['id'])
                assert current['progress_data']['phase'] == 'saving'
                assert current['progress_percentage'] >= 92
                cache_writes.append(ident)
            return original_put(kind, ident, value, *args, **kwargs)

        monkeypatch.setattr(runtime.store, 'put', put)
        result = runtime._job_scan(first)
        assert result['accepted'] and cache_writes
        assert runtime.store.operation(first['id'])['progress_percentage'] == 98
        runtime.store.update_operation(first['id'], 'completed', result=result)
        second = runtime.schedule_scan('leaf')
        reused = runtime._job_scan(second)
        assert runtime.pipeline.calls == 1
        assert reused['coverage']['components_matched'] == 0
        assert reused['coverage']['components_reused'] == 1
        assert reused['scanner']['scan_mode'] == 'assessment_cached'
        assert reused['scanner']['cache_hits'] == 0
        assert 'scope_work' not in reused['scanner']
        progress = runtime.store.operation(second['id'])['progress_data']
        assert progress['packages_matched'] == 0 and progress['packages_reused'] == 1
    finally:
        runtime.stop()
