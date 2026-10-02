"""The outer assessment cache must not bypass matcher freshness checks."""
import copy
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.db.store import inventory_hash
from app.runtime import Runtime
from app.services.scanner import ScanError
from tests.unit.test_scan_progress import RecordingPipeline


class MutablePipeline(RecordingPipeline):
    def __init__(self, *args):
        self.calls = 0
        self.snapshot = {'status': 'ready', 'version': 'scanner-1',
                         'db_revision': 'db1', 'db_identity': 'file-1'}
        self.configuration = 'config-1'
        self.change_after_matching = None
        self.scanner = SimpleNamespace(status=lambda: copy.deepcopy(self.snapshot),
            _configuration=lambda: (self.configuration, None))

    def analyze(self, inventory, context):
        result = super().analyze(inventory, context)
        result['scanner'].update(version=self.snapshot['version'],
                                 db_revision=self.snapshot['db_revision'])
        if self.change_after_matching:
            self.change_after_matching()
        return result


@pytest.fixture
def runtime(tmp_path):
    value = Runtime(Settings(database_url='sqlite:///:memory:', state_dir=tmp_path,
                             jobs_enabled=False, source_roots=[]), pipeline_factory=MutablePipeline)
    components = [{'component_id': 'host:demo', 'scope': 'host', 'name': 'demo',
                   'version': '1', 'architecture': 'amd64',
                   'distro': {'id': 'debian', 'version_id': '12'}}]
    token = value.store.issue_token('fixture', 'agent')
    value.store.sync({'schema_version': 1, 'device_id': 'identity-fixture',
        'hostname': 'fixture', 'sonic_version': 'test-build', 'build_id': 'test-build',
        'epoch': 'epoch', 'sequence': 1, 'kind': 'checkpoint',
        'inventory_digest': inventory_hash(components), 'components': components},
        value.store.authenticate(token['token']))
    yield value
    value.stop()


def run(runtime):
    job = runtime.schedule_scan('identity-fixture')
    claimed = runtime.store.claim()
    assert claimed['id'] == job['id']
    try:
        result = runtime._job_scan(claimed)
    except Exception:
        runtime.store.update_operation(job['id'], 'failed')
        raise
    runtime.store.update_operation(job['id'], 'completed', result=result)
    return result


@pytest.mark.parametrize('change', ['version', 'db_identity', 'configuration'])
def test_changed_matcher_context_cannot_reuse_outer_cache(runtime, change):
    assert run(runtime)['accepted']
    assert run(runtime)['scanner']['assessment_cache_hit']
    assert runtime.pipeline.calls == 1
    if change == 'configuration':
        runtime.pipeline.configuration = 'config-2'
    else:
        runtime.pipeline.snapshot[change] += '-changed'
    result = run(runtime)
    assert result['accepted'] and not result['scanner'].get('assessment_cache_hit')
    assert runtime.pipeline.calls == 2


def test_unavailable_database_never_reuses_a_known_revision(runtime):
    assert run(runtime)['accepted']
    runtime.pipeline.snapshot['status'] = 'unavailable'
    with pytest.raises(ScanError, match='unavailable'):
        run(runtime)
    assert runtime.pipeline.calls == 1
    assert runtime.store.device('identity-fixture')['scan_status'] != 'completed'


def test_uninspectable_configuration_bypasses_outer_reuse_and_storage(runtime):
    runtime.pipeline.configuration = None
    assert run(runtime)['accepted']
    assert run(runtime)['accepted']
    assert runtime.pipeline.calls == 2
    assert not runtime.store.list('cache')


@pytest.mark.parametrize('change', ['version', 'db_identity', 'configuration', 'status'])
def test_matcher_changes_during_assessment_cannot_commit_current_proof(runtime, change):
    def mutate():
        if change == 'configuration':
            runtime.pipeline.configuration = 'changed'
        elif change == 'status':
            runtime.pipeline.snapshot[change] = 'unavailable'
        else:
            runtime.pipeline.snapshot[change] += '-changed'
    runtime.pipeline.change_after_matching = mutate
    with pytest.raises(ScanError, match='changed during assessment'):
        run(runtime)
    assert not runtime.store.get('maintenance_scan', 'identity-fixture')
    assert not runtime.store.list('cache')


def test_cache_hit_does_not_extend_original_assessment_ttl(runtime):
    assert run(runtime)['accepted']
    before = runtime.store.list('cache')[0]['created_at']
    assert run(runtime)['scanner']['assessment_cache_hit']
    assert runtime.store.list('cache')[0]['created_at'] == before


def test_scanner_change_during_outer_cache_lookup_rejects_its_proof(runtime):
    assert run(runtime)['accepted']
    before = runtime.store.get('maintenance_scan', 'identity-fixture')
    calls = [0]
    def configuration():
        calls[0] += 1
        return ('config-1' if calls[0] == 1 else 'config-2'), None
    runtime.pipeline.scanner._configuration = configuration
    with pytest.raises(ScanError, match='changed during assessment'):
        run(runtime)
    assert runtime.pipeline.calls == 1
    assert runtime.store.get('maintenance_scan', 'identity-fixture') == before
