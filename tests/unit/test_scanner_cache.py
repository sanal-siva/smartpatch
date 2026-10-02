import copy
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from app.services.scanner import GrypeScanner, ScanError


def scope(version='1.0', ident='host'):
    return {'id': ident, 'distro': {'name': 'debian', 'version': '12'},
            'components': [{'id': ident + ':openssl', 'name': 'openssl', 'version': version, 'ecosystem': 'deb', 'arch': 'amd64'}]}


def result(item, missing=None):
    return {'findings': [], 'evidence': [], 'scanner': {'version': '1', 'database': {'built': 'revision1'}},
            'scope_id': item['id'], 'missing_versions': missing or [], 'components_scanned': len(item['components'])}


@pytest.fixture
def scanner(tmp_path):
    scanner = GrypeScanner(cache_dir=tmp_path)
    scanner.status = Mock(return_value={'status': 'ready', 'version': '1', 'db_revision': 'revision1'})
    scanner._configuration = Mock(return_value=('effective-config-1', None))
    def fresh_result(item):
        value = result(item)
        status = scanner.status.return_value
        value['scanner'] = {'version': status['version'], 'database': {'built': status['db_revision']}}
        return value
    scanner._scan_scope_uncached = Mock(side_effect=fresh_result)
    return scanner


def test_cache_reuses_exact_scoped_match_but_not_new_version_or_scope(scanner):
    assert scanner.scan_scope(scope())['cache_hit'] is False
    assert scanner.scan_scope(scope())['cache_hit'] is True
    scanner.scan_scope(scope(version='1.1'))
    scanner.scan_scope(scope(ident='bgp'))
    assert scanner._scan_scope_uncached.call_count == 3
    assert scanner.cache_hits == 1


def test_database_revision_invalidates_cache(scanner):
    scanner.scan_scope(scope())
    scanner.status.return_value['db_revision'] = 'revision2'
    assert scanner.scan_scope(scope())['cache_hit'] is False
    assert scanner._scan_scope_uncached.call_count == 2


def test_unavailable_database_cannot_use_cached_matches(scanner):
    scanner.scan_scope(scope())
    scanner.status.return_value['status'] = 'unavailable'
    scanner._scan_scope_uncached.side_effect = ScanError('database unavailable')
    with pytest.raises(ScanError):
        scanner.scan_scope(scope())


def test_partial_and_failed_results_never_cached(scanner):
    scanner._scan_scope_uncached.side_effect = lambda item: result(item, ['no-version'])
    scanner.scan_scope(scope())
    scanner.scan_scope(scope())
    assert scanner._scan_scope_uncached.call_count == 2
    assert list(scanner.cache_dir.glob('*.json')) == []
    scanner._scan_scope_uncached.side_effect = ScanError('scanner failed')
    with pytest.raises(ScanError):
        scanner.scan_scope(scope())
    assert list(scanner.cache_dir.glob('*.json')) == []


def test_concurrent_requests_do_one_match_run(scanner):
    def slow(item):
        time.sleep(0.1)
        return result(item)
    scanner._scan_scope_uncached.side_effect = slow
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: scanner.scan_scope(scope()), range(8)))
    assert scanner._scan_scope_uncached.call_count == 1
    assert sum(item['cache_hit'] for item in results) == 7


def test_cache_has_bounded_files_and_corruption_recovers(scanner):
    scanner.cache_max_entries = 2
    for version in ['1.0', '1.1', '1.2']:
        scanner.scan_scope(scope(version))
    assert len(list(scanner.cache_dir.glob('*.json'))) <= 2
    for path in scanner.cache_dir.glob('*.json'):
        path.write_text('truncated JSON')
    assert scanner.scan_scope(scope('1.2'))['cache_hit'] is False


def test_advisory_update_during_scan_is_not_cached(scanner):
    scanner.status.side_effect = [{'status': 'ready', 'version': '1', 'db_revision': 'revision1'},
                                 {'status': 'ready', 'version': '1', 'db_revision': 'revision2'}]
    with pytest.raises(ScanError, match='changed during matching'):
        scanner.scan_scope(scope())
    assert list(scanner.cache_dir.glob('*.json')) == []

def packages(*versions, ident='host'):
    return {'id': ident, 'distro': {'name': 'debian', 'version': '12'},
            'components': [{'id': f'{ident}:pkg-{index}', 'name': f'pkg-{index}',
                            'version': version, 'arch': 'amd64', 'ecosystem': 'deb'}
                           for index, version in enumerate(versions)]}


def matches(item):
    value = result(item)
    for package in item['components']:
        if package['version'] == 'safe':
            continue
        ident = 'evidence:' + package['id'] + ':' + package['version']
        value['findings'].append({'id': 'finding:' + package['id'], 'scope_id': item['id'],
                                 'component_id': package['id'], 'package_name': package['name'],
                                 'affected_version': package['version'], 'component': copy.deepcopy(package),
                                 'cve_id': 'CVE-2026-1234', 'evidence_ids': [ident]})
        value['evidence'].append({'id': ident, 'scope_id': item['id'], 'component_id': package['id'],
                                 'cve_id': 'CVE-2026-1234', 'data': {'version': package['version']}})
    return value


def test_changed_package_only_and_explicit_zero_match_reuse(scanner):
    scanner._scan_scope_uncached.side_effect = matches
    baseline = packages('1', 'safe', '1')
    scanner.scan_scope(baseline)
    current = packages('safe', 'safe', '1')
    actual = scanner.scan_scope(current)
    assert [p['id'] for p in scanner._scan_scope_uncached.call_args.args[0]['components']] == ['host:pkg-0']
    assert actual['components_scanned'] == 3
    assert actual['components_matched'] == 1
    assert actual['components_reused'] == 2
    assert actual['scan_mode'] == 'incremental'
    assert actual['findings'] == matches(current)['findings']
    assert actual['evidence'] == matches(current)['evidence']
    # The successful zero-match for the updated package is durable across restart.
    fresh = GrypeScanner(cache_dir=scanner.cache_dir)
    fresh.status = scanner.status
    fresh._configuration = scanner._configuration
    fresh._scan_scope_uncached = Mock(side_effect=AssertionError('must reuse all packages'))
    cached = fresh.scan_scope(current)
    assert cached['components_matched'] == 0 and cached['components_reused'] == 3


def test_multiple_changes_are_one_matching_process_and_removed_findings_disappear(scanner):
    scanner._scan_scope_uncached.side_effect = matches
    scanner.scan_scope(packages('1', '1', '1', '1'))
    current = packages('2', '2', '1')
    actual = scanner.scan_scope(current)
    assert scanner._scan_scope_uncached.call_count == 2
    assert len(scanner._scan_scope_uncached.call_args.args[0]['components']) == 2
    assert actual['components_removed'] == 1
    assert {f['component_id'] for f in actual['findings']} == {'host:pkg-0', 'host:pkg-1', 'host:pkg-2'}
    # Removal-only changes need no matching process, including the empty scope.
    current['components'] = current['components'][:1]
    removed = scanner.scan_scope(current)
    assert removed['components_removed'] == 2 and removed['components_matched'] == 0
    current['components'] = []
    empty = scanner.scan_scope(current)
    assert empty['findings'] == [] and empty['evidence'] == [] and empty['components_scanned'] == 0
    assert scanner._scan_scope_uncached.call_count == 2


@pytest.mark.parametrize('field,value', [('source_version', '2'), ('source_name', 'source-2'),
    ('purl', 'pkg:deb/debian/pkg-0@1?arch=amd64&distro=debian-12'), ('arch', 'arm64'),
    ('properties', {'syft:metadata:sourceVersion': '2'}), ('hashes', [{'sha256': 'new'}]),
    ('patches', [{'id': 'vendor-fix'}]), ('custom_patch_context', 'changed')])
def test_exact_package_metadata_is_part_of_reuse_identity(scanner, field, value):
    baseline = packages('1', '1')
    scanner.scan_scope(baseline)
    current = copy.deepcopy(baseline)
    current['components'][0][field] = value
    actual = scanner.scan_scope(current)
    assert actual['components_matched'] == 1 and actual['components_reused'] == 1


@pytest.mark.parametrize('change', [
    {'id': 'container:bgp'}, {'image_digest': 'sha256:different'},
    {'distro': {'name': 'debian', 'version': '13'}}, {'custom_context': {'build_id': 'another'}}])
def test_scope_context_changes_force_full_matching(scanner, change):
    baseline = packages('1', '1')
    scanner.scan_scope(baseline)
    actual = scanner.scan_scope({**baseline, **change})
    assert actual['components_matched'] == 2 and actual['components_reused'] == 0
    assert actual['scan_mode'] == 'full'


@pytest.mark.parametrize('mutation', ['missing_arch', 'missing_version', 'duplicate_id', 'duplicate_occurrence'])
def test_unsafe_scope_context_does_not_use_package_reuse(scanner, mutation):
    current = packages('1', '1')
    if mutation == 'missing_arch':
        current['components'][1].pop('arch')
    elif mutation == 'missing_version':
        current['components'][1]['version'] = None
    elif mutation == 'duplicate_id':
        current['components'][1]['id'] = current['components'][0]['id']
    else:
        current['components'][1]['name'] = current['components'][0]['name']
    scanner.scan_scope(current)
    actual = scanner.scan_scope(current)
    assert scanner._scan_scope_uncached.call_count == 2
    assert actual['scan_mode'] == 'full' and actual['incremental_fallback_reason']
    assert list(scanner.cache_dir.glob('*.json')) == []


def test_configuration_change_and_scanner_upgrade_invalidate_baseline(scanner):
    scanner.scan_scope(packages('1', '1'))
    scanner._configuration.return_value = ('configuration2', None)
    assert scanner.scan_scope(packages('2', '1'))['scan_mode'] == 'full'
    scanner.status.return_value = {**scanner.status.return_value, 'version': '2'}
    assert scanner.scan_scope(packages('3', '1'))['scan_mode'] == 'full'


def test_external_or_unavailable_configuration_bypasses_reuse(scanner):
    scanner.scan_scope(packages('1', '1'))
    scanner._configuration.return_value = (None, 'external_matching_context_requires_full_scan')
    actual = scanner.scan_scope(packages('2', '1'))
    assert actual['scan_mode'] == 'full' and actual['components_reused'] == 0
    assert actual['incremental_fallback_reason'] == 'external_matching_context_requires_full_scan'


def test_db_change_during_incremental_or_cache_hit_rejects_all_results(scanner):
    scanner.scan_scope(packages('1', '1'))
    first = dict(scanner.status.return_value)
    scanner.status.side_effect = [first, {**first, 'db_revision': 'revision2'}]
    with pytest.raises(ScanError, match='changed during matching'):
        scanner.scan_scope(packages('2', '1'))
    scanner.status.side_effect = [first, {**first, 'db_revision': 'revision2'}]
    with pytest.raises(ScanError, match='changed during matching'):
        scanner.scan_scope(packages('1', '1'))


def test_config_change_during_matching_rejects_result(scanner):
    scanner._configuration.side_effect = [('config1', None), ('config2', None)]
    with pytest.raises(ScanError, match='changed during matching'):
        scanner.scan_scope(packages('1', '1'))


def test_partial_incremental_response_does_not_claim_complete_coverage(scanner):
    scanner.scan_scope(packages('1', '1'))
    scanner._scan_scope_uncached.side_effect = lambda item: {**result(item), 'components_scanned': 0}
    with pytest.raises(ScanError, match='incomplete package coverage'):
        scanner.scan_scope(packages('2', '1'))


def test_mutable_returned_findings_do_not_poison_cached_source_evidence(scanner):
    scanner._scan_scope_uncached.side_effect = matches
    first = scanner.scan_scope(packages('1', '1'))
    first['findings'][0]['component']['name'] = 'injected'
    first['findings'][0]['applicability'] = 'not_affected'
    again = scanner.scan_scope(packages('1', '1'))
    assert again['findings'][0]['component']['name'] == 'pkg-0'
    assert 'applicability' not in again['findings'][0]


def test_valid_json_with_altered_or_missing_coverage_misses_cache(scanner):
    import json
    scanner.scan_scope(packages('1', '1'))
    path = next(scanner.cache_dir.glob('*.json'))
    document = json.loads(path.read_text())
    document['payload']['result']['components_scanned'] = 1
    path.write_text(json.dumps(document))
    actual = scanner.scan_scope(packages('1', '1'))
    assert actual['scan_mode'] == 'full' and actual['components_matched'] == 2


def test_environment_and_config_file_content_are_in_effective_configuration(tmp_path, monkeypatch):
    from app.services import scanner as module
    config = {'match': {'dpkg': {'using-cpes': False}}, 'ignore': []}
    monkeypatch.setattr(module, 'run_bounded', lambda *args, **kwargs: module.yaml.safe_dump(config))
    scanner = GrypeScanner(cache_dir=tmp_path)
    before, reason = scanner._configuration()
    assert before and reason is None
    config['ignore'] = [{'vulnerability': 'CVE-2026-1234'}]
    assert scanner._configuration()[0] != before
    config['vex-documents'] = ['/tmp/dynamic-vex.json']
    assert scanner._configuration()[0] is None


@pytest.mark.parametrize('mutation', ['missing_receipt', 'missing_fingerprint', 'missing_match',
    'missing_evidence', 'dangling_evidence', 'unknown_component', 'wrong_version', 'wrong_component'])
def test_internally_inconsistent_baseline_cannot_prove_zero_matches(scanner, mutation):
    import json
    from app.services.sbom_parser import stable_id
    scanner._scan_scope_uncached.side_effect = matches
    scanner.scan_scope(packages('1', '1'))
    path = next(scanner.cache_dir.glob('*.json'))
    stored = json.loads(path.read_text())
    payload = stored['payload']
    result = payload['result']
    if mutation == 'missing_receipt':
        payload['packages'].pop('host:pkg-0')
    elif mutation == 'missing_fingerprint':
        payload['fingerprints'].pop('host:pkg-0')
    elif mutation == 'missing_match':
        result['findings'].pop()
    elif mutation == 'missing_evidence':
        result['evidence'].pop()
    elif mutation == 'dangling_evidence':
        result['findings'][0]['evidence_ids'] = ['no-such-proof']
    elif mutation == 'unknown_component':
        result['findings'][0]['component_id'] = 'unknown'
    elif mutation == 'wrong_version':
        result['findings'][0]['affected_version'] = 'wrong'
    else:
        result['findings'][0]['component']['name'] = 'wrong-package'
    stored['checksum'] = stable_id(payload)
    path.write_text(json.dumps(stored))
    actual = scanner.scan_scope(packages('1', '1'))
    assert actual['scan_mode'] == 'full'
    assert scanner._scan_scope_uncached.call_count == 2
    assert len(actual['findings']) == 2


def test_scanner_report_descriptor_must_match_the_validated_database(scanner):
    scanner._scan_scope_uncached.side_effect = lambda item: {
        **result(item), 'scanner': {'version': '1', 'database': {'built': 'unvalidated-db'}}}
    with pytest.raises(ScanError, match='changed during matching'):
        scanner.scan_scope(packages('1', '1'))
    assert list(scanner.cache_dir.glob('*.json')) == []


def test_many_packages_do_not_create_per_package_cache_files_and_bytes_are_bounded(scanner):
    scanner.cache_max_entries = 2
    for index in range(4):
        scanner.scan_scope(packages(*(['1'] * 100), ident=f'container:{index}'))
    assert len(list(scanner.cache_dir.glob('*.json'))) == 2
    assert len(list(scanner.cache_dir.glob('.lock-*'))) <= 64
    scanner.cache_max_bytes = 100
    scanner.scan_scope(packages(*(['1'] * 100), ident='container:large'))
    scanner._prune_cache()
    assert sum(path.stat().st_size for path in scanner.cache_dir.glob('*.json')) <= 100


def test_cpe_or_dynamic_matching_configuration_falls_back_to_full(tmp_path, monkeypatch):
    from app.services import scanner as module
    for config in [{'match': {'dpkg': {'using-cpes': True}}}, {'exclude': ['/opt/**']},
                   {'external-sources': {'enable': True}}, {'add-cpes-if-none': True}]:
        monkeypatch.setattr(module, 'run_bounded', lambda *args, **kwargs: module.yaml.safe_dump(config))
        scanner = GrypeScanner(cache_dir=tmp_path)
        identity, reason = scanner._configuration()
        assert identity is None and reason


@pytest.mark.parametrize('kind', ['python', 'mixed', 'ubuntu'])
def test_non_debian_scopes_reuse_only_exact_whole_scope_metadata(scanner, kind):
    scanner._scan_scope_uncached.side_effect = matches
    baseline = packages('1', '1')
    if kind == 'ubuntu':
        baseline['distro'] = {'name': 'ubuntu', 'version': '24.04'}
    else:
        baseline['components'][1]['ecosystem'] = 'python'
        baseline['components'][1].pop('arch')
        if kind == 'python':
            baseline['components'][0]['ecosystem'] = 'python'
            baseline['components'][0].pop('arch')
    first = scanner.scan_scope(baseline)
    assert first['scan_mode'] == 'full' and first['incremental_fallback_reason']
    repeated = scanner.scan_scope(baseline)
    assert repeated['scan_mode'] == 'cached' and repeated['components_reused'] == 2
    assert scanner._scan_scope_uncached.call_count == 1
    for mutate in ('version', 'custom_context'):
        current = copy.deepcopy(baseline)
        current['components'][0][mutate] = 'changed'
        changed = scanner.scan_scope(current)
        assert changed['scan_mode'] == 'full'
        assert changed['components_matched'] == 2 and changed['components_reused'] == 0
        assert len(scanner._scan_scope_uncached.call_args.args[0]['components']) == 2
    scanner._configuration.return_value = (None, 'external_matching_context_requires_full_scan')
    assert scanner.scan_scope(baseline)['scan_mode'] == 'full'
    assert scanner.scan_scope(baseline)['scan_mode'] == 'full'
    assert scanner._scan_scope_uncached.call_count == 5


def test_mixed_scope_cannot_prime_sparse_debian_reuse(scanner):
    baseline = packages('1', '1', '1')
    baseline['components'][2]['ecosystem'] = 'python'
    scanner.scan_scope(baseline)
    current = copy.deepcopy(baseline)
    current['components'].pop()
    actual = scanner.scan_scope(current)
    assert actual['scan_mode'] == 'full' and actual['components_matched'] == 2
    assert actual['components_reused'] == 0


def test_non_debian_ambiguous_occurrences_and_missing_versions_never_cached(scanner):
    baseline = packages('1', '1')
    for component in baseline['components']:
        component['ecosystem'] = 'python'
    baseline['components'][1]['name'] = baseline['components'][0]['name']
    scanner.scan_scope(baseline)
    assert scanner.scan_scope(baseline)['scan_mode'] == 'full'
    assert list(scanner.cache_dir.glob('*.json')) == []
    baseline['components'][1]['name'] = 'other'
    baseline['components'][1]['version'] = None
    scanner.scan_scope(baseline)
    assert scanner.scan_scope(baseline)['scan_mode'] == 'full'
    assert list(scanner.cache_dir.glob('*.json')) == []
