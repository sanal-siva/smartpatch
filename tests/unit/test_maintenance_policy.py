import copy

import pytest
from app.services.maintenance_policy import resolve_maintenance_targets, MaintenancePolicyError


def finding(cve='CVE-2026-1001', fixed='1.1', installed='1.0', source_name=None, source_version=None):
    component = {'name': 'smart-patch-fixture', 'version': installed, 'ecosystem': 'deb', 'arch': 'amd64'}
    if source_name:
        component.update(source_name=source_name, source_version=source_version)
    return {'cve_id': cve, 'package_name': 'smart-patch-fixture', 'scope_id': 'host', 'affected_version': installed,
            'fixed_versions': [fixed], 'component': component, 'applicability': 'affected'}


def candidate(version='1.3', source_name='smart-patch-fixture', source_version=None):
    return {'name': 'smart-patch-fixture', 'version': version, 'architecture': 'amd64',
            'source_name': source_name, 'source_version': source_version or version,
            'verified': True, 'evidence_ids': ['apt-index-verified'], 'sha256': 'a' * 64,
            'repository': 'https://deb.example.test/debian', 'suite': 'bookworm'}


def clean_scan(target, findings):
    return {'target': {'package_name': target['name'], 'version': target['version'], 'scope_id': 'host',
                       'architecture': target['architecture'], 'source_name': target.get('source_name'),
                       'source_version': target.get('source_version')},
            'scanner': {'status': 'complete', 'db_revision': 'db-current'}, 'current_db_revision': 'db-current',
            'coverage': {'complete': True}, 'findings': [], 'evidence_ids': ['target-scan-evidence']}


def test_available_higher_version_satisfies_multiple_different_fix_floors():
    result = resolve_maintenance_targets([finding(fixed='1.1'), finding('CVE-2026-1002', fixed='1.2')], [candidate()], validator=clean_scan)
    assert result['target_version'] == '1.3'
    assert result['target_options'][0]['status'] == 'recheck_passed'
    assert result['target_options'][0]['execution_eligible'] is False
    assert result['required_agent_preflight']


def test_single_exact_advisory_fixture_survives_without_catalog():
    result = resolve_maintenance_targets([finding()], requested_version='1.1')
    assert result['target_version'] == '1.1'
    assert result['target_options'][0]['status'] == 'candidate_only'
    assert result['repository_availability'] == 'unknown'
    assert result['target_options'][0]['agent_preflight_required']


def test_distinct_advisory_floors_do_not_invent_downloadable_version():
    result = resolve_maintenance_targets([finding(fixed='1.1'), finding('CVE-2026-1002', fixed='1.2')])
    assert result['target_options'] == []
    assert result['target_version'] is None
    with pytest.raises(MaintenancePolicyError):
        resolve_maintenance_targets([finding()], requested_version='9.0')


def test_epoch_ordering_is_native_debian_not_lexical():
    selected = [finding(installed='1:1.0', fixed='1:1.2')]
    result = resolve_maintenance_targets(selected, [candidate('9.0'), candidate('1:1.3')], validator=clean_scan)
    assert result['target_version'] == '1:1.3'
    assert result['rejected_candidates'][0]['version'] == '9.0'


def test_new_binary_revision_does_not_prove_new_source_fix():
    selected = [finding(installed='1.0-2+sonic1', fixed='1.0-2', source_name='upstream-source', source_version='1.0-1')]
    result = resolve_maintenance_targets(selected, [candidate('1.0-2+sonic2', source_name='upstream-source', source_version='1.0-1')], validator=clean_scan)
    assert result['target_options'] == []
    assert 'fix floor' in result['rejected_candidates'][0]['reason']


def test_correct_source_and_binary_versions_are_both_preserved():
    selected = [finding(installed='1.0-1+b1', fixed='1.1-1', source_name='upstream-source', source_version='1.0-1')]
    result = resolve_maintenance_targets(selected, [candidate('1.1-1+b2', source_name='upstream-source', source_version='1.1-1')], validator=clean_scan)
    assert result['target_version'] == '1.1-1+b2'
    assert result['target_options'][0]['source_version'] == '1.1-1'


def test_missing_cross_package_source_evidence_is_rejected():
    selected = [finding(source_name='upstream-source', source_version='1.0')]
    item = candidate()
    item.pop('source_name'); item.pop('source_version')
    result = resolve_maintenance_targets(selected, [item], validator=clean_scan)
    assert result['target_options'] == []
    assert resolve_maintenance_targets(selected)['target_options'] == []


def test_reintroduced_selected_cve_rejects_candidate():
    def reintroduced(target, findings):
        result = clean_scan(target, findings)
        result['findings'] = [{'cve_id': findings[0]['cve_id']}]
        return result
    result = resolve_maintenance_targets([finding()], [candidate()], validator=reintroduced)
    assert result['target_options'] == []
    assert 'reintroduced' in result['rejected_candidates'][0]['reason']


def test_related_alias_reintroduced_cve_also_rejects():
    def alias(target, findings):
        result = clean_scan(target, findings)
        result['findings'] = [{'cve_id': 'GHSA-example', 'related_vulnerabilities': [{'id': findings[0]['cve_id']}]}]
        return result
    assert resolve_maintenance_targets([finding()], [candidate()], validator=alias)['target_options'] == []


@pytest.mark.parametrize('mutation', ['stale_db', 'partial', 'wrong_scope', 'wrong_source'])
def test_incomplete_or_misbound_recheck_is_rejected(mutation):
    def invalid(target, findings):
        result = clean_scan(target, findings)
        if mutation == 'stale_db':result['current_db_revision'] = 'db-new'
        if mutation == 'partial':result['coverage']['complete'] = False
        if mutation == 'wrong_scope':result['target']['scope_id'] = 'bgp'
        if mutation == 'wrong_source':result['target']['source_version'] = '0.1'
        return result
    result = resolve_maintenance_targets([finding()], [candidate()], validator=invalid)
    assert result['target_options'] == []


def test_available_candidate_without_recheck_is_explicitly_pending():
    result = resolve_maintenance_targets([finding()], [candidate()])
    assert result['target_options'][0]['status'] == 'recheck_required'
    assert result['target_options'][0]['central_recheck']['status'] == 'not_run'
    assert result['target_options'][0]['execution_eligible'] is False


def test_catalog_row_shape_is_supported():
    item = candidate()
    item.pop('verified'); item.pop('evidence_ids')
    row = {'status': 'available', 'availability_basis': 'signature-verified configured APT indices',
           'candidate': item, 'evidence_ids': ['apt-index-verified']}
    result = resolve_maintenance_targets([finding()], {'coverage': {'complete': True}, 'packages': [row]}, validator=clean_scan)
    assert result['repository_availability'] == 'verified_index'
    assert result['target_version'] == '1.3'


def test_unverified_repository_claim_does_not_establish_availability():
    item = candidate()
    item['verified'] = False
    result = resolve_maintenance_targets([finding()], [item])
    assert result['repository_availability'] == 'unknown'
    assert result['target_options'][0]['status'] == 'candidate_only'


def test_cross_scope_and_cross_device_selection_is_rejected():
    with pytest.raises(MaintenancePolicyError):
        resolve_maintenance_targets([finding(), {**finding('CVE-2026-1002'), 'scope_id': 'bgp'}])
    with pytest.raises(MaintenancePolicyError):
        resolve_maintenance_targets([{**finding(), 'device_id': 'leaf1'}, {**finding('CVE-2026-1002'), 'device_id': 'leaf2'}])


def test_validator_failure_does_not_become_clean_result():
    def failed(*args):
        raise RuntimeError('scanner unavailable')
    result = resolve_maintenance_targets([finding()], [candidate()], validator=failed)
    assert result['target_options'] == []
    assert 'scanner unavailable' in result['rejected_candidates'][0]['reason']


def test_same_version_different_artifacts_remains_ambiguous():
    with pytest.raises(MaintenancePolicyError, match='multiple repository artifacts'):
        resolve_maintenance_targets([finding()], [candidate(), {**candidate(), 'sha256': 'b' * 64}], requested_version='1.3')
