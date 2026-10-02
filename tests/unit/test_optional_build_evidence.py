"""Optional provenance requirements never manufacture artifact or fix evidence."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.services.assessment import AssessmentEngine, finding_decision_fresh
from app.services.pipeline import AnalysisPipeline


def candidate():
    return {'id': 'candidate', 'cve_id': 'SYNTHETIC-CVE', 'scope_id': 'host', 'component_id': 'curl-host',
            'package_name': 'curl', 'affected_version': '7.88.1-1', 'fixed_versions': ['7.88.1-2'],
            'component': {'id': 'curl-host', 'name': 'curl', 'version': '7.88.1-1', 'ecosystem': 'deb',
                          'source_name': 'curl', 'source_version': '7.88.1-1', 'purl': 'pkg:deb/debian/curl@7.88.1-1'},
            'distro': {'name': 'debian', 'version': '12'}, 'advisory_namespace': 'debian:distro:debian:12',
            'match_details': [{'type': 'exact-direct-match'}], 'evidence_ids': ['scanner-evidence'], 'cvss_score': 7.5}


def test_default_is_required_and_caller_context_cannot_relax_it():
    assert Settings(_env_file=None).build_evidence_policy == 'required'
    result = AssessmentEngine().evaluate(candidate(), 'unverified-build', {'build_evidence_policy': 'optional'})
    assert result['applicability'] == 'under_investigation'
    assert result['build_evidence_policy'] == 'required'
    with pytest.raises(ValidationError):
        Settings(_env_file=None, build_evidence_policy='ignore_all')


def test_optional_mode_uses_reported_inventory_without_verifying_or_authorizing_it():
    original = candidate()
    result = AssessmentEngine(build_evidence_policy='optional').evaluate(original, 'unverified-build')
    assert original == candidate()
    assert result['applicability'] == 'affected'
    assert result['decision_basis'] == 'inventory_advisory_match'
    assert result['artifact_binding'] == 'unverified'
    assert result['build_evidence_policy'] == 'optional'
    assert result['exposure'] == 'unknown' and result['vex_verdict'] is None
    assert result['remediation_eligible'] is False and result['review_required'] is True
    assert result['action_type'] == 'defer'
    assert result['candidate_fixed_versions'] == ['7.88.1-2']
    assert 'unverified' in result['rationale']


@pytest.mark.parametrize('change', [
    {'component': {'custom_build': True}},
    {'component': {'patches': [{'name': 'custom.patch'}]}},
    {'component': {'purl': 'pkg:deb/sonic/curl@7.88.1-1'}},
    {'component': {'source_version': '7.88.1-1+deb11u1'}},
    {'advisory_namespace': 'debian:distro:debian:11'},
    {'advisory_namespace': 'ubuntu:distro:ubuntu:12'},
    {'advisory_namespace': 'nvd:cpe'},
    {'match_details': [{'type': 'cpe-match'}]},
    {'distro': {'name': 'debian', 'version': ''}},
])
def test_optional_does_not_skip_other_evidence_requirements(change):
    item = candidate()
    for field, value in change.items():
        item[field] = {**item[field], **value} if field == 'component' else value
    result = AssessmentEngine(build_evidence_policy='optional').evaluate(item)
    assert result['applicability'] == 'under_investigation'
    assert result['artifact_binding'] == 'unverified'
    assert result['remediation_eligible'] is False and result['vex_verdict'] is None


@pytest.mark.parametrize('policy', ['required', 'optional'])
def test_verified_exact_match_keeps_verified_basis(policy):
    result = AssessmentEngine(build_evidence_policy=policy).evaluate(candidate(), context={'artifact_verified': True})
    assert result['applicability'] == 'affected'
    assert result['decision_basis'] == 'verified_distribution_match'
    assert result['artifact_binding'] == 'verified'
    assert result['remediation_eligible'] is True


def test_policy_switch_cannot_reuse_previous_review_and_reassessment_clears_staleness():
    record = {'id': 'review', 'build_id': 'build', 'device_id': 'device', 'scope_id': 'host',
              'component_id': 'curl-host', 'cve_id': 'SYNTHETIC-CVE', 'version': '7.88.1-1',
              'verification': 'reviewed', 'applicability': 'fixed', 'justification': 'Synthetic reviewed patch evidence',
              'evidence_ids': ['patch'], 'build_evidence_policy': 'optional',
              'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    result = AssessmentEngine([record], 'optional').evaluate(candidate(), 'build', {'device_id': 'device'})
    assert result['applicability'] == 'fixed'
    assert AssessmentEngine([record], 'required').evaluate(result, 'build', {'device_id': 'device'})['applicability'] == 'under_investigation'
    result['assessment_stale'] = True
    assert not finding_decision_fresh(result)
    record['verification'] = 'invalidated'
    revised = AssessmentEngine([record], 'optional').evaluate(result, 'build', {'device_id': 'device'})
    assert finding_decision_fresh(revised)
    assert revised['decision_basis'] == 'inventory_advisory_match'


def test_pipeline_reuses_scanner_evidence_but_reassesses_policy_and_skips_unnecessary_ai():
    pipeline = AnalysisPipeline(settings={'ai_enabled': False, 'build_evidence_policy': 'optional'})
    finding = candidate()
    inventory = {'build_id': 'build', 'scopes': [{'id': 'host', 'distro': finding['distro'],
                                               'components': [finding['component']]}]}
    def scan(scope):
        return {'findings': [deepcopy(finding)], 'evidence': [{'id': 'scanner-evidence', 'type': 'scanner_match'}],
                'components_scanned': 1, 'missing_versions': [], 'scanner': {'version': 'test', 'database': {'checksum': 'db1'}}}
    pipeline.scanner.scan_scope = scan
    result = pipeline.analyze(inventory, {'build_evidence_policy': 'required'})
    assert result['findings'][0]['decision_basis'] == 'inventory_advisory_match'
    assert result['coverage']['artifact_binding'] == 'unverified'
    assert result['coverage']['build_evidence_policy'] == 'optional'
    assert result['ai_usage']['calls'] == 0
    pipeline.engine = AssessmentEngine()
    retried = pipeline.retry_findings(result['findings'], {'build_id': 'build'})
    assert retried['findings'][0]['applicability'] == 'under_investigation'
    assert retried['findings'][0]['build_evidence_policy'] == 'required'
    assert retried['findings'][0]['remediation_eligible'] is False
