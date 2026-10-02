from datetime import datetime, timedelta, timezone

from app.services.assessment import AssessmentEngine, RULESET_VERSION


def finding(version='1.0.16-1+deb12u1', distro='13'):
    return {'id': 'candidate', 'cve_id': 'CVE-2023-41910', 'scope_id': 'container:lldp', 'component_id': 'lldpd',
            'package_name': 'lldpd', 'affected_version': version, 'distro': {'name': 'debian', 'version': distro},
            'component': {'id': 'lldpd', 'name': 'lldpd', 'version': version, 'source_name': 'lldpd', 'source_version': version,
                          'ecosystem': 'deb', 'purl': 'pkg:deb/debian/lldpd@' + version},
            'advisory_namespace': 'debian:distro:debian:' + distro, 'match_details': [{'type': 'exact-direct-match'}],
            'evidence_ids': ['scanner-match'], 'fixed_versions': ['1.0.17-1'], 'cvss_score': None}


def test_verified_image_does_not_resolve_cross_release_revision():
    result = AssessmentEngine().evaluate(finding(), 'synthetic-build', {'artifact_verified': True})
    assert result['applicability'] == 'under_investigation'
    assert result['advisory_match_status'] == 'cross_release_candidate'
    assert result['release_lineage']['scope_release'] == '13'
    assert result['release_lineage']['signals'][0]['release_hint'] == '12'
    assert result['vex_verdict'] is None
    assert result['ruleset_version'] == RULESET_VERSION


def test_suffix_is_not_a_fix_claim_for_other_direct_matches():
    item = finding(distro='12')
    item['cve_id'] = 'SYNTHETIC-OTHER-ADVISORY'
    result = AssessmentEngine().evaluate(item, 'synthetic-build', {'artifact_verified': True})
    assert result['applicability'] == 'affected'
    assert result['vex_verdict'] is None
    assert 'release_lineage' not in result


def test_source_revision_also_flags_uncertain_lineage_and_point_release_is_supported():
    item = finding(version='1.0.16-1+sonic4', distro='13.7')
    item['component']['source_version'] = '1.0.16-1+deb12u1'
    result = AssessmentEngine().evaluate(item, 'synthetic-build', {'artifact_verified': True})
    assert result['applicability'] == 'under_investigation'
    assert result['release_lineage']['signals'] == [{'field': 'source_version', 'version': '1.0.16-1+deb12u1', 'release_hint': '12'}]


def test_valid_package_specific_review_can_resolve_the_candidate():
    item = finding()
    record = {'id': 'review', 'build_id': 'synthetic-build', 'scope_id': item['scope_id'], 'component_id': item['component_id'],
              'cve_id': item['cve_id'], 'version': item['affected_version'], 'verification': 'reviewed',
              'device_id': 'synthetic-device', 'inventory_digest': 'inventory1', 'applicability': 'fixed',
              'justification': 'Synthetic review fixture verifies exact package-specific patch evidence',
              'evidence_ids': ['synthetic-reviewed-patch'],
              'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    context = {'device_id': 'synthetic-device', 'inventory_digest': 'inventory1', 'artifact_verified': True}
    result = AssessmentEngine([record]).evaluate(item, 'synthetic-build', context)
    assert result['applicability'] == 'fixed'
    assert result['release_lineage']['resolution'] == 'reviewed_package_specific_decision'
    record['expires_at'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert AssessmentEngine([record]).evaluate(item, 'synthetic-build', context)['applicability'] == 'under_investigation'
