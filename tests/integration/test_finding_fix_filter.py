"""Fix filtering is server-side and does not change collector delivery or totals."""
import pytest

from app.db.store import now
from tests.integration.test_workspace_api import service, enroll


@pytest.fixture
def recorded_findings(service):
    client, runtime, _ = service
    token, envelope, _ = enroll(client)
    base = {'device_id': envelope['device_id'], 'hostname': 'filter-switch', 'scope': 'host',
            'package_name': 'test-package', 'component_id': 'host:curl:amd64',
            'affected_version': '1.0', 'status': 'current', 'severity': 'HIGH', 'cvss_score': 7.5,
            'applicability': 'under_investigation', 'assessed_at': now()}
    for index, versions in enumerate((['1.1'], [], None, ['1.2', '1.3'])):
        row = {**base, 'id': f'finding-{index}', 'cve_id': f'CVE-TEST-{index:04d}',
               'fixed_versions': versions}
        if index == 1:
            row['candidate_fixed_versions'] = ['withheld-2.0']
        runtime.store.put('finding', row['id'], row, row['device_id'])
    missing = {**base, 'id': 'finding-missing', 'cve_id': 'CVE-TEST-0099'}
    runtime.store.put('finding', missing['id'], missing, missing['device_id'])
    other = {**base, 'id': 'finding-other', 'device_id': 'other-switch',
             'cve_id': 'CVE-OTHER-0010', 'fixed_versions': [], 'severity': 'LOW'}
    runtime.store.put('finding', other['id'], other, other['device_id'])
    retired = {**base, 'id': 'finding-retired', 'status': 'removed', 'fixed_versions': []}
    runtime.store.put('finding', retired['id'], retired, retired['device_id'])
    return client, runtime, token, envelope


@pytest.mark.parametrize('flag,expected', [
    (None, {'finding-0', 'finding-1', 'finding-2', 'finding-3', 'finding-missing', 'finding-other'}),
    ('true', {'finding-0', 'finding-3'}),
    ('false', {'finding-1', 'finding-2', 'finding-missing', 'finding-other'}),
])
def test_fix_filter_counts_before_pagination_and_keeps_legacy_default(recorded_findings, flag, expected):
    client, _, _, _ = recorded_findings
    params = {'limit': 1}
    if flag is not None:
        params['fix_available'] = flag
    observed = set()
    for offset in range(len(expected)):
        response = client.get('/api/v1/findings', params={**params, 'offset': offset})
        assert response.status_code == 200, response.text
        assert response.json()['total'] == len(expected)
        assert len(response.json()['findings']) == 1
        observed.add(response.json()['findings'][0]['id'])
    assert observed == expected
    last = client.get('/api/v1/findings', params={**params, 'offset': len(expected)}).json()
    assert last == {'findings': [], 'total': len(expected)}


def test_fix_filter_combines_with_existing_filters_and_does_not_treat_candidates_as_fixes(recorded_findings):
    client, _, _, envelope = recorded_findings
    params = {'fix_available': 'false', 'device_id': envelope['device_id'], 'severity': 'high',
              'applicability': 'under_investigation', 'search': 'CVE-TEST-0001'}
    result = client.get('/api/v1/findings', params=params).json()
    assert result['total'] == 1
    assert result['findings'][0]['fixed_versions'] == []
    assert result['findings'][0]['candidate_fixed_versions'] == ['withheld-2.0']
    assert client.get('/api/v1/findings', params={**params, 'fix_available': 'true'}).json()['total'] == 0
    assert client.get('/api/v1/findings', params={**params, 'search': '%'}).json()['total'] == 0


def test_filter_is_validated_and_does_not_hide_findings_from_switch_or_overview(recorded_findings):
    client, runtime, token, envelope = recorded_findings
    assert client.get('/api/v1/findings?fix_available=invalid').status_code == 422
    assert runtime.store.finding_counts()['total'] == 6
    heartbeat = {**envelope, 'kind': 'heartbeat', 'components': [], 'collected_at': now()}
    response = client.post('/api/v1/agents/sync', json=heartbeat, headers={'Authorization': 'Bearer ' + token})
    assert response.status_code == 200, response.text
    assert {row['id'] for row in response.json()['findings']} == {
        'finding-0', 'finding-1', 'finding-2', 'finding-3', 'finding-missing'}
