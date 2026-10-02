"""Real application contracts used by the operational UI, with isolated durable state."""
import json
import stat
from datetime import datetime,timezone,timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.analytics import capture_snapshot
from app.db.store import inventory_hash, now, stable_hash


@pytest.fixture
def service(tmp_path):
    config = Settings(_env_file=None, state_dir=tmp_path/'state',
                      database_url='sqlite:///'+str(tmp_path/'smart_patch.db'), jobs_enabled=False,
                      scanner_binary='/does/not/exist/grype', source_roots=[], ai_enabled=False)
    app = create_app(config)
    with TestClient(app) as client:
        token_file = config.state_dir/'bootstrap-token'
        token = token_file.read_text().strip()
        client.headers['Authorization'] = 'Bearer '+token
        yield client, app.state.runtime, config


def enroll(client, device_id='ui-test-switch'):
    created = client.post('/api/v1/tokens', json={'description':'Integration-test collector',
                         'role':'agent','device_id':device_id})
    assert created.status_code == 201, created.text
    agent = created.json()['token']
    components = [{'component_id':'host:curl:amd64','scope':'host','name':'curl','version':'7.88.1-10',
                   'architecture':'amd64','source_name':'curl','source_version':'7.88.1-10'}]
    envelope = {'schema_version':1,'device_id':device_id,'hostname':'test-switch','epoch':'test-epoch',
                'sequence':1,'kind':'checkpoint','inventory_digest':inventory_hash(components),
                'collected_at':now(),'components':components,'sonic_version':'test-build','build_id':'test-id'}
    result = client.post('/api/v1/agents/sync', json=envelope, headers={'Authorization':'Bearer '+agent})
    assert result.status_code == 200, result.text
    return agent, envelope, result.json()


def test_lifespan_creates_private_bootstrap_and_rejects_unregistered_tokens(service):
    client, runtime, config = service
    assert stat.S_IMODE((config.state_dir/'bootstrap-token').stat().st_mode) == 0o600
    assert stat.S_IMODE((config.state_dir/'settings.key').stat().st_mode) == 0o600
    assert runtime._threads == []
    assert client.get('/health').json()['status'] == 'healthy'
    assert client.get('/api/v1/overview', headers={'Authorization':'Bearer fabricated'}).status_code == 401
    assert client.get('/api/v1/overview', headers={'Authorization':''}).status_code == 401


def test_scoped_inventory_surfaces_in_ui_without_fabricated_scan_results(service):
    client, _, _ = service
    agent, envelope, result = enroll(client)
    assert result['ack_sequence'] == 1 and result['resync_required'] is False
    device = client.get('/api/v1/devices').json()['devices'][0]
    assert device['id'] == envelope['device_id'] and device['components_count'] == 1
    assert device['scan_status'] == 'queued'
    assert client.get('/api/v1/findings').json()['findings'] == []
    operation = client.get('/api/v1/operations/'+result['operation_id']).json()
    assert operation['status'] == 'queued'
    assert client.get('/api/v1/settings', headers={'Authorization':'Bearer '+agent}).status_code == 403
    assert client.get('/api/v1/operations/missing').status_code == 404


def test_heartbeat_does_not_make_old_inventory_look_fresh(service):
    client,_,_=service
    token,envelope,_=enroll(client)
    observed=(datetime.now(timezone.utc)-timedelta(minutes=20)).isoformat()
    fact={'collector':'inventory','status':'observed','collected_at':observed,'ttl_seconds':600,
          'value':[{'scope':'host','status':'complete'}]}
    heartbeat={**envelope,'kind':'heartbeat','components':[],'facts':[fact],'collected_at':now()}
    response=client.post('/api/v1/agents/sync',json=heartbeat,headers={'Authorization':'Bearer '+token})
    assert response.status_code==200,response.text
    device=client.get('/api/v1/devices/ui-test-switch?include_findings=false').json()
    assert device['heartbeat_age_seconds']<5 and device['inventory_age_seconds']>=1200
    assert device['inventory_freshness']=='stale' and 'findings' not in device
    future={**fact,'collected_at':(datetime.now(timezone.utc)+timedelta(minutes=4)).isoformat()}
    response=client.post('/api/v1/agents/sync',json={**heartbeat,'facts':[future]},headers={'Authorization':'Bearer '+token})
    assert response.status_code==200,response.text
    device=client.get('/api/v1/devices').json()['devices'][0]
    assert device['inventory_freshness']=='clock_uncertain' and device['inventory_age_seconds'] is None


def test_settings_encrypt_provider_secret_and_return_only_presence_flag(service):
    client, runtime, _ = service
    secret = 'integration-test-secret-not-production'
    response = client.put('/api/v1/settings', json={'ai_provider':'openai','ai_model':'test-model',
                         'ai_api_key':secret,'ai_enabled':False,'source_roots':[]})
    assert response.status_code == 200, response.text
    assert response.json()['ai_api_key_set'] is True
    assert secret not in response.text
    assert secret not in client.get('/api/v1/settings').text
    stored = runtime.store.get('settings','service')
    assert 'ai_api_key' not in stored and secret not in json.dumps(stored)
    assert runtime.cipher.decrypt(stored['ai_api_key_encrypted'].encode()).decode() == secret


def test_token_revoke_enforces_access_and_omits_raw_tokens(service):
    client, _, _ = service
    created = client.post('/api/v1/tokens', json={'description':'Temporary operator','role':'operator'}).json()
    token_headers = {'Authorization':'Bearer '+created['token']}
    assert client.get('/api/v1/overview', headers=token_headers).status_code == 200
    assert created['token'] not in client.get('/api/v1/tokens').text
    assert client.delete('/api/v1/tokens/'+created['token_id']).status_code == 200
    assert client.get('/api/v1/overview', headers=token_headers).status_code == 401


def test_version_evidence_tool_and_bad_tool_arguments(service):
    client, _, _ = service
    tools = client.get('/api/v1/tools').json()['tools']
    assert all({'name','description','input_schema'} <= set(tool) for tool in tools)
    result = client.post('/api/v1/tools/compare_versions', json={'arguments':{
        'ecosystem':'deb','installed':'1:1.0-1','other':'2.0-1'}})
    assert result.status_code == 200, result.text
    assert result.json()['result']['data']['comparison'] == 1
    assert client.post('/api/v1/tools/execute_shell',json={'arguments':{'command':'id'}}).status_code == 422
    assert client.post('/api/v1/tools/get_source',json={'arguments':{'root':'unapproved','revision':'a'*40,'path':'../../etc/passwd'}}).status_code == 422


def test_sbom_upload_reports_parser_errors_and_persists_valid_artifact(service):
    client, _, _ = service
    bad = client.post('/api/v1/sbom-upload',data={'release_id':'custom:ui-test'},
                      files={'file':('broken.json',b'{broken','application/json')})
    assert bad.status_code == 422 and 'line' in bad.json()['message']
    schema_invalid=b'{\n "bomFormat":"CycloneDX", "specVersion":"1.6",\n "components":[{"type":"library","name":"curl",\n "hashes":[{"alg":"SHA-256","content":"invalid"}]}]}\n'
    bad=client.post('/api/v1/sbom-upload',data={'release_id':'custom:ui-test'},
                    files={'file':('schema-invalid.json',schema_invalid,'application/json')})
    assert bad.status_code==422
    assert '$.components[0].hashes[0].content' in bad.json()['message']
    assert 'line 4' in bad.json()['message']
    document = {'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
                'components':[{'type':'library','bom-ref':'curl-component','name':'curl','version':'7.88.1-10',
                               'purl':'pkg:deb/debian/curl@7.88.1-10?arch=amd64'}]}
    uploaded = client.post('/api/v1/sbom-upload',data={'release_id':'custom:ui-test'},
                      files={'file':('inventory.json',json.dumps(document).encode(),'application/json')})
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()['packages_count'] == 1
    release = client.get('/api/v1/releases').json()['releases'][0]
    assert release['status'] == 'imported' and release['artifact_id'] == uploaded.json()['artifact_id']


def test_sbom_upload_preserves_registered_source_repository_and_primary(service):
    client,runtime,config=service
    keyring=config.state_dir/'keyrings'/'fixture.gpg';keyring.parent.mkdir();keyring.write_bytes(b'only a path-validation fixture')
    repository={'base_url':'https://deb.debian.org/debian','suite':'bookworm','components':['main'],
                'architectures':['amd64'],'keyring':str(keyring)}
    configured=client.post('/api/v1/releases',json={'release_id':'custom:configured',
        'source_url':'https://github.com/sonic-net/sonic-buildimage','source_revision':'a'*40,
        'repositories':[repository],'primary':True})
    assert configured.status_code==201,configured.text
    document={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[
        {'type':'library','bom-ref':'fixture','name':'fixture','version':'1.0','purl':'pkg:deb/debian/fixture@1.0'}]}
    uploaded=client.post('/api/v1/sbom-upload',data={'release_id':'custom:configured'},
        files={'file':('fixture.json',json.dumps(document).encode(),'application/json')})
    assert uploaded.status_code==201,uploaded.text
    release=runtime.store.get('release','custom:configured')
    assert release['source_revision']=='a'*40 and release['repositories']==[repository] and release['primary'] is True
    assert release['clone_operation_id']==configured.json()['clone_operation_id']
    packages=runtime.store.list('package',owner='custom:configured')
    assert len(packages)==1 and packages[0]['artifact_id']==uploaded.json()['artifact_id']


def test_shell_and_static_assets_work_in_real_application(service):
    client, _, _ = service
    for route in ('/ui/','/ui/findings','/ui/fleet','/ui/tools','/ui/settings'):
        response = client.get(route)
        assert response.status_code == 200, response.text
        assert 'id="auth-dialog"' in response.text
        assert "frame-ancestors 'none'" in response.headers['content-security-policy']
    assert client.get('/ui/static/js/app.js').status_code == 200
    assert client.get('/ui/static/css/style.css').status_code == 200
    metrics = client.get('/metrics')
    assert metrics.status_code == 200 and 'smart_patch_devices_total' in metrics.text


def test_nullable_cvss_assessment_and_input_validation(service):
    client, _, _ = service
    request = {'sonic_version':'test','vulnerabilities':[{'cve_id':'CVE-2026-0001','package_name':'curl',
               'affected_version':'7.88.1-10','severity':'HIGH','cvss_score':None}]}
    result = client.post('/api/v1/assess-vulnerabilities',json=request)
    assert result.status_code == 200, result.text
    assert result.json()['recommendations']
    timing=result.json()
    assert timing['duration_basis']=='server_request_entry_to_audit_prepare'
    assert timing['assessment_duration_ms']>=timing['processing_duration_ms']
    assert timing['queue_wait_ms']>=0
    request['vulnerabilities'][0]['cvss_score'] = 11
    assert client.post('/api/v1/assess-vulnerabilities',json=request).status_code == 422


def test_release_history_api_recovers_exact_evidence_and_checks_release_scope(service):
    from app.services.release_history import commit_release_assessment,release_assessment_identity
    client,runtime,_=service
    runtime.store.put('release','release-a',{'release_id':'release-a','artifact_id':'artifact-a'})
    candidate={'scope_id':'host','component_id':'pkg-a','package_name':'curl','affected_version':'1',
               'cve_id':'CVE-2026-1234','applicability':'under_investigation','evidence_ids':['proof-a']}
    for revision,text in [('r1','old advisory text'),('r2','corrected advisory text')]:
        result={'findings':[candidate],'evidence':[{'id':'proof-a','data':{'text':text}}]}
        assert commit_release_assessment(runtime.store,'release-a',result,revision,
            expected_identity=release_assessment_identity(runtime.store.get('release','release-a')),artifact_id='artifact-a')
    fid=runtime.store.list('release_finding',owner='release-a')[0]['id']
    route='/api/v1/releases/release-a/findings/'+fid
    assert client.get(route).json()['assessment_revision']=='r2'
    response=client.get(route+'/history');assert response.status_code==200
    history=response.json()['assessments']
    assert {row['assessment_revision'] for row in history}=={'r1','r2'}
    texts={client.get('/api/v1/evidence-snapshots/'+row['evidence_digests'][0]).json()['evidence']['data']['text'] for row in history}
    assert texts=={'old advisory text','corrected advisory text'}
    assert client.get('/api/v1/releases/release-b/findings/'+fid+'/history').status_code==404
    assert client.get(route+'/history',headers={'Authorization':''}).status_code==401


def test_processing_history_api_filters_target_kind_and_finding_and_requires_operator(service):
    client,runtime,_=service
    for ident,kind,target,finding in [('one','device','leaf1','f1'),('two','device','leaf1','f2'),
                                     ('three','release','leaf1','f1'),('four','device','leaf2','f1')]:
        runtime.store.put('analysis_lifecycle',ident,{'id':ident,'target_kind':kind,'target_id':target,
            'finding_id':finding,'assessment_state':'analyzing','transitions':[{'state':'analyzing','at':now()}]},target)
    route='/api/v1/analysis-lifecycle?target_kind=device&target_id=leaf1&finding_id=f1'
    response=client.get(route);assert response.status_code==200
    assert [row['id'] for row in response.json()['records']]==['one']
    assert 'applicability is a separate decision' in response.json()['meaning']
    token=runtime.store.issue_token('read denied fixture','agent','leaf1')['token']
    assert client.get(route,headers={'Authorization':'Bearer '+token}).status_code==403


def test_analytics_records_observations_without_backfilling_unknown_history(service):
    client, runtime, _ = service
    capture_snapshot(runtime.store)
    initial = client.get('/api/v1/analytics?days=30')
    assert initial.status_code == 200, initial.text
    data = initial.json()
    assert len(data['package_trends']) == 1
    assert data['package_trends'][0]['date'] == now()[:10]
    assert data['request_metrics']['average_duration_ms'] is None
    assert data['request_metrics']['cache_hit_rate'] is None
    assert data['request_metrics']['total_requests'] == 0
    _,envelope,_=enroll(client)
    runtime.store.put('finding','test-fixed',{'id':'test-fixed','status':'current','device_id':'ui-test-switch',
        'inventory_digest':envelope['inventory_digest'],'inventory_epoch':envelope['epoch'],
        'build_id':envelope['build_id'],'context_hash':stable_hash([]),
        'package_name':'curl','cve_id':'CVE-TEST-0001','severity':'HIGH','applicability':'fixed'},'ui-test-switch')
    capture_snapshot(runtime.store)
    measured = client.get('/api/v1/analytics?days=7').json()
    assert measured['package_trends'][-1]['components'] == 1
    assert measured['package_trends'][-1]['devices'] == 1
    assert measured['cve_trends'][-1]['fixed'] == 1
    assert measured['cve_trends'][-1]['affected'] == 0
    assert measured['severity_package_grid'][0]['high'] == 1
    assert measured['severity_package_grid'][0]['affected_devices'] == 0


def test_review_requires_existing_scoped_evidence_and_retains_vex_record(service):
    client, runtime, _ = service
    _, envelope, _ = enroll(client)
    finding = {'id':'review-fixture','status':'current','device_id':'ui-test-switch','hostname':'test-switch',
               'inventory_digest':envelope['inventory_digest'],'inventory_epoch':envelope['epoch'],
               'build_id':envelope['build_id'],'context_hash':stable_hash([]),'component_id':'host:curl:amd64','scope':'host',
               'package_name':'curl','affected_version':'7.88.1-10','cve_id':'CVE-TEST-0002','severity':'HIGH',
               'applicability':'under_investigation','evidence_ids':['fixture-evidence'],
               'evidence':[{'id':'fixture-evidence','type':'test_match','data':{'verified_fixture':True}}]}
    runtime.store.put('finding',finding['id'],finding,'ui-test-switch')
    payload = {'applicability':'fixed','justification':'Reviewed the exact synthetic build fixture and its recorded patch evidence.',
               'evidence_ids':['other-component-evidence'],'review_reference':'https://example.test/review'}
    assert client.post('/api/v1/findings/review-fixture/review',json=payload).status_code == 422
    payload['evidence_ids'] = ['fixture-evidence']
    payload['review_reference'] = ''
    assert client.post('/api/v1/findings/review-fixture/review',json=payload).status_code == 422
    payload['review_reference'] = 'https://example.test/review'
    response = client.post('/api/v1/findings/review-fixture/review',json=payload)
    assert response.status_code == 200, response.text
    assert response.json()['applicability'] == 'fixed'
    assert response.json()['decision_basis'] == 'operator_review'
    review = runtime.store.list('reviewed_assessment')[0]
    assert review['component_id'] == finding['component_id']
    assert review['inventory_digest'] == envelope['inventory_digest']
    assert review['device_id'] == envelope['device_id']
    assert review['expires_at']
    vex = client.get('/api/v1/devices/ui-test-switch/vex').json()
    assert vex['statements'][0]['status'] == 'fixed'


@pytest.mark.parametrize('stale_field',['inventory_epoch','build_id','context_hash'])
def test_review_rejects_stale_identity_and_vex_downgrades_it(service,stale_field):
    client,runtime,_=service
    _,envelope,_=enroll(client)
    finding={'id':'stale-review-fixture','status':'current','device_id':envelope['device_id'],
             'inventory_digest':envelope['inventory_digest'],'inventory_epoch':envelope['epoch'],
             'build_id':envelope['build_id'],'context_hash':stable_hash([]),
             'component_id':'host:curl:amd64','scope':'host','package_name':'curl',
             'affected_version':'7.88.1-10','cve_id':'CVE-TEST-STALE','applicability':'fixed',
             'evidence_ids':['stale-evidence'],'evidence':[{'id':'stale-evidence','type':'fixture'}]}
    finding[stale_field]='different-prior-observation'
    runtime.store.put('finding',finding['id'],finding,envelope['device_id'])
    result=client.post('/api/v1/findings/'+finding['id']+'/review',json={
        'applicability':'fixed','justification':'This old observation must not justify the current device state.',
        'evidence_ids':['stale-evidence'],'review_reference':'https://example.test/old-build'})
    assert result.status_code==409,result.text
    vex=client.get('/api/v1/devices/'+envelope['device_id']+'/vex').json()
    assert vex['statements'][0]['status']=='under_investigation'
