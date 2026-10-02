"""Real registry/API signature verification using temporary keys and original SBOM bytes.

Workers are disabled. Only the expensive scanner boundary is substituted in the
explicit release-job persistence test; signatures, parsing, database and HTTP
contracts use the real implementation throughout.
"""
import base64
import hashlib
import json
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.db.store import inventory_hash, now, stable_hash
from app.main import create_app


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def serialize(value):
    return json.dumps(value, indent=2)+'\n'


@pytest.fixture(scope='module')
def builder_key():
    return rsa.generate_private_key(public_exponent=65537,key_size=2048)


@pytest.fixture
def registered_release(tmp_path,builder_key):
    config=Settings(_env_file=None,state_dir=tmp_path/'state',database_url='sqlite:///'+str(tmp_path/'service.db'),
                    jobs_enabled=False,scanner_binary='/not-installed/grype',source_roots=[],ai_enabled=False)
    app=create_app(config)
    with TestClient(app) as client:
        client.headers['Authorization']='Bearer '+(config.state_dir/'bootstrap-token').read_text().strip()
        runtime=app.state.runtime
        keydir=config.state_dir/'trusted-build-keys';keydir.mkdir(mode=0o700)
        keyfile=keydir/'approved-builder.pem'
        keyfile.write_bytes(builder_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        keyfile.chmod(0o644)
        document={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
                  'metadata':{'component':{'type':'operating-system','name':'SONiC fixture','version':'test-build','bom-ref':'test-image'}},
                  'components':[{'type':'library','name':'curl','version':'7.88.1-10','bom-ref':'curl-component',
                                 'purl':'pkg:deb/debian/curl@7.88.1-10?arch=amd64'}]}
        raw_sbom=(json.dumps(document,indent=3)+'\n\n').encode()
        release_id='custom:provenance-api-fixture'
        uploaded=client.post('/api/v1/sbom-upload',data={'release_id':release_id},
                             files={'file':('original.cdx.json',raw_sbom,'application/json')})
        assert uploaded.status_code==201,uploaded.text
        artifact_id=uploaded.json()['artifact_id']
        manifest={'schema_version':1,'build_nonce':'provenance-api-test','platform':'test-platform','architecture':'amd64',
                  'sonic_version':'test-build','source_revision':'a'*40,'host_package_database_sha256':'b'*64,
                  'provenance':'build_pipeline','artifact_binding':'external_release_index'}
        manifest['build_id']='sha256:'+digest(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
        manifest_text=serialize(manifest)
        index={'schema_version':1,'build_id':manifest['build_id'],'manifest_sha256':digest(manifest_text.encode()),
               'artifacts':[{'kind':'image','filename':'sonic.bin','sha256':digest(b'fixture image bytes'),'bytes':19},
                            {'kind':'sbom','filename':'sonic.bin.cdx.json','sha256':digest(raw_sbom),'bytes':len(raw_sbom)}],
               'sbom_available':True}
        index_text=serialize(index)
        signature=builder_key.sign(index_text.encode(),padding.PKCS1v15(),hashes.SHA256())
        request={'release_id':release_id,'manifest_text':manifest_text,'release_index_text':index_text,
                 'signature_base64':base64.b64encode(signature).decode(),'key_id':'approved-builder'}
        yield {'client':client,'runtime':runtime,'config':config,'body':request,'manifest':manifest,
               'raw_sbom':raw_sbom,'document':document,'artifact_id':artifact_id,'upload':uploaded.json(),'keyfile':keyfile}


def enroll(release,device_id,*,build_id=None,manifest_digest=None,manifest=None):
    client=release['client']
    token=client.post('/api/v1/tokens',json={'description':'Temporary provenance test collector',
                      'role':'agent','device_id':device_id})
    assert token.status_code==201,token.text
    headers={'Authorization':'Bearer '+token.json()['token']}
    components=[{'component_id':'host:curl:amd64','scope':'host','name':'curl','version':'7.88.1-10','architecture':'amd64'}]
    envelope={'schema_version':1,'device_id':device_id,'hostname':device_id,'epoch':'provenance-test-epoch','sequence':1,
              'kind':'checkpoint','collected_at':now(),'components':components,'inventory_digest':inventory_hash(components),
              'build_id':build_id if build_id is not None else release['manifest']['build_id'],
              'manifest_digest':manifest_digest if manifest_digest is not None else 'sha256:'+digest(release['body']['manifest_text'].encode()),
              'manifest':release['manifest'] if manifest is None else manifest,'artifact_verified':True}
    response=client.post('/api/v1/agents/sync',json=envelope,headers=headers)
    assert response.status_code==200,response.text
    return headers,envelope


def verify(release):
    result=release['client'].post('/api/v1/artifacts/verify',json=release['body'])
    assert result.status_code==200,result.text
    return result.json()


def test_client_verification_claim_is_never_a_trust_source(registered_release):
    release=registered_release
    enroll(release,'claimed-verified')
    device=release['client'].get('/api/v1/devices/claimed-verified').json()
    assert device['artifact_claimed_verified'] is True
    assert device['artifact_verified'] is False
    assert device['artifact_binding']=='unverified'
    assert device['runtime_attestation']=='not_available'


def test_signed_binding_matches_only_exact_build_and_raw_manifest(registered_release):
    release=registered_release
    enroll(release,'matching-switch')
    enroll(release,'wrong-manifest',manifest_digest='sha256:'+'0'*64)
    enroll(release,'wrong-build',build_id='sha256:'+'1'*64)
    enroll(release,'missing-manifest',manifest_digest='')
    result=verify(release)
    assert result['matched_devices']==['matching-switch']
    assert result['artifact_id']==release['artifact_id']
    assert result['verification']=='signature_verified'
    assert result['runtime_attestation']=='not_available'
    assert result['sbom_digest']=='sha256:'+digest(release['raw_sbom'])
    for ident,verified in [('matching-switch',True),('wrong-manifest',False),('wrong-build',False),('missing-manifest',False)]:
        device=release['client'].get('/api/v1/devices/'+ident).json()
        assert device['artifact_verified'] is verified
        assert device['runtime_attestation']=='not_available'
    stored=release['runtime'].store.get('build_binding',result['build_id'])
    assert stored['verified_by'] and stored['key_fingerprint']
    record=release['client'].get('/api/v1/releases').json()['releases'][0]
    assert record['verification']=='signature_verified'
    assert record['binding']['manifest_digest']==result['manifest_digest']


def test_new_device_reuses_signed_baseline_but_changed_manifest_loses_association(registered_release):
    release=registered_release;verify(release)
    headers,envelope=enroll(release,'later-device')
    assert release['client'].get('/api/v1/devices/later-device').json()['artifact_verified'] is True
    heartbeat={**envelope,'kind':'heartbeat','components':[],'manifest_digest':'sha256:'+'c'*64,'collected_at':now()}
    response=release['client'].post('/api/v1/agents/sync',json=heartbeat,headers=headers)
    assert response.status_code==200,response.text
    device=release['client'].get('/api/v1/devices/later-device').json()
    assert device['artifact_verified'] is False
    assert device['runtime_attestation']=='not_available'


@pytest.mark.parametrize('tamper',['index_bytes','manifest_bytes','unknown_key','signature'])
def test_invalid_signature_binding_cannot_change_registry_or_devices(registered_release,tamper):
    release=registered_release;enroll(release,'untrusted-switch')
    body=dict(release['body'])
    if tamper=='index_bytes':body['release_index_text']+=' '
    elif tamper=='manifest_bytes':body['manifest_text']+=' '
    elif tamper=='unknown_key':body['key_id']='unprovisioned-builder'
    else:body['signature_base64']=base64.b64encode(b'\0'*256).decode()
    result=release['client'].post('/api/v1/artifacts/verify',json=body)
    assert result.status_code==422,result.text
    assert release['runtime'].store.list('build_binding')==[]
    assert release['client'].get('/api/v1/devices/untrusted-switch').json()['artifact_verified'] is False


def test_different_original_sbom_bytes_reject_even_if_json_semantics_match(registered_release):
    release=registered_release
    different=json.dumps(release['document'],sort_keys=True,separators=(',',':')).encode()
    assert digest(different)!=digest(release['raw_sbom'])
    uploaded=release['client'].post('/api/v1/sbom-upload',data={'release_id':release['body']['release_id']},
                       files={'file':('reserialized.cdx.json',different,'application/json')})
    assert uploaded.status_code==201,uploaded.text
    assert uploaded.json()['artifact_id']==release['artifact_id']
    result=release['client'].post('/api/v1/artifacts/verify',json=release['body'])
    assert result.status_code==422,result.text
    assert 'raw SBOM digest' in result.json()['message']


def test_revocation_downgrades_device_and_blocks_agent_claimed_reactivation(registered_release):
    release=registered_release;headers,envelope=enroll(release,'revoked-device')
    binding=verify(release)
    revoked=release['client'].delete('/api/v1/artifacts/bindings/'+quote(binding['build_id'],safe=''))
    assert revoked.status_code==200,revoked.text
    assert release['runtime'].store.get('build_binding',binding['build_id'])['verification']=='revoked'
    device=release['client'].get('/api/v1/devices/revoked-device').json()
    assert device['artifact_verified'] is False
    heartbeat={**envelope,'kind':'heartbeat','components':[],'artifact_verified':True,'collected_at':now()}
    response=release['client'].post('/api/v1/agents/sync',json=heartbeat,headers=headers)
    assert response.status_code==200,response.text
    assert release['client'].get('/api/v1/devices/revoked-device').json()['artifact_verified'] is False
    enroll(release,'new-device-after-revoke')
    assert release['client'].get('/api/v1/devices/new-device-after-revoke').json()['artifact_verified'] is False


def test_agent_and_operator_cannot_approve_or_revoke_builder_trust(registered_release):
    release=registered_release;headers,_=enroll(release,'restricted-agent')
    assert release['client'].post('/api/v1/artifacts/verify',json=release['body'],headers=headers).status_code==403
    binding=verify(release)
    url='/api/v1/artifacts/bindings/'+quote(binding['build_id'],safe='')
    assert release['client'].delete(url,headers=headers).status_code==403
    operator=release['client'].post('/api/v1/tokens',json={'description':'Restricted operator','role':'operator'}).json()
    operator_headers={'Authorization':'Bearer '+operator['token']}
    assert release['client'].post('/api/v1/artifacts/verify',json=release['body'],headers=operator_headers).status_code==403
    assert release['client'].delete(url,headers=operator_headers).status_code==403


def test_background_release_handler_preserves_original_upload_digest(registered_release,monkeypatch):
    release=registered_release;runtime=release['runtime']
    artifact=runtime.store.get('artifact',release['artifact_id'])
    assert artifact['source_sha256']==digest(release['raw_sbom'])
    assert artifact['source_sha256']!=stable_hash(release['document'])
    binding=verify(release)
    def scanner_boundary(inventory,context):
        assert context['artifact_verified'] is False
        return {'findings':[],'evidence':[],'coverage':{'complete':True,'scopes_scanned':len(inventory['scopes'])},
                'scanner':{'status':'complete'},'errors':[],'ai_usage':{}}
    monkeypatch.setattr(runtime.pipeline,'analyze',scanner_boundary)
    operation=runtime.store.operation(release['upload']['operation_id'])
    assert operation['operation_type']=='release_sync' and operation['status']=='queued'
    result=runtime._job_release_sync(operation)
    assert result['status']=='analyzed'
    after=runtime.store.get('artifact',release['artifact_id'])
    assert after['source_sha256']==digest(release['raw_sbom'])
    assert runtime.store.get('build_binding',binding['build_id'])['verification']=='signature_verified'
    assert verify(release)['sbom_digest']==binding['sbom_digest']


def test_revocation_updates_operator_visible_release_binding(registered_release):
    release=registered_release;binding=verify(release)
    result=release['client'].delete('/api/v1/artifacts/bindings/'+quote(binding['build_id'],safe=''))
    assert result.status_code==200,result.text
    record=release['client'].get('/api/v1/releases').json()['releases'][0]
    assert record['verification']=='revoked'
    assert record['binding']['verification']=='revoked'


def test_reuploading_new_raw_bytes_invalidates_old_binding_before_background_work(registered_release):
    release=registered_release;enroll(release,'reimported-device');binding=verify(release)
    assert release['client'].get('/api/v1/devices/reimported-device').json()['artifact_verified'] is True
    changed=json.dumps(release['document'],sort_keys=True,separators=(',',':')).encode()
    assert digest(changed)!=digest(release['raw_sbom'])
    result=release['client'].post('/api/v1/sbom-upload',data={'release_id':release['body']['release_id']},
                          files={'file':('reimported.cdx.json',changed,'application/json')})
    assert result.status_code==201,result.text
    assert result.json()['artifact_id']==release['artifact_id']
    assert release['runtime'].store.get('build_binding',binding['build_id'])['verification']!='signature_verified'
    assert release['client'].get('/api/v1/devices/reimported-device').json()['artifact_verified'] is False
    assert release['client'].post('/api/v1/artifacts/verify',json=release['body']).status_code==422


def test_reported_manifest_content_cannot_borrow_another_manifests_raw_hash(registered_release):
    release=registered_release
    altered={**release['manifest'],'source_revision':'f'*40}
    enroll(release,'tampered-before-verification',manifest=altered)
    binding=verify(release)
    assert binding['matched_devices']==[]
    before=release['client'].get('/api/v1/devices/tampered-before-verification').json()
    assert before['artifact_verified'] is False
    assert not before.get('bound_manifest')
    headers,envelope=enroll(release,'tampered-after-verification',manifest=altered)
    after=release['client'].get('/api/v1/devices/tampered-after-verification').json()
    assert after['artifact_verified'] is False
    assert not after.get('bound_manifest')
    corrected={**envelope,'kind':'heartbeat','components':[],'manifest':release['manifest'],'collected_at':now()}
    response=release['client'].post('/api/v1/agents/sync',json=corrected,headers=headers)
    assert response.status_code==200,response.text
    associated=release['client'].get('/api/v1/devices/tampered-after-verification').json()
    assert associated['artifact_verified'] is True
    assert associated['bound_manifest']==release['manifest']
    assert associated['runtime_attestation']=='not_available'


def test_one_build_identity_cannot_be_rebound_to_another_image(registered_release,builder_key):
    release=registered_release;first=verify(release)
    body=dict(release['body']);index=json.loads(body['release_index_text'])
    index['artifacts'][0]['sha256']=digest(b'different image bytes')
    body['release_index_text']=serialize(index)
    body['signature_base64']=base64.b64encode(builder_key.sign(
        body['release_index_text'].encode(),padding.PKCS1v15(),hashes.SHA256())).decode()
    result=release['client'].post('/api/v1/artifacts/verify',json=body)
    assert result.status_code==409,result.text
    assert 'collision' in result.json()['message'].lower()
    stored=release['runtime'].store.get('build_binding',first['build_id'])
    assert stored['image_digest']==first['image_digest']
    assert stored['index_digest']==first['index_digest']


def test_revocation_immediately_downgrades_vex_for_old_trusted_findings(registered_release):
    release=registered_release;_,envelope=enroll(release,'vex-revocation-device');binding=verify(release)
    runtime=release['runtime']
    finding={'component_id':'host:curl:amd64','scope_id':'host','package_name':'curl','affected_version':'7.88.1-10',
             'cve_id':'CVE-TEST-REVOKED','applicability':'fixed','severity':'HIGH','rationale':'Synthetic signed-baseline decision'}
    assert runtime.store.store_findings('vex-revocation-device',envelope['inventory_digest'],
        {'findings':[finding],'evidence':[],'coverage':{'complete':True}},'fixture-assessment')
    url='/api/v1/devices/vex-revocation-device/vex'
    assert release['client'].get(url).json()['statements'][0]['status']=='fixed'
    revoked=release['client'].delete('/api/v1/artifacts/bindings/'+quote(binding['build_id'],safe=''))
    assert revoked.status_code==200,revoked.text
    assert release['client'].get(url).json()['statements'][0]['status']=='under_investigation'
