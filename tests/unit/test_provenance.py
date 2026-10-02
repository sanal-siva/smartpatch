"""Signed baseline binding tests; all keys/artifacts are temporary test fixtures."""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.services.provenance import MAX_DOCUMENT_BYTES, ProvenanceVerificationError, verify_release_binding


def encoded(value):
    return json.dumps(value, indent=2)+'\n'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def sign(key, text):
    raw = text.encode()
    signature = key.sign(raw, padding.PKCS1v15(), hashes.SHA256()) if isinstance(key,rsa.RSAPrivateKey) else key.sign(raw)
    return base64.b64encode(signature).decode()


def approve(directory, key, name='test-builder'):
    directory.mkdir(exist_ok=True)
    directory.chmod(0o755)
    path=directory/(name+'.pem')
    path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    path.chmod(0o644)
    return path


@pytest.fixture(scope='module')
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537,key_size=2048)


@pytest.fixture
def release(tmp_path,rsa_key):
    keys=tmp_path/'trusted-build-keys';approve(keys,rsa_key)
    manifest={'schema_version':1,'build_nonce':'test-nonce','platform':'test-platform','architecture':'amd64',
              'sonic_version':'test-build','source_revision':'a'*40,'host_package_database_sha256':'b'*64,
              'provenance':'build_pipeline','artifact_binding':'external_release_index'}
    manifest['build_id']='sha256:'+sha(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
    manifest_text=encoded(manifest)
    sbom=b'{"bomFormat":"CycloneDX","components":[]}\n'
    index={'schema_version':1,'build_id':manifest['build_id'],'manifest_sha256':sha(manifest_text.encode()),
           'artifacts':[{'kind':'image','filename':'sonic.bin','sha256':sha(b'image-fixture'),'bytes':13},
                        {'kind':'sbom','filename':'sonic.bin.cdx.json','sha256':sha(sbom),'bytes':len(sbom)}],
           'sbom_available':True}
    body={'release_id':'custom:test-build','manifest_text':manifest_text,'release_index_text':encoded(index),
          'signature_base64':sign(rsa_key,encoded(index)),'key_id':'test-builder'}
    artifact={'id':'test-artifact','release_id':body['release_id'],'source_sha256':sha(sbom)}
    return body,artifact,keys,index,manifest


def resign(body,index,key):
    body['release_index_text']=encoded(index)
    body['signature_base64']=sign(key,body['release_index_text'])


def test_valid_rsa_signature_binds_original_bytes_and_records_public_metadata(release):
    body,artifact,keys,index,manifest=release
    result=verify_release_binding(body,artifact,keys)
    assert result['build_id']==manifest['build_id']
    assert result['manifest_digest']=='sha256:'+index['manifest_sha256']
    assert result['sbom_digest']=='sha256:'+artifact['source_sha256']
    assert result['image_digest']=='sha256:'+index['artifacts'][0]['sha256']
    assert result['verification']=='signature_verified'
    assert result['binding_scope']=='signed_release_baseline'
    assert result['signature_algorithm']=='rsa-pkcs1v15-sha256'
    assert result['key_fingerprint'].startswith('sha256:') and result['verified_at'].endswith('Z')
    assert 'private' not in json.dumps(result).lower()


def test_ed25519_builder_is_supported(release):
    body,artifact,keys,_,_=release
    key=ed25519.Ed25519PrivateKey.generate();approve(keys,key)
    body['signature_base64']=sign(key,body['release_index_text'])
    assert verify_release_binding(body,artifact,keys)['signature_algorithm']=='ed25519'


@pytest.mark.parametrize('change',['trailing_space','different_digest'])
def test_signature_covers_exact_index_bytes(release,change):
    body,artifact,keys,_,_=release
    if change=='trailing_space':body['release_index_text']+=' '
    else:body['release_index_text']=body['release_index_text'].replace('sonic.bin','different.bin')
    with pytest.raises(ProvenanceVerificationError,match='signature verification failed'):
        verify_release_binding(body,artifact,keys)


def test_wrong_approved_key_cannot_verify_index(release):
    body,artifact,keys,_,_=release
    approve(keys,rsa.generate_private_key(public_exponent=65537,key_size=2048))
    with pytest.raises(ProvenanceVerificationError,match='signature verification failed'):
        verify_release_binding(body,artifact,keys)


def test_manifest_raw_byte_changes_are_detected(release):
    body,artifact,keys,_,_=release
    body['manifest_text']=json.dumps(json.loads(body['manifest_text']),separators=(',',':'))
    with pytest.raises(ProvenanceVerificationError,match='Manifest digest'):
        verify_release_binding(body,artifact,keys)


def test_manifest_index_build_identity_mismatch_is_rejected(release,rsa_key):
    body,artifact,keys,index,_=release
    index['build_id']='sha256:'+'f'*64;resign(body,index,rsa_key)
    with pytest.raises(ProvenanceVerificationError,match='build_id values must match'):
        verify_release_binding(body,artifact,keys)


def test_canonical_manifest_identity_is_checked_even_with_valid_signature(release,rsa_key):
    body,artifact,keys,index,manifest=release
    manifest['source_revision']='c'*40
    body['manifest_text']=encoded(manifest);index['manifest_sha256']=sha(body['manifest_text'].encode())
    resign(body,index,rsa_key)
    with pytest.raises(ProvenanceVerificationError,match='canonical build identity'):
        verify_release_binding(body,artifact,keys)


def test_registered_raw_sbom_digest_must_match_and_has_no_canonical_fallback(release):
    body,artifact,keys,_,_=release
    artifact['source_sha256']='f'*64
    with pytest.raises(ProvenanceVerificationError,match='Registered raw SBOM digest'):
        verify_release_binding(body,artifact,keys)
    artifact.pop('source_sha256');artifact['digest']='sha256:'+'f'*64
    with pytest.raises(ProvenanceVerificationError,match='source_sha256'):
        verify_release_binding(body,artifact,keys)


@pytest.mark.parametrize('missing',['image','sbom'])
def test_index_requires_both_release_artifacts(release,rsa_key,missing):
    body,artifact,keys,index,_=release
    index['artifacts']=[item for item in index['artifacts'] if item['kind']!=missing]
    resign(body,index,rsa_key)
    with pytest.raises(ProvenanceVerificationError,match='both image and SBOM'):
        verify_release_binding(body,artifact,keys)


def test_duplicate_artifact_kind_is_ambiguous(release,rsa_key):
    body,artifact,keys,index,_=release
    index['artifacts'].append(dict(index['artifacts'][0]));resign(body,index,rsa_key)
    with pytest.raises(ProvenanceVerificationError,match='unique'):
        verify_release_binding(body,artifact,keys)


def test_duplicate_json_keys_are_rejected_even_when_signed(release,rsa_key):
    body,artifact,keys,_,_=release
    body['release_index_text']=body['release_index_text'].replace('"schema_version": 1','"schema_version": 1, "schema_version": 1')
    body['signature_base64']=sign(rsa_key,body['release_index_text'])
    with pytest.raises(ProvenanceVerificationError,match='Duplicate JSON'):
        verify_release_binding(body,artifact,keys)


@pytest.mark.parametrize('key_id',['../test-builder','/tmp/test-builder','a/b','a\\b','..','%2e%2e%2fkey'])
def test_key_identifiers_cannot_escape_approved_directory(release,key_id):
    body,artifact,keys,_,_=release;body['key_id']=key_id
    with pytest.raises(ProvenanceVerificationError,match='safe approved-key'):
        verify_release_binding(body,artifact,keys)


def test_key_symlink_cannot_read_outside_approved_directory(release,tmp_path):
    body,artifact,keys,_,_=release
    path=keys/'test-builder.pem';outside=tmp_path/'outside.pem';outside.write_bytes(path.read_bytes())
    path.unlink();path.symlink_to(outside)
    with pytest.raises(ProvenanceVerificationError,match='forbidden symlink'):
        verify_release_binding(body,artifact,keys)


def test_trusted_directory_symlink_is_rejected(release,tmp_path):
    body,artifact,keys,_,_=release
    alias=tmp_path/'key-alias';alias.symlink_to(keys,target_is_directory=True)
    with pytest.raises(ProvenanceVerificationError,match='forbidden symlink'):
        verify_release_binding(body,artifact,alias)


def test_group_writable_public_key_is_not_trusted(release):
    body,artifact,keys,_,_=release;(keys/'test-builder.pem').chmod(0o664)
    with pytest.raises(ProvenanceVerificationError,match='writable by group'):
        verify_release_binding(body,artifact,keys)


@pytest.mark.parametrize('field',['manifest_text','release_index_text'])
def test_raw_documents_have_byte_bounds(release,field):
    body,artifact,keys,_,_=release;body[field]='x'*(MAX_DOCUMENT_BYTES+1)
    with pytest.raises(ProvenanceVerificationError,match='1 MiB'):
        verify_release_binding(body,artifact,keys)


def test_multibyte_unicode_is_counted_in_byte_budget(release):
    body,artifact,keys,_,_=release;body['manifest_text']='☃'*400000
    with pytest.raises(ProvenanceVerificationError,match='UTF-8 byte limit'):
        verify_release_binding(body,artifact,keys)


@pytest.mark.parametrize('signature',['not:base64','A'*4097,''])
def test_invalid_or_unbounded_signatures_are_rejected(release,signature):
    body,artifact,keys,_,_=release;body['signature_base64']=signature
    with pytest.raises(ProvenanceVerificationError,match='base64'):
        verify_release_binding(body,artifact,keys)


def test_no_request_supplied_key_material_is_accepted(release):
    body,artifact,keys,_,_=release;body['public_key']='unapproved key'
    with pytest.raises(ProvenanceVerificationError,match='Supply exactly'):
        verify_release_binding(body,artifact,keys)


def test_artifact_must_be_registered_for_requested_release(release):
    body,artifact,keys,_,_=release
    with pytest.raises(ProvenanceVerificationError,match='registered SBOM artifact'):
        verify_release_binding(body,None,keys)
    artifact['release_id']='custom:other'
    with pytest.raises(ProvenanceVerificationError,match='different release'):
        verify_release_binding(body,artifact,keys)


def test_unsupported_elliptic_curve_key_is_rejected(release):
    body,artifact,keys,_,_=release;approve(keys,ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ProvenanceVerificationError,match='Only RSA and Ed25519'):
        verify_release_binding(body,artifact,keys)


def test_actual_community_manifest_producer_interoperates(tmp_path,rsa_key):
    producer=Path(__file__).resolve().parents[3]/'sonic-buildimage/src/sonic-smart-patch/scripts/smart-patch-manifest.py'
    if not producer.is_file():pytest.skip('Community SONiC producer checkout is not available')
    rootfs=tmp_path/'rootfs';(rootfs/'var/lib/dpkg').mkdir(parents=True)
    (rootfs/'var/lib/dpkg/status').write_text('Package: fixture\nVersion: 1.0\n')
    manifest=tmp_path/'manifest.json';image=tmp_path/'sonic-test.bin';image.write_bytes(b'fixture image')
    sbom=Path(str(image)+'.cdx.json');sbom.write_bytes(b'{"components":[]}\n')
    subprocess.run([sys.executable,str(producer),'--rootfs',str(rootfs),'--source-revision','a'*40,'--manifest',str(manifest)],check=True)
    subprocess.run([sys.executable,str(producer),'--manifest',str(manifest),'--artifact',str(image)],check=True)
    index=Path(str(image)+'.smart-patch.json').read_text()
    keys=tmp_path/'keys';approve(keys,rsa_key)
    result=verify_release_binding({'release_id':'custom:producer','manifest_text':manifest.read_text(),
           'release_index_text':index,'signature_base64':sign(rsa_key,index),'key_id':'test-builder'},
           {'source_sha256':sha(sbom.read_bytes())},keys)
    assert result['manifest_digest']=='sha256:'+sha((rootfs/'etc/sonic/smart-patch/manifest.json').read_bytes())
    assert result['image_digest']=='sha256:'+sha(image.read_bytes())


def test_group_writable_trusted_directory_is_rejected(release):
    body,artifact,keys,_,_=release;keys.chmod(0o775)
    with pytest.raises(ProvenanceVerificationError,match='key directory must not be writable'):
        verify_release_binding(body,artifact,keys)
