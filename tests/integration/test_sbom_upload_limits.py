"""SBOM-specific upload budgets, including actual 50 MiB multipart input."""
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app, RequestSizeLimit, request_byte_limit, SBOM_MULTIPART_OVERHEAD

DOCUMENT=json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
    'components':[{'type':'library','name':'fixture','version':'1.0'}]}).encode()


def config(tmp_path, **values):
    return Settings(_env_file=None,state_dir=tmp_path/'state',database_url='sqlite:///'+str(tmp_path/'db'),
        jobs_enabled=False,source_roots=[],scanner_binary='/not-installed/grype',**values)


def authenticated(app):
    client=TestClient(app)
    client.__enter__()
    client.headers['Authorization']='Bearer '+(app.state.runtime.settings.state_dir/'bootstrap-token').read_text().strip()
    return client


def test_default_50_mib_actual_document_accepts_exact_file_boundary(tmp_path):
    settings=config(tmp_path)
    assert settings.max_sbom_upload_bytes==50*1024*1024
    path=tmp_path/'large.json'
    with path.open('wb') as output:
        output.write(DOCUMENT)
        remaining=settings.max_sbom_upload_bytes-len(DOCUMENT)
        while remaining:
            chunk=min(remaining,1024*1024);output.write(b' '*chunk);remaining-=chunk
    client=authenticated(create_app(settings))
    try:
        limits=client.get('/api/v1/upload-limits').json()
        assert limits=={'sbom_bytes':50*1024*1024,'request_bytes':16*1024*1024}
        with path.open('rb') as source:
            response=client.post('/api/v1/sbom-upload',data={'release_id':'boundary-fixture'},
                files={'file':('large.json',source,'application/json')})
        assert response.status_code==201,response.text
        assert response.json()['packages_count']==1
    finally:client.__exit__(None,None,None)


def test_file_boundary_and_admin_alias_reject_one_extra_byte(tmp_path):
    settings=config(tmp_path,max_sbom_upload_bytes=1024)
    client=authenticated(create_app(settings))
    try:
        for route in ('/api/v1/sbom-upload','/admin/sbom-upload'):
            response=client.post(route,data={'release_id':'boundary-fixture'},files={
                'file':('large.json',DOCUMENT+b' '*(1025-len(DOCUMENT)),'application/json')})
            assert response.status_code==413,response.text
            assert 'MiB limit' in response.json()['message']
        response=client.post('/api/v1/agents/sync',content=b'{}',headers={'Content-Length':str(settings.max_request_bytes+1)})
        assert response.status_code==413
    finally:client.__exit__(None,None,None)


@pytest.mark.asyncio
async def test_streamed_bytes_are_bounded_without_content_length(tmp_path):
    settings=config(tmp_path,max_sbom_upload_bytes=1024,max_request_bytes=512)
    consumed=[]
    async def downstream(scope,receive,send):
        while True:
            message=await receive();consumed.append(len(message.get('body',b'')))
            if not message.get('more_body'):break
    async def receive():return {'type':'http.request','body':b'x'*1024,'more_body':True}
    async def send(message):pass
    bounded=RequestSizeLimit(downstream,settings.max_request_bytes,settings)
    with pytest.raises(HTTPException) as failed:
        await bounded({'type':'http','path':'/api/v1/sbom-upload','method':'POST'},receive,send)
    assert failed.value.status_code==413
    assert sum(consumed)<=1024+SBOM_MULTIPART_OVERHEAD
    consumed.clear()
    with pytest.raises(HTTPException):
        await bounded({'type':'http','path':'/api/v1/agents/sync','method':'POST'},receive,send)
    assert not consumed
    assert request_byte_limit(settings,'/api/v1/sbom-upload','GET')==512
    assert request_byte_limit(settings,'/api/v1/sbom-upload/other','POST')==512
