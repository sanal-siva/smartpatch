"""Staged-maintenance HTTP contracts, using an explicit synthetic finding fixture.

Collector acknowledgements are protocol fixtures, not hardware preflight results.
No real package is staged or installed by these tests.
"""
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db.store import inventory_hash, now
from app.main import create_app


class AgentHeaders(dict):
    def __repr__(self):
        return "{'Authorization': '<temporary test credential>'}"


@pytest.fixture
def maintenance(tmp_path):
    config=Settings(_env_file=None,state_dir=tmp_path/'state',database_url='sqlite:///'+str(tmp_path/'db.sqlite'),
                    jobs_enabled=False,scanner_binary='/not-installed/grype',source_roots=[],ai_enabled=False)
    app=create_app(config)
    with TestClient(app) as client:
        client.headers['Authorization']='Bearer '+(config.state_dir/'bootstrap-token').read_text().strip()
        runtime=app.state.runtime
        token=client.post('/api/v1/tokens',json={'description':'Synthetic maintenance collector','role':'agent','device_id':'maintenance-test'}).json()
        headers=AgentHeaders(Authorization='Bearer '+token['token'])
        component={'component_id':'host:smart-patch-testprobe:amd64','scope':'host','name':'smart-patch-testprobe','version':'1.0',
                   'architecture':'amd64','distro':{'name':'debian','version':'12'}}
        envelope={'schema_version':1,'device_id':'maintenance-test','hostname':'test-switch','build_id':'synthetic-build',
                  'epoch':'maintenance-epoch','sequence':1,'kind':'checkpoint','collected_at':now(),
                  'components':[component],'inventory_digest':inventory_hash([component])}
        enrolled=client.post('/api/v1/agents/sync',json=envelope,headers=headers)
        assert enrolled.status_code==200,enrolled.text
        finding={'component_id':component['component_id'],'scope_id':'host','package_name':component['name'],
                 'affected_version':'1.0','cve_id':'SYNTHETIC-MAINTENANCE-NOT-A-CVE','severity':'HIGH','applicability':'affected',
                 'fixed_versions':['1.1'],'candidate_fixed_versions':['1.1'],'rationale':'Synthetic API workflow fixture',
                 'component':{'name':component['name'],'version':'1.0','ecosystem':'deb','architecture':'amd64'}}
        assert runtime.store.store_findings('maintenance-test',envelope['inventory_digest'],
                                           {'findings':[finding],'evidence':[],'coverage':{'complete':True}},'fixture-assessment')
        record=runtime.store.list('finding',owner='maintenance-test')[0]
        created=client.post('/api/v1/plans',json={'device_id':'maintenance-test','finding_ids':[record['id']]})
        assert created.status_code==201,created.text
        yield {'client':client,'runtime':runtime,'plan':created.json(),'agent':headers,'envelope':envelope}


def endpoint(fixture,action):
    return '/api/v1/plans/'+fixture['plan']['id']+'/'+action


def stage(fixture):
    client=fixture['client']
    approved=client.post(endpoint(fixture,'approve'),json={})
    assert approved.status_code==200,approved.text
    staged=client.post(endpoint(fixture,'stage'),json={})
    assert staged.status_code==202,staged.text
    return staged.json()


def acknowledge(fixture,request_id,status,collector='maintenance_action',details=None):
    fact={'fact_id':request_id,'collector':collector,'status':'complete','collected_at':now(),
          'value':{'status':status,'fixture':'API protocol fixture; not a real package operation'}}
    if details is not None:
        fact['value']['details']=details
    heartbeat={**fixture['envelope'],'kind':'heartbeat','components':[],'facts':[fact],'collected_at':now()}
    response=fixture['client'].post('/api/v1/agents/sync',json=heartbeat,headers=fixture['agent'])
    assert response.status_code==200,response.text
    return response


def test_advisory_candidate_requires_approval_then_separate_staging(maintenance):
    fixture=maintenance;client=fixture['client'];plan=fixture['plan']
    assert plan['status']=='draft' and plan['staging_eligible'] is True
    assert plan['execution_eligible'] is False
    assert plan['target_resolution']['target_options'][0]['status']=='candidate_only'
    assert plan['target_resolution']['repository_availability']=='unknown'
    assert client.post(endpoint(fixture,'stage'),json={}).status_code==409
    confirm={'confirmed_device_id':'maintenance-test'}
    assert client.post(endpoint(fixture,'execute'),json=confirm).status_code==409
    approved=client.post(endpoint(fixture,'approve'),json={}).json()
    assert approved['approved'] is True and approved['execution_eligible'] is False
    assert client.post(endpoint(fixture,'execute'),json=confirm).status_code==409
    result=client.post(endpoint(fixture,'stage'),json={})
    assert result.status_code==202,result.text
    queued=result.json()
    assert queued['status']=='staging_queued' and queued['execution_eligible'] is False
    request=fixture['runtime'].store.get('action_request',queued['stage_request_id'])
    assert request['action']=='stage_plan' and request['status']=='queued'
    assert client.post(endpoint(fixture,'execute'),json=confirm).status_code==409


@pytest.mark.parametrize('reported_status',['staging_failed','unknown','staged'])
def test_execution_depends_on_successful_stage_report_and_exact_confirmation(maintenance,reported_status):
    fixture=maintenance;client=fixture['client'];queued=stage(fixture)
    acknowledge(fixture,queued['stage_request_id'],reported_status)
    current=client.get('/api/v1/plans/'+fixture['plan']['id']).json()
    assert current['status']==reported_status
    assert current['execution_eligible'] is (reported_status=='staged')
    if reported_status!='staged':
        assert client.post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'}).status_code==409
        assert not [r for r in fixture['runtime'].store.list('action_request') if r['action']=='execute_plan']
        return
    assert client.post(endpoint(fixture,'execute'),json={'confirmed_device_id':'wrong-device'}).status_code==422
    response=client.post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'})
    assert response.status_code==202,response.text
    executed=response.json()
    assert executed['status']=='queued'
    assert executed['action_request_id']!=queued['stage_request_id']
    assert fixture['runtime'].store.get('action_request',executed['action_request_id'])['action']=='execute_plan'


def test_optional_checks_and_missing_rollback_are_recorded_without_automatic_execution(maintenance):
    fixture=maintenance;client=fixture['client'];store=fixture['runtime'].store
    queued=stage(fixture)
    details={'maintenance_checks_enabled':False,'checks_skipped':['free_space','dependency_policy','rollback_required'],
             'rollback_available':False,'rollback_missing':[{'package':'smart-patch-testprobe','version':'1.0',
                 'reason':'Synthetic fixture: exact installed version unavailable from repository'}]}
    response=acknowledge(fixture,queued['stage_request_id'],'staged',details=details)
    assert response.json()['action_requests']==[]
    current=client.get('/api/v1/plans/'+fixture['plan']['id']).json()
    assert current['status']=='staged' and current['execution_eligible'] is True
    assert current['staging_result']['value']['details']==details
    assert current['execution_result']['value']['details']==details
    assert store.get('action_request',queued['stage_request_id'])['result']['value']['details']==details
    assert not [row for row in store.list('action_request') if row['action']=='execute_plan']

    wrong=client.post(endpoint(fixture,'execute'),json={'confirmed_device_id':'wrong-device'})
    assert wrong.status_code==422,wrong.text
    assert not [row for row in store.list('action_request') if row['action']=='execute_plan']
    still_staged=client.get('/api/v1/plans/'+fixture['plan']['id']).json()
    assert still_staged['status']=='staged' and still_staged['execution_eligible'] is True

    confirmed=client.post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'})
    assert confirmed.status_code==202,confirmed.text
    executed=confirmed.json()
    assert executed['status']=='queued' and executed['execution_eligible'] is False
    assert executed['staging_result']['value']['details']==details
    requests=[row for row in store.list('action_request') if row['action']=='execute_plan']
    assert len(requests)==1 and requests[0]['request_id']==executed['action_request_id']
    assert requests[0]['plan']['staging_result']['value']['details']==details


def test_target_recheck_is_a_scoped_job_and_clears_approval(maintenance):
    fixture=maintenance;client=fixture['client']
    assert client.post(endpoint(fixture,'approve'),json={}).status_code==200
    result=client.post(endpoint(fixture,'validate-target'),json={'target_version':'1.1'})
    assert result.status_code==202,result.text
    operation=fixture['runtime'].store.operation(result.json()['operation_id'])
    assert operation['operation_type']=='plan_validate'
    assert operation['arguments']=={'plan_id':fixture['plan']['id'],'target_version':'1.1'}
    current=client.get('/api/v1/plans/'+fixture['plan']['id']).json()
    assert current['status']=='validating_target'
    assert current['approved'] is False and current['staging_eligible'] is False and current['execution_eligible'] is False
    assert client.post(endpoint(fixture,'stage'),json={}).status_code==409


def test_expired_plan_cannot_queue_staging(maintenance):
    fixture=maintenance
    assert fixture['client'].post(endpoint(fixture,'approve'),json={}).status_code==200
    plan=fixture['runtime'].store.get('plan',fixture['plan']['id'])
    fixture['runtime'].store.put('plan',plan['id'],{**plan,'expires_at':'2000-01-01T00:00:00Z'},plan['device_id'])
    result=fixture['client'].post(endpoint(fixture,'stage'),json={})
    assert result.status_code==409,result.text
    assert not fixture['runtime'].store.list('action_request')


def test_old_stage_ack_does_not_reopen_an_already_queued_execution(maintenance):
    fixture=maintenance;queued=stage(fixture)
    acknowledge(fixture,queued['stage_request_id'],'staged')
    executed=fixture['client'].post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'})
    assert executed.status_code==202,executed.text
    acknowledge(fixture,queued['stage_request_id'],'staged')
    current=fixture['client'].get('/api/v1/plans/'+fixture['plan']['id']).json()
    assert current['status']=='queued'
    duplicate=fixture['client'].post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'})
    assert duplicate.status_code==409,duplicate.text
    assert len([r for r in fixture['runtime'].store.list('action_request') if r['action']=='execute_plan'])==1


def test_new_review_invalidates_a_previously_staged_plan(maintenance):
    fixture=maintenance;queued=stage(fixture)
    acknowledge(fixture,queued['stage_request_id'],'staged')
    fixture['runtime'].store.update_device('maintenance-test',{'review_revision':'new-review-retracts-old-decision'})
    result=fixture['client'].post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'})
    assert result.status_code==409,result.text
    assert not [r for r in fixture['runtime'].store.list('action_request') if r['action']=='execute_plan']


def test_queued_execution_is_not_delivered_after_review_retraction(maintenance):
    fixture=maintenance;queued=stage(fixture)
    acknowledge(fixture,queued['stage_request_id'],'staged')
    result=fixture['client'].post(endpoint(fixture,'execute'),json={'confirmed_device_id':'maintenance-test'})
    assert result.status_code==202,result.text
    fixture['runtime'].store.update_device('maintenance-test',{'review_revision':'retracted-before-delivery'})
    heartbeat={**fixture['envelope'],'kind':'heartbeat','components':[],'facts':[],'collected_at':now()}
    response=fixture['client'].post('/api/v1/agents/sync',json=heartbeat,headers=fixture['agent'])
    assert response.status_code==200,response.text
    assert response.json()['action_requests']==[]
    current=fixture['client'].get('/api/v1/plans/'+fixture['plan']['id']).json()
    assert current['status']=='requires_revalidation' and current['execution_eligible'] is False


@pytest.mark.parametrize('collector',['remediation','maintenance_action'])
def test_stage_receipt_keeps_review_current_but_listener_change_requires_reassessment(maintenance,collector):
    fixture=maintenance;client=fixture['client'];store=fixture['runtime'].store
    finding=store.list('finding',owner='maintenance-test')[0]
    # This is a protocol fixture, not evidence that a real package is vulnerable.
    store.put('finding',finding['id'],{**finding,'evidence_ids':['fixture-scan'],
              'evidence':[{'id':'fixture-scan','type':'synthetic_test_fixture'}]},'maintenance-test')
    reviewed=client.post('/api/v1/findings/'+finding['id']+'/review',json={
        'applicability':'affected','justification':'Synthetic review used only to exercise the staging protocol invariant.',
        'evidence_ids':['fixture-scan']})
    assert reviewed.status_code==200,reviewed.text
    deadline=reviewed.json()['decision_valid_until']
    created=client.post('/api/v1/plans',json={'device_id':'maintenance-test','finding_ids':[finding['id']]})
    assert created.status_code==201,created.text
    fixture['plan']=created.json()
    queued=stage(fixture)
    operation_ids={row['id'] for row in store.operations()}
    acknowledged=acknowledge(fixture,queued['stage_request_id'],'staged',collector).json()
    assert 'operation_id' not in acknowledged
    assert {row['id'] for row in store.operations()}==operation_ids
    assert acknowledged['findings'][0]['applicability']=='affected'
    current=client.get('/api/v1/findings/'+finding['id']).json()
    assert current['decision_basis']=='operator_review' and current['applicability']=='affected'
    assert current['decision_valid_until']==deadline and not current.get('assessment_stale')
    assert store.get('action_request',queued['stage_request_id'])['result']['collector']==collector
    assert client.get('/api/v1/plans/'+fixture['plan']['id']).json()['execution_eligible'] is True
    # Genuine listeners evidence remains part of the context and invalidates the old review.
    heartbeat={**fixture['envelope'],'kind':'heartbeat','components':[],'collected_at':now(),
        'facts':[{'collector':'listeners','scope':'host','status':'observed','collected_at':now(),
                  'value':[{'port':443,'address':'0.0.0.0'}]}]}
    changed=client.post('/api/v1/agents/sync',json=heartbeat,headers=fixture['agent'])
    assert changed.status_code==200,changed.text
    assert changed.json().get('operation_id')
    current=client.get('/api/v1/findings/'+finding['id']).json()
    assert current['assessment_stale'] is True and current['applicability']=='under_investigation'
