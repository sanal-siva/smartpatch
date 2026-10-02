"""Synthetic collector reports: no real switches, APT, Docker or network calls."""
import copy
from datetime import datetime, timezone, timedelta

import pytest

from app.db.store import stable_hash
from app.services.maintenance_commands import device_busy, transaction
from app.services.applicability_context import applicability_facts, assessment_facts
from .test_remediation_batches_acceptance import fleet, CVE

ENDPOINT='/api/v1/agents/remediation'


def report_body(fleet, ident, status='planned', revision=1, **overrides):
    device=fleet.devices[ident];finding=device['finding'];component=device['component']
    report={'local_plan_id':'fixture-local-'+ident,'revision':revision,'origin':'cli',
        'scope':component['scope'],'package_name':component['name'],'from_version':finding['affected_version'],
        'target_version':device['target'],'component_id':component['component_id'],
        'architecture':component['architecture'],'finding_ids':[finding['id']],'cve_ids':[CVE],
        'inventory_digest':finding['inventory_digest'],'inventory_epoch':finding['inventory_epoch'],
        'build_id':finding['build_id'],'status':status,'progress':{'phase':status},**overrides}
    body={'device_id':ident,'epoch':device['envelope']['epoch'],'build_id':device['envelope']['build_id'],
          'inventory_digest':device['envelope']['inventory_digest'],'maintenance_mode':True,
          'capabilities':{'container_package_update':1,'local_plan_reporting':1},'reports':[report]}
    if component['scope'].startswith('container:'):
        body['containers']={component['scope']:{'id':'a'*64,'image':'sha256:'+'b'*64,
            'name':'/'+component['scope'].split(':',1)[1],'running':True,'pid':1234}}
    return body


def send(fleet, ident, body):
    response=fleet.client.post(ENDPOINT,json=body,headers=fleet.devices[ident]['headers'])
    assert response.status_code==200,response.text
    return response.json()


def rows(fleet, **params):
    response=fleet.client.get('/api/v1/remediation-status',params=params)
    assert response.status_code==200,response.text
    return response.json()


def test_only_exact_device_token_can_report_progress(fleet):
    fleet.enroll('a');fleet.enroll('b')
    body=report_body(fleet,'a')
    assert fleet.client.post(ENDPOINT,json=body).status_code==403
    assert fleet.client.post(ENDPOINT,json=body,headers=fleet.devices['b']['headers']).status_code==403
    assert len(send(fleet,'a',body)['accepted'])==1
    assert len(fleet.store.list('local_remediation'))==1
    assert not fleet.store.list('plan') and not fleet.store.list('action_request')


def test_local_install_waits_for_changed_inventory_and_post_report_complete_scan(fleet):
    fleet.enroll('a')
    send(fleet,'a',report_body(fleet,'a'))
    result=send(fleet,'a',report_body(fleet,'a','pending_reassessment',2))
    assert result['remediation_status'][0]['state']=='pending_reassessment'
    fleet.scan('a',[])
    assert rows(fleet)['items'][0]['state']=='pending_reassessment'
    fleet.installed_inventory('a')
    fleet.scan('a',[],complete=False)
    assert rows(fleet)['items'][0]['state']=='pending_reassessment'
    fleet.scan('a',[])
    resolved=rows(fleet,status='resolved')['items'][0]
    assert resolved['origin']=='cli' and resolved['plan_id'] is None
    assert resolved['local_plan_id']=='fixture-local-a'
    assert resolved['central_resolution']['execution_evidence']=='collector_reported'
    assert resolved['target_version']==resolved['observed_version']=='1.1'
    assert not fleet.store.list('plan')
    with transaction(fleet.runtime) as service:
        assert device_busy(service,'a') is None


def test_first_cli_report_after_install_uses_retained_original_selection(fleet):
    fleet.enroll('a')
    body=report_body(fleet,'a','pending_reassessment',4)
    fleet.installed_inventory('a');fleet.scan('a',[])
    result=send(fleet,'a',body)
    assert result['accepted']
    row=rows(fleet)['items'][0]
    assert row['state']=='pending_reassessment'
    assert row['central_resolution']['reason_code']=='awaiting_scan'
    fleet.scan('a',[])
    assert rows(fleet)['items'][0]['state']=='resolved'


def test_missing_original_identity_cannot_be_declared_resolved(fleet):
    fleet.enroll('a')
    body=report_body(fleet,'a','pending_reassessment',4,inventory_digest='unknown')
    send(fleet,'a',body)
    fleet.installed_inventory('a');fleet.scan('a',[])
    row=next(r for r in rows(fleet)['items'] if r['origin']=='cli')
    assert row['state']=='pending_reassessment'
    assert row['central_resolution']['reason_code']=='selection_unknown'


def test_stale_duplicate_conflicting_identity_and_regressive_reports(fleet):
    fleet.enroll('a')
    first=report_body(fleet,'a','installed',3)
    assert send(fleet,'a',first)['accepted']
    assert send(fleet,'a',first)['accepted']
    assert send(fleet,'a',report_body(fleet,'a','staged',2))['rejected']
    assert send(fleet,'a',report_body(fleet,'a','restarting',3))['rejected']
    assert send(fleet,'a',report_body(fleet,'a','staging',4))['rejected']
    assert send(fleet,'a',report_body(fleet,'a','pending_reassessment',4,target_version='9'))['rejected']
    assert fleet.store.list('local_remediation')[0]['status']=='installed'
    assert fleet.client.post(ENDPOINT,json=report_body(fleet,'a','resolved',4),headers=fleet.devices['a']['headers']).status_code==422


def test_recurrence_reopens_exact_scope_and_architecture(fleet):
    fleet.enroll('a')
    send(fleet,'a',report_body(fleet,'a','pending_reassessment',2))
    fleet.installed_inventory('a');fleet.scan('a',[])
    assert rows(fleet)['items'][0]['state']=='resolved'
    finding={**fleet.devices['a']['finding_source'],'affected_version':'1.1','component':fleet.devices['a']['component']}
    fleet.scan('a',[finding])
    assert rows(fleet)['items'][0]['state']=='reopened'
    assert rows(fleet)['items'][0]['current_matching_finding'] is True


def test_other_scope_same_cve_does_not_prevent_resolution(fleet):
    fleet.enroll('a')
    send(fleet,'a',report_body(fleet,'a','pending_reassessment',2))
    fleet.installed_inventory('a')
    finding={**fleet.devices['a']['finding_source'],'scope_id':'container:pmon','component_id':'container:pmon:other:amd64'}
    fleet.scan('a',[finding])
    assert rows(fleet,status='resolved')['total']==1
    assert rows(fleet,status='no_plan')['total']==1


def test_container_plans_need_fresh_mode_capability_and_recheck_before_delivery(fleet):
    fleet.enroll('a',scope='container:pmon')
    blocked=fleet.create_batch(['a'])
    assert blocked['entries'][0]['eligibility']=='manual'
    body=report_body(fleet,'a');body['reports']=[]
    send(fleet,'a',body)
    eligible=fleet.create_batch(['a'])
    entry=eligible['entries'][0]
    assert entry['eligibility']=='eligible'
    assert entry['plan']['container_maintenance'] is True
    stage=fleet.stage(eligible)
    body['maintenance_mode']=False;send(fleet,'a',body)
    response=fleet.heartbeat('a')
    assert not response['action_requests']
    assert fleet.store.get('plan',entry['plan_id'])['status']=='requires_revalidation'
    assert fleet.client.get('/api/v1/devices/a').json()['container_maintenance_eligible'] is False


def test_stale_mode_and_protected_container_package_still_manual(fleet):
    fleet.enroll('a',scope='container:pmon')
    body=report_body(fleet,'a');body['reports']=[];send(fleet,'a',body)
    device=fleet.store.device('a')
    expired=(datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat()
    fleet.store.update_device('a',{'maintenance':{**device['maintenance'],'reported_at':expired}})
    assert fleet.create_batch(['a'])['entries'][0]['eligibility']=='manual'
    fleet.enroll('b',scope='container:pmon',package='libssl-fixture')
    body=report_body(fleet,'b');body['reports']=[];send(fleet,'b',body)
    assert fleet.create_batch(['b'])['entries'][0]['eligibility']=='manual'


def test_service_telemetry_cannot_create_plan_approve_or_enable_execution(fleet):
    fleet.enroll('a')
    batch=fleet.create_batch(['a']);stage=fleet.stage(batch)
    plan=stage['entries'][0]['plan'];request_id=plan['stage_request_id']
    body=report_body(fleet,'a','downloading',1,origin='service',service_plan_id=plan['id'],request_id=request_id)
    assert send(fleet,'a',body)['accepted']
    stored=fleet.store.get('plan',plan['id'])
    assert stored['status']=='staging_queued' and stored['execution_eligible'] is False
    assert rows(fleet)['items'][0]['state']=='downloading'
    assert not fleet.store.list('local_remediation')
    body['reports'][0]['request_id']='unrelated';body['reports'][0]['revision']=2
    assert send(fleet,'a',body)['rejected']
    assert fleet.store.get('plan',plan['id'])==stored


def test_status_filter_history_and_readonly_operator_permissions(fleet):
    fleet.enroll('a');fleet.enroll('b')
    assert rows(fleet,status='no_plan',device_id='a')['total']==1
    assert rows(fleet,cve_id='not-a-real-match')['total']==0
    fleet.scan('a',[])
    assert rows(fleet,status='no_longer_reported')['total']==1
    assert not fleet.store.list('action_request')
    assert fleet.client.get('/api/v1/remediation-status',headers=fleet.devices['a']['headers']).status_code==403


def test_maintenance_fact_does_not_invalidate_applicability_or_scan_identity():
    evidence={'collector':'network','value':True}
    maintenance={'collector':'smart_patch_maintenance','value':{'maintenance_mode':True}}
    assert applicability_facts([evidence,maintenance])==[evidence]
    assert assessment_facts([evidence,maintenance])==[evidence]


def test_container_replacement_invalidates_preapproved_staging(fleet):
    fleet.enroll('a',scope='container:pmon')
    body=report_body(fleet,'a');body['reports']=[];send(fleet,'a',body)
    batch=fleet.create_batch(['a'])
    plan=batch['entries'][0]['plan']
    assert plan['container_identity']['id']=='a'*64
    body['containers']['container:pmon']['id']='c'*64;send(fleet,'a',body)
    response=fleet.client.post('/api/v1/remediation-batches/'+batch['id']+'/approve-and-stage',json={
        'expected_revision':batch['revision'],'confirmed_plan_ids':[plan['id']]})
    assert response.status_code==409,response.text
    assert not fleet.store.list('action_request')


def test_runtime_container_identity_required_before_package_planning(fleet):
    fleet.enroll('a',scope='container:pmon')
    body=report_body(fleet,'a');body['reports']=[];body['containers']={};send(fleet,'a',body)
    batch=fleet.create_batch(['a'])
    assert batch['entries'][0]['eligibility']=='manual'
    assert 'identity' in batch['entries'][0]['reason']


def test_overwritten_finding_keeps_original_cli_identity_in_assessment_history(fleet):
    fleet.enroll('a')
    body=report_body(fleet,'a','pending_reassessment',5)
    fleet.installed_inventory('a')
    newer={**fleet.devices['a']['finding_source'],'affected_version':'1.1','component':fleet.devices['a']['component']}
    fleet.scan('a',[newer])
    send(fleet,'a',body)
    local=fleet.store.list('local_remediation')[0]
    assert local['selected_findings'][0]['affected_version']=='1.0'
    fleet.scan('a',[newer])
    assert rows(fleet)['items'][0]['central_resolution']['reason_code']=='remaining_findings'
    fleet.scan('a',[])
    assert rows(fleet,status='resolved')['total']==1


def test_status_record_filter_and_compact_report_no_raw_receipts(fleet):
    fleet.enroll('a')
    body=report_body(fleet,'a','staged',2,staging_result={'details':{'stdout':'fixture '*1000}})
    result=send(fleet,'a',body)
    assert not result['remediation_truncated']
    assert result['remediation_total']==1
    assert 'staging_result' not in result['remediation_status'][0]
    assert result['remediation_status'][0]['report_revision']==2
    row=rows(fleet)['items'][0]
    assert rows(fleet,record_id=row['id'],limit=1)['items']==[row]
    assert rows(fleet,record_id='missing')['total']==0


def container_fixture(fleet, ident='a'):
    from app.db.store import inventory_hash, now
    fleet.enroll(ident,scope='container:pmon')
    device=fleet.devices[ident]
    device['component']={**device['component'],'image_digest':'sha256:'+'b'*64}
    device['envelope']={**device['envelope'],'sequence':2,'components':[device['component']],
        'inventory_digest':inventory_hash([device['component']]),'collected_at':now()}
    response=fleet.client.post('/api/v1/agents/sync',json=device['envelope'],headers=device['headers'])
    assert response.status_code==200,response.text
    device['finding_source']={**device['finding_source'],'component':device['component']}
    fleet.scan(ident,[device['finding_source']])
    device['finding']=fleet.store.list('finding',owner=ident)[0]
    return device


@pytest.mark.parametrize('replacement',[False,True])
def test_container_cli_resolution_requires_same_runtime_instance_and_image(fleet,replacement):
    container_fixture(fleet)
    body=report_body(fleet,'a','pending_reassessment',2)
    body['reports'][0]['container_identity']=copy.deepcopy(body['containers']['container:pmon'])
    send(fleet,'a',body)
    if replacement:
        body['reports']=[];body['containers']['container:pmon']['id']='c'*64
        send(fleet,'a',body)
    fleet.installed_inventory('a');fleet.scan('a',[])
    row=next(r for r in rows(fleet)['items'] if r['origin']=='cli')
    assert row['state']==('pending_reassessment' if replacement else 'resolved')
    if replacement:assert row['central_resolution']['reason_code']=='container_identity_mismatch'


def test_service_container_plan_stages_executes_and_resolves_exact_scope(fleet):
    container_fixture(fleet)
    body=report_body(fleet,'a');body['reports']=[];send(fleet,'a',body)
    batch=fleet.create_batch(['a'])
    batch=fleet.stage(batch)
    plan=batch['entries'][0]['plan']
    fleet.heartbeat('a',plan['stage_request_id'],'staged')
    batch=fleet.execute(batch);plan=batch['entries'][0]['plan']
    fleet.heartbeat('a',plan['action_request_id'],'pending_reassessment')
    fleet.installed_inventory('a');fleet.scan('a',[])
    assert fleet.store.get('plan',plan['id'])['status']=='completed'
    row=rows(fleet,status='resolved')['items'][0]
    assert row['scope']=='container:pmon' and row['origin']=='service'


def test_cli_rollback_after_resolution_shows_active_recovery_then_reopened(fleet):
    fleet.enroll('a')
    body=report_body(fleet,'a','pending_reassessment',2);send(fleet,'a',body)
    fleet.installed_inventory('a');fleet.scan('a',[])
    assert rows(fleet)['items'][0]['state']=='resolved'
    body['reports'][0].update(status='rolling_back',revision=3)
    send(fleet,'a',body)
    row=rows(fleet)['items'][0]
    assert row['state']=='rolling_back'
    assert row['central_resolution']['status']=='waiting'
    assert row['last_resolution']['status']=='completed'
    body['reports'][0].update(status='rolled_back',revision=4)
    send(fleet,'a',body)
    assert rows(fleet)['items'][0]['state']=='rolled_back'
    fleet.devices['a']['target']='1.0';fleet.installed_inventory('a')
    fleet.scan('a',[fleet.devices['a']['finding_source']])
    assert rows(fleet)['items'][0]['state']=='reopened'


def test_service_origin_rollback_progress_does_not_display_old_resolution(fleet):
    fleet.enroll('a')
    batch=fleet.stage(fleet.create_batch(['a']));plan=batch['entries'][0]['plan']
    fleet.heartbeat('a',plan['stage_request_id'],'staged')
    batch=fleet.execute(batch);plan=batch['entries'][0]['plan']
    fleet.heartbeat('a',plan['action_request_id'],'pending_reassessment')
    fleet.installed_inventory('a');fleet.scan('a',[])
    assert rows(fleet)['items'][0]['state']=='resolved'
    body=report_body(fleet,'a','rolling_back',8,origin='service',service_plan_id=plan['id'],request_id=plan['action_request_id'])
    send(fleet,'a',body)
    row=rows(fleet)['items'][0]
    assert row['state']=='rolling_back' and row['central_resolution']['status']=='waiting'
    assert row['last_resolution']['status']=='completed'
    assert fleet.store.get('plan',plan['id'])['status']=='completed'


def test_idle_agent_response_omits_unplanned_findings_but_gui_keeps_them(fleet):
    fleet.enroll('a')
    body=report_body(fleet,'a');body['reports']=[]
    response=send(fleet,'a',body)
    assert response['remediation_status']==[] and response['remediation_total']==0
    assert response['remediation_truncated'] is False
    assert rows(fleet,device_id='a')['items'][0]['state']=='no_plan'
    body=report_body(fleet,'a','planned',1)
    response=send(fleet,'a',body)
    assert response['remediation_total']==1
    assert response['remediation_status'][0]['origin']=='cli'
