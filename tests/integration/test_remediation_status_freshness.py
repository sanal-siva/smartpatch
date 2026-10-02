"""Current CVE outcomes must not inherit historical scan or verdict authority."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from app.db.store import Record
from app.services.assessment import RULESET_VERSION
from .test_remediation_batches_acceptance import fleet, CVE
from .test_remediation_status_api import report_body, rows, send


def completed(fleet, origin):
    fleet.enroll('freshness')
    body=report_body(fleet,'freshness','pending_reassessment',2)
    if origin=='cli':
        send(fleet,'freshness',body)
        kind='local_remediation'
    else:
        batch=fleet.stage(fleet.create_batch(['freshness']))
        plan=batch['entries'][0]['plan']
        fleet.heartbeat('freshness',plan['stage_request_id'],'staged')
        batch=fleet.execute(batch);plan=batch['entries'][0]['plan']
        fleet.heartbeat('freshness',plan['action_request_id'],'pending_reassessment')
        kind='plan'
    fleet.installed_inventory('freshness');fleet.scan('freshness',[])
    row=rows(fleet,device_id='freshness')['items'][0]
    assert row['state']=='resolved'
    return body,kind,fleet.store.list(kind,owner='freshness')[0],row


@pytest.mark.parametrize('origin',['cli','service'])
def test_current_inventory_needs_new_scan_before_recurrence_or_resolution(fleet,origin):
    body,kind,plan,resolved=completed(fleet,origin)
    original_resolution=copy.deepcopy(resolved['central_resolution'])
    original_finding=copy.deepcopy(fleet.devices['freshness']['finding'])
    fleet.devices['freshness']['target']='1.2'
    fleet.installed_inventory('freshness')
    # Deliberately retain an old current row; it is not a current scanner match.
    fleet.store.put('finding',original_finding['id'],{**original_finding,'status':'current'},'freshness')
    before=copy.deepcopy(fleet.store.get(kind,plan['id']))
    pending=rows(fleet,device_id='freshness')['items'][0]
    assert pending['state']=='pending_reassessment'
    assert pending['central_resolution']['status']=='waiting'
    assert pending['central_resolution']['reason_code']=='stale_scan'
    assert pending['current_matching_finding'] is None
    assert pending['last_resolution']['status']=='completed'
    assert pending['last_resolution']['observed_version']=='1.1'
    assert fleet.store.get(kind,plan['id'])==before, 'GET projection cannot rewrite completed history'

    current={**fleet.devices['freshness']['finding_source'],'affected_version':'1.2',
             'component':fleet.devices['freshness']['component']}
    fleet.scan('freshness',[current])
    reopened=rows(fleet,device_id='freshness')['items'][0]
    assert reopened['state']=='reopened' and reopened['current_matching_finding'] is True
    assert reopened['central_resolution']['remaining_cves']==[CVE]

    fleet.scan('freshness',[])
    refreshed=rows(fleet,device_id='freshness')['items'][0]
    assert refreshed['state']=='resolved' and refreshed['current_matching_finding'] is False
    assert refreshed['central_resolution']['observed_version']=='1.2'
    assert refreshed['central_resolution']['scan_completed_at']!=original_resolution['scan_completed_at']
    assert refreshed['last_resolution']['observed_version']=='1.1'
    if origin=='service':
        assert fleet.store.get('plan',plan['id'])['status']=='completed'
        assert fleet.store.get('plan',plan['id'])['reassessment']==plan['reassessment']


@pytest.mark.parametrize('origin',['cli','service'])
@pytest.mark.parametrize('change',['build','policy','review','advisory','db_revision','coverage','partial','missing','timestamp'])
def test_old_resolution_does_not_survive_scan_context_changes(fleet,origin,change):
    body,kind,plan,_=completed(fleet,origin)
    if change=='build':fleet.store.update_device('freshness',{'build_id':'another-build'})
    elif change=='policy':fleet.store.update_device('freshness',{'assessment_policy_revision':'new-policy'})
    elif change=='review':fleet.store.update_device('freshness',{'review_revision':'new-evidence'})
    elif change=='advisory':fleet.store.put('status','advisory',{'generation':42})
    elif change=='db_revision':fleet.store.update_device('freshness',{'scanner':{'status':'complete','db_revision':'new-db'}})
    elif change=='coverage':fleet.store.update_device('freshness',{'coverage':{'complete':False}})
    elif change=='partial':fleet.scan('freshness',[],complete=False)
    elif change=='missing':
        with fleet.store.lock,fleet.store.sessions.begin() as session:
            session.delete(session.get(Record,('maintenance_scan','freshness')))
    else:
        proof=fleet.store.get('maintenance_scan','freshness')
        fleet.store.put('maintenance_scan','freshness',{**proof,'scan_completed_at':'invalid'},'freshness')
    row=rows(fleet,device_id='freshness')['items'][0]
    assert row['state']=='pending_reassessment'
    assert row['central_resolution']['status']=='waiting'
    assert row['last_resolution']['status']=='completed'
    assert row['current_matching_finding'] is None


@pytest.mark.parametrize('change',['expired_review','policy','partial_scan'])
def test_stale_fixed_verdict_is_under_investigation(fleet,change):
    remote=fleet.enroll('fixed',applicability='fixed')
    future=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
    finding={**remote['finding'],'decision_basis':'operator_review','decision_valid_until':future,
             'ruleset_version':RULESET_VERSION,'build_evidence_policy':'required'}
    fleet.store.put('finding',finding['id'],finding,'fixed')
    assert rows(fleet,device_id='fixed')['items'][0]['applicability']=='fixed'
    if change=='expired_review':
        fleet.store.put('finding',finding['id'],{**finding,'decision_valid_until':'2000-01-01T00:00:00Z'},'fixed')
    elif change=='policy':fleet.store.update_device('fixed',{'assessment_policy_revision':'new-policy'})
    else:fleet.scan('fixed',[],complete=False)
    row=rows(fleet,device_id='fixed')['items'][0]
    assert row['applicability']=='under_investigation'
    assert row['state']!='resolved'


def test_freshness_changes_are_included_in_duplicate_collector_response(fleet):
    body,_,_,_=completed(fleet,'cli')
    # No new operation report revision is needed to invalidate cached outcomes.
    fleet.store.update_device('freshness',{'assessment_policy_revision':'new-policy'})
    response=send(fleet,'freshness',body)
    row=response['remediation_status'][0]
    assert row['report_revision']==2
    assert row['state']=='pending_reassessment'
    assert row['central_resolution']['status']=='waiting'
    assert row['central_resolution']['reason_code']=='stale_scan'
    assert row['applicability']=='under_investigation'


@pytest.mark.parametrize('origin',['cli','service'])
def test_recovery_operation_remains_primary_even_with_new_clean_scan(fleet,origin):
    body,_,plan,_=completed(fleet,origin)
    if origin=='service':
        body=report_body(fleet,'freshness','rolling_back',3,origin='service',
                         service_plan_id=plan['id'],request_id=plan['action_request_id'])
    else:body['reports'][0].update(status='rolling_back',revision=3)
    send(fleet,'freshness',body)
    fleet.scan('freshness',[])
    row=rows(fleet,device_id='freshness')['items'][0]
    assert row['state']=='rolling_back'
    assert row['central_resolution']['status']=='waiting'
    assert row['last_resolution']['status']=='completed'
