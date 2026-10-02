import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from app.db.store import Device, InventoryMessage, Operation, Record, Store, Token
from app.services import retention

NOW = datetime(2026,9,29,12,tzinfo=timezone.utc)
OLD = '2020-01-01T00:00:00Z'


@pytest.fixture
def store():
    database=Store('sqlite://')
    yield database
    database.close()


def age(store, kind, ident, stamp=OLD):
    with store.sessions.begin() as session:
        row=session.get(Operation,ident) if kind=='operation' else session.get(Record,(kind,ident))
        row.created_at=row.updated_at=stamp


def put_old(store, kind, ident, payload, owner=None, stamp=OLD):
    store.put(kind,ident,payload,owner)
    age(store,kind,ident,stamp)


def finished(store, status='completed'):
    operation=store.enqueue('scan',{'device_id':'d1'})
    store.update_operation(operation['id'],status=status,logs=[{'message':'retained complete log line'}])
    age(store,'operation',operation['id'])
    return operation['id']


def test_archive_is_durable_private_and_contains_full_rows_before_deletion(store,tmp_path):
    put_old(store,'event','e1',{'message':'old event'})
    put_old(store,'request','r1',{'status':'completed','response':{'findings':3}})
    put_old(store,'cache','c1',{'result':{'answer':'old cached result'}})
    operation=finished(store)
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['archived']==result['deleted']==4
    path=Path(result['archive'])
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    with gzip.open(path,'rt') as stream:lines=[json.loads(line) for line in stream]
    assert lines[0]['records']==4
    for line in lines[1:]:
        assert line['sha256']==hashlib.sha256(retention._json(line['record'])).hexdigest()
    archived_job=next(line['record'] for line in lines[1:] if line['record']['table']=='operation')
    assert archived_job['payload']['logs']==[{'message':'retained complete log line'}]
    assert store.get('event','e1') is None
    assert store.operation(operation) is None


def test_live_and_trust_state_and_protocol_tombstones_are_preserved(store,tmp_path):
    for kind in ('settings','release','build_binding','artifact','package','token','unknown_future_kind'):
        put_old(store,kind,kind,{'value':'preserved'})
    put_old(store,'finding','current',{'status':'current','evidence_ids':['cited']})
    put_old(store,'finding_summary','current',{'status':'current'})
    put_old(store,'evidence','cited',{'id':'cited','content':'live evidence'})
    put_old(store,'evidence','orphan',{'id':'orphan','content':'old unused evidence'})
    put_old(store,'plan','pending-plan',{'status':'completed'})
    put_old(store,'action_request','pending-action',{'status':'queued','plan':{'id':'pending-plan'}})
    operation=finished(store,status='in_progress')
    with store.sessions.begin() as session:
        session.add(Device(id='d1',epoch='new',sequence=1,inventory_digest='abc',last_seen=OLD,payload={}))
        session.add(InventoryMessage(id='old-message',device_id='d1',epoch='retired',sequence=1,digest='old',created_at=OLD))
        session.add(Token(id='token',digest='digest',role='agent',device_id='d1',description='preserve credential record',created_at=OLD,revoked=0))
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==1 and store.get('evidence','orphan') is None
    assert store.get('evidence','cited') is not None
    assert store.get('plan','pending-plan') is not None
    assert store.operation(operation)['status']=='in_progress'
    with store.sessions() as session:
        assert session.get(Device,'d1') and session.get(InventoryMessage,'old-message') and session.get(Token,'token')


def test_latest_external_proposal_and_registered_citations_survive(store,tmp_path):
    put_old(store,'finding','old-finding',{'status':'no_longer_reported'})
    put_old(store,'external_agent_analysis','older',{'finding_id':'old-finding','session_id':'s-old','evidence_ids':['e-old']},stamp='2019-01-01T00:00:00Z')
    put_old(store,'external_agent_session','s-old',{'status':'submitted'})
    put_old(store,'evidence','e-old',{'id':'e-old'})
    put_old(store,'external_agent_analysis','latest',{'finding_id':'old-finding','session_id':'s-new','evidence_ids':['e-new']})
    put_old(store,'external_agent_latest','old-finding',{'finding_id':'old-finding','analysis_id':'latest'})
    put_old(store,'external_agent_session','s-new',{'status':'submitted','evidence_ids':['e-new']})
    put_old(store,'external_agent_evidence','registered-e-new',{'session_id':'s-new','record':{'id':'e-new'}},owner='s-new')
    put_old(store,'evidence','e-new',{'id':'e-new'})
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('external_agent_analysis','latest')
    assert store.get('external_agent_session','s-new')
    assert store.get('external_agent_evidence','registered-e-new')
    assert store.get('evidence','e-new')
    assert store.get('external_agent_analysis','older') is None
    assert store.get('evidence','e-old') is None


def test_archive_write_failure_never_deletes_database_rows(store,tmp_path,monkeypatch):
    put_old(store,'event','one',{'message':'must survive'})
    def fail(*args,**kwargs):raise OSError('simulated full archive disk')
    monkeypatch.setattr(retention,'_write_archive',fail)
    with pytest.raises(OSError):retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('event','one')=={'message':'must survive'}


def test_changed_payload_is_preserved_even_if_legacy_writer_did_not_update_timestamp(store,tmp_path,monkeypatch):
    put_old(store,'event','one',{'version':1})
    original=retention._write_archive
    def archive_then_update(*args):
        path=original(*args)
        store.put('event','one',{'version':2})
        age(store,'event','one')
        return path
    monkeypatch.setattr(retention,'_write_archive',archive_then_update)
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['archived']==1 and result['deleted']==0
    assert result['preserved_changed_or_referenced']==1
    assert store.get('event','one')=={'version':2}


def test_new_current_finding_reference_prevents_post_archive_deletion(store,tmp_path,monkeypatch):
    put_old(store,'evidence','one',{'id':'one'})
    original=retention._write_archive
    def archive_then_reference(*args):
        path=original(*args)
        store.put('finding','new-current',{'status':'current','evidence_ids':['one']})
        return path
    monkeypatch.setattr(retention,'_write_archive',archive_then_reference)
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==0 and store.get('evidence','one')


def test_batch_is_bounded_and_archives_are_append_only(store,tmp_path):
    for ident in ('a','b','c'):put_old(store,'event',ident,{'id':ident})
    finished(store)
    first=retention.archive_expired(store,tmp_path,batch_size=2,current_time=NOW)
    first_bytes=Path(first['archive']).read_bytes()
    second=retention.archive_expired(store,tmp_path,batch_size=2,current_time=NOW)
    assert first['deleted']==second['deleted']==2
    assert first['archive']!=second['archive']
    assert Path(first['archive']).read_bytes()==first_bytes
    with pytest.raises(ValueError):retention.archive_expired(store,tmp_path,batch_size=1001)


def test_oversized_rows_and_invalid_timestamps_are_retained(store,tmp_path):
    put_old(store,'event','large',{'payload':'x'*4096})
    put_old(store,'event','bad-time',{'payload':'unknown-time'},stamp='')
    result=retention.archive_expired(store,tmp_path,max_archive_bytes=1024,current_time=NOW)
    assert result['deleted']==0
    assert store.get('event','large') and store.get('event','bad-time')


def test_immutable_history_preserves_recent_and_current_snapshot_references(store,tmp_path):
    put_old(store,'finding','current-finding',{'status':'current','assessment_revision':'current-revision'})
    put_old(store,'evidence_snapshot','old-only',{'id':'old-evidence'})
    put_old(store,'evidence_snapshot','shared',{'id':'shared-evidence'})
    put_old(store,'assessment_history','old-history',{'finding_id':'current-finding','assessment_revision':'old-revision','evidence_digests':['old-only','shared']},owner='current-finding',stamp='2019-01-01T00:00:00Z')
    put_old(store,'assessment_history','latest-current',{'finding_id':'current-finding','assessment_revision':'current-revision','evidence_digests':['shared']},owner='current-finding')
    store.put('assessment_history','recent-history',{'finding_id':'another-finding','evidence_digests':['shared']},owner='another-finding')
    first=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('assessment_history','old-history') is None
    assert store.get('assessment_history','latest-current')
    assert store.get('assessment_history','recent-history')
    assert store.get('evidence_snapshot','shared')
    # Snapshot survives while the old history is being archived; next batch can
    # archive it only after no retained history refers to it.
    assert store.get('evidence_snapshot','old-only')
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('evidence_snapshot','old-only') is None
    assert store.get('evidence_snapshot','shared')


def test_current_embedded_evidence_protects_content_addressed_snapshot(store,tmp_path):
    evidence={'id':'ev','data':{'fact':'pinned current evidence'}}
    digest=hashlib.sha256(retention._json(evidence)).hexdigest()
    put_old(store,'finding','current',{'status':'current','evidence':[evidence]})
    put_old(store,'evidence_snapshot',digest,evidence)
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==0
    assert store.get('evidence_snapshot',digest)==evidence


def test_trusted_review_and_binding_proofs_are_not_orphaned(store,tmp_path):
    put_old(store,'reviewed_assessment','review',{'evidence_ids':['review-proof']})
    put_old(store,'build_binding','binding',{'evidence_ids':['binding-proof']})
    put_old(store,'evidence','review-proof',{'id':'review-proof'})
    put_old(store,'evidence','binding-proof',{'id':'binding-proof'})
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==0
    assert store.get('evidence','review-proof') and store.get('evidence','binding-proof')


def test_uncompressed_chunk_respects_byte_budget(store,tmp_path):
    for index in range(10):put_old(store,'event',str(index),{'message':'x'*100})
    result=retention.archive_expired(store,tmp_path,current_time=NOW,max_archive_bytes=2048)
    with gzip.open(result['archive'],'rb') as stream:
        assert len(stream.read()) <= 2048
    assert 0 < result['deleted'] < 10


def test_expired_open_sessions_and_inactive_plans_can_archive_without_touching_active_jobs(store,tmp_path):
    expired='2020-02-01T00:00:00Z'
    future='2099-01-01T00:00:00Z'
    put_old(store,'external_agent_session','expired-open',{'status':'open','expires_at':expired})
    put_old(store,'external_agent_session','still-valid',{'status':'open','expires_at':future})
    put_old(store,'external_agent_session','invalid-time',{'status':'open','expires_at':'bad'})
    put_old(store,'plan','expired-draft',{'status':'draft','expires_at':expired})
    put_old(store,'plan','expired-approved',{'status':'approved','expires_at':expired})
    put_old(store,'plan','expired-validation',{'status':'validation_failed','expires_at':expired})
    put_old(store,'plan','expired-target',{'status':'target_validation_failed','expires_at':expired})
    put_old(store,'plan','queued',{'status':'queued','expires_at':expired})
    put_old(store,'plan','job-reference',{'status':'approved','expires_at':expired})
    operation=store.enqueue('validate_plan',{'plan_id':'job-reference'})
    age(store,'operation',operation['id'])
    retention.archive_expired(store,tmp_path,current_time=NOW)
    for kind,ident in [('external_agent_session','expired-open'),('plan','expired-draft'),('plan','expired-approved'),
                      ('plan','expired-validation'),('plan','expired-target')]:
        assert store.get(kind,ident) is None
    for kind,ident in [('external_agent_session','still-valid'),('external_agent_session','invalid-time'),('plan','queued'),('plan','job-reference')]:
        assert store.get(kind,ident)
    assert store.operation(operation['id'])['status']=='queued'


def test_cold_analytics_and_terminal_retries_archive_but_active_retry_references_survive(store,tmp_path):
    put_old(store,'snapshot','old-observation',{'measured_at':OLD,'devices':2})
    for kind in ('analysis_retry','release_analysis_retry'):
        for status in ('completed','exhausted','superseded'):
            put_old(store,kind,kind+'-'+status,{'status':status})
        put_old(store,kind,kind+'-waiting',{'status':'retry_needed'})
    put_old(store,'analysis_retry','currently-referenced',{'status':'completed'})
    operation=store.enqueue('retry_analysis',{'retry_id':'currently-referenced','device_id':'d1'})
    age(store,'operation',operation['id'])
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==7
    assert store.get('snapshot','old-observation') is None
    assert store.get('analysis_retry','currently-referenced')
    assert store.get('analysis_retry','analysis_retry-waiting')
    assert store.get('release_analysis_retry','release_analysis_retry-waiting')


def test_expired_session_still_protects_evidence_when_latest_proposal_cites_it(store,tmp_path):
    put_old(store,'external_agent_session','session',{'status':'open','expires_at':'2020-01-02T00:00:00Z','evidence_ids':['evidence']})
    put_old(store,'external_agent_analysis','proposal',{'finding_id':'finding','session_id':'session','evidence_ids':['evidence']})
    put_old(store,'external_agent_latest','finding',{'analysis_id':'proposal','finding_id':'finding'})
    put_old(store,'evidence','evidence',{'id':'evidence'})
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==0
    assert store.get('external_agent_session','session') and store.get('evidence','evidence')


def test_current_retry_limit_tombstones_survive_but_obsolete_identities_archive(store,tmp_path):
    from app.db.store import stable_hash
    from app.services.release_service import advance_retry_schedule, retry_identity, release_retry_identity
    def unexpected_job(*args,**kwargs):raise AssertionError('Retention must not reset the exhausted retry budget')
    runtime=SimpleNamespace(store=store,configuration=lambda:{'ai_enabled':True},enqueue=unexpected_job)
    with store.sessions.begin() as session:
        session.add(Device(id='device',epoch='current',sequence=1,inventory_digest='digest',last_seen=OLD,payload={}))
    release={'release_id':'release','artifact_id':'artifact','source_revision':'current'}
    put_old(store,'release','release',release)
    put_old(store,'finding','device-finding',{'status':'current','assessment_state':'retry_needed'},owner='device')
    put_old(store,'release_finding','release-finding',{'status':'current','assessment_state':'retry_needed'},owner='release')
    records=[]
    for kind,owner,identity in [('analysis_retry','device',retry_identity(runtime,store.device('device'))),
                               ('release_analysis_retry','release',release_retry_identity(runtime,release))]:
        field='device_id' if kind=='analysis_retry' else 'release_id'
        ident=stable_hash([owner,identity])
        put_old(store,kind,ident,{field:owner,'expected_identity':identity,'status':'exhausted','attempts':5},owner=owner)
        obsolete={**identity,('epoch' if field=='device_id' else 'source_revision'):'old'}
        put_old(store,kind,ident+'-old',{field:owner,'expected_identity':obsolete,'status':'exhausted','attempts':5},owner=owner)
        records.append((kind,ident))
    retention.archive_expired(store,tmp_path,current_time=NOW)
    advance_retry_schedule(runtime)
    for kind,ident in records:
        assert store.get(kind,ident)['attempts']==5
        assert store.get(kind,ident)['status']=='exhausted'
        assert store.get(kind,ident+'-old') is None


def test_bounded_scan_advances_past_protected_prefix_and_wraps(store,tmp_path):
    for index in range(10):put_old(store,'finding',str(index),{'status':'current'})
    put_old(store,'event','eligible',{'message':'archive after protected prefix'},stamp='2020-02-01T00:00:00Z')
    first=retention.archive_expired(store,tmp_path,batch_size=1,current_time=NOW)
    assert first['deleted']==0 and first['scan_limit_reached']
    assert store.get('retention_cursor','records')['position']
    second=retention.archive_expired(store,tmp_path,batch_size=1,current_time=NOW)
    assert second['deleted']==1 and store.get('event','eligible') is None
    # A backfilled record before the current position is picked up after a
    # bounded end-of-stream pass wraps the persisted cursor.
    put_old(store,'event','backfill',{'message':'inserted behind cursor'},stamp='2019-01-01T00:00:00Z')
    retention.archive_expired(store,tmp_path,batch_size=1,current_time=NOW)
    assert store.get('retention_cursor','records')['position'] is None
    assert retention.archive_expired(store,tmp_path,batch_size=1,current_time=NOW)['deleted']==1


def test_oversized_prefix_does_not_starve_smaller_cold_rows_or_operation_stream(store,tmp_path):
    for index in range(10):put_old(store,'event','large-'+str(index),{'payload':'x'*4096})
    put_old(store,'event','small',{'message':'fits'},stamp='2020-02-01T00:00:00Z')
    operation=finished(store)
    first=retention.archive_expired(store,tmp_path,batch_size=1,max_archive_bytes=2048,current_time=NOW)
    assert first['deleted']==1 and store.operation(operation) is None
    retention.archive_expired(store,tmp_path,batch_size=1,max_archive_bytes=2048,current_time=NOW)
    retention.archive_expired(store,tmp_path,batch_size=1,max_archive_bytes=2048,current_time=NOW)
    assert store.get('event','small') is None
    assert store.get('event','large-0')


@pytest.mark.parametrize('batch_size,byte_budget,message_size',[(1,2048,10),(1000,2048,900)])
def test_full_record_batches_do_not_starve_finished_operations(store,tmp_path,batch_size,byte_budget,message_size):
    operation=finished(store)
    for index in range(4):put_old(store,'event',str(index),{'message':'x'*message_size})
    first=retention.archive_expired(store,tmp_path,batch_size=batch_size,max_archive_bytes=byte_budget,current_time=NOW)
    assert first['deleted']==1
    assert store.operation(operation)
    # Even with more eligible records arriving, the other stream gets priority
    # on the next bounded pass.
    put_old(store,'event','new',{'message':'x'*message_size})
    retention.archive_expired(store,tmp_path,batch_size=batch_size,max_archive_bytes=byte_budget,current_time=NOW)
    assert store.operation(operation) is None


def test_current_release_history_and_exact_evidence_survive_cold_history_archival(store,tmp_path):
    put_old(store,'release_finding','current-release-finding',{'status':'current','release_id':'release','assessment_revision':'current'})
    put_old(store,'package_cve','current-release-finding',{'status':'current'})
    put_old(store,'evidence_snapshot','old-release-proof',{'proof':'old'})
    put_old(store,'evidence_snapshot','current-release-proof',{'proof':'current'})
    put_old(store,'release_assessment_history','old',{'release_finding_id':'current-release-finding','evidence_digests':['old-release-proof']},
            owner='current-release-finding',stamp='2019-01-01T00:00:00Z')
    put_old(store,'release_assessment_history','current',{'release_finding_id':'current-release-finding','evidence_digests':['current-release-proof']},
            owner='current-release-finding')
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('release_assessment_history','old') is None
    assert store.get('release_assessment_history','current')
    assert store.get('release_finding','current-release-finding')
    assert store.get('package_cve','current-release-finding')
    assert store.get('evidence_snapshot','old-release-proof')
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('evidence_snapshot','old-release-proof') is None
    assert store.get('evidence_snapshot','current-release-proof')


def test_fleet_cve_first_seen_ledger_and_coverage_are_permanent(store,tmp_path):
    put_old(store,'cve_discovery','SYNTHETIC-LEDGER-NOT-A-CVE',{'first_seen':OLD})
    put_old(store,'status','cve_discovery_coverage',{'observed_since':OLD})
    put_old(store,'event','cold',{'message':'archive this event only'})
    result=retention.archive_expired(store,tmp_path,current_time=NOW)
    assert result['deleted']==1
    assert store.get('cve_discovery','SYNTHETIC-LEDGER-NOT-A-CVE')
    assert store.get('status','cve_discovery_coverage')


def test_obsolete_ai_context_archives_in_dependency_order_while_current_proof_and_jobs_stay(store,tmp_path):
    old_identity,new_identity={'context':'old'},{'context':'current'}
    old_job=store.enqueue('analysis_backlog',{'backlog_id':'old-context'})
    store.update_operation(old_job['id'],status='completed')
    age(store,'operation',old_job['id'],stamp='2019-01-01T00:00:00Z')
    new_job=store.enqueue('analysis_backlog',{'backlog_id':'current-context'})
    store.update_operation(new_job['id'],status='completed')
    age(store,'operation',new_job['id'])
    for prefix,identity,stamp,job in [('old',old_identity,'2019-01-01T00:00:00Z',old_job),('current',new_identity,OLD,new_job)]:
        backlog=prefix+'-context';work=prefix+'-work';proof={'id':prefix+'-proof','value':prefix}
        digest=hashlib.sha256(retention._json(proof)).hexdigest()
        put_old(store,'analysis_backlog',backlog,{'id':backlog,'target_kind':'device','target_id':'leaf',
            'expected_identity':identity,'status':'completed','operation_id':job['id']},owner='leaf',stamp=stamp)
        put_old(store,'analysis_work',work,{'id':work,'target_kind':'device','target_id':'leaf','expected_identity':identity,
            'backlog_id':backlog,'status':'exhausted','operation_id':job['id'],
            'finding':{'analysis_attempts':5,'evidence':[proof]}},owner=backlog,stamp=stamp)
        put_old(store,'analysis_lifecycle',work,{'target_kind':'device','target_id':'leaf','expected_identity':identity,
            'assessment_state':'retry_needed','analysis_attempts':5,'operation_id':job['id']},owner='leaf',stamp=stamp)
        put_old(store,'evidence',proof['id'],proof,stamp=stamp)
        put_old(store,'evidence_snapshot',digest,proof,stamp=stamp)
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('analysis_work','old-work') is None
    assert store.get('analysis_backlog','old-context') and store.get('analysis_lifecycle','old-work')
    assert store.operation(old_job['id']) and store.get('evidence','old-proof')
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.get('analysis_backlog','old-context') is None
    assert store.get('analysis_lifecycle','old-work') is None
    retention.archive_expired(store,tmp_path,current_time=NOW)
    assert store.operation(old_job['id']) is None and store.get('evidence','old-proof') is None
    assert store.get('analysis_work','current-work')['finding']['analysis_attempts']==5
    assert store.get('analysis_lifecycle','current-work')['analysis_attempts']==5
    assert store.get('analysis_backlog','current-context') and store.operation(new_job['id'])
    assert store.get('evidence','current-proof')


@pytest.mark.parametrize('state',['completed','exhausted'])
def test_retention_cannot_reset_current_ai_success_or_retry_budget(tmp_path,state):
    from tests.unit.test_analysis_lifecycle_backlog import make_runtime, register, scan, tick
    from app.services.analysis_lifecycle import analysis_identity, seed_backlog
    runtime=make_runtime(tmp_path/'runtime',count=1)
    try:
        register(runtime);scan(runtime);tick(runtime)
        work=runtime.store.list('analysis_work')[0]
        if state=='exhausted':
            finding={**work['finding'],'analysis_attempts':5,'analysis_success':False,
                     'assessment_state':'retry_needed','analysis_retry_exhausted':True}
            runtime.store.put('analysis_work',work['id'],{**work,'status':'exhausted','finding':finding},work['backlog_id'])
            runtime.store.put('finding',finding['id'],finding,'leaf1')
            lifecycle=runtime.store.get('analysis_lifecycle',work['id'])
            runtime.store.put('analysis_lifecycle',work['id'],{**lifecycle,'analysis_attempts':5,
                'assessment_state':'retry_needed','analysis_success':False,'analysis_retry_exhausted':True},'leaf1')
        with runtime.store.sessions.begin() as session:
            for row in session.scalars(select(Record)):row.created_at=row.updated_at=OLD
            for row in session.scalars(select(Operation)):row.created_at=row.updated_at=OLD
        before=len(runtime.test_factory.provider.calls)
        retention.archive_expired(runtime.store,tmp_path/'archive-state',current_time=NOW)
        retained=runtime.store.get('analysis_work',work['id'])
        assert retained['status']==state
        assert runtime.store.get('analysis_lifecycle',work['id'])
        seed_backlog(runtime,'device','leaf1',expected_identity=analysis_identity(runtime,'device','leaf1'),
                     assessment_revision=runtime.store.device('leaf1')['assessment_revision'])
        scan(runtime)
        assert len(runtime.test_factory.provider.calls)==before
        if state=='exhausted':assert runtime.store.get('analysis_work',work['id'])['finding']['analysis_attempts']==5
    finally:runtime.stop()


def test_inflight_operation_keeps_even_superseded_context_references(store,tmp_path):
    put_old(store,'analysis_backlog','latest',{'target_kind':'release','target_id':'release',
            'expected_identity':{'context':'new'},'status':'completed'})
    put_old(store,'analysis_backlog','older',{'target_kind':'release','target_id':'release',
            'expected_identity':{'context':'old'},'status':'superseded'},stamp='2019-01-01T00:00:00Z')
    job=store.enqueue('analysis_backlog',{'backlog_id':'older'})
    store.update_operation(job['id'],status='in_progress');age(store,'operation',job['id'])
    put_old(store,'analysis_work','work',{'backlog_id':'older','target_kind':'release','target_id':'release',
            'expected_identity':{'context':'old'},'status':'exhausted','finding':{'evidence_ids':['proof']}},owner='older',stamp='2019-01-01T00:00:00Z')
    put_old(store,'analysis_lifecycle','work',{'target_kind':'release','target_id':'release',
            'expected_identity':{'context':'old'},'operation_id':job['id']},stamp='2019-01-01T00:00:00Z')
    put_old(store,'evidence','proof',{'id':'proof'})
    assert retention.archive_expired(store,tmp_path,current_time=NOW)['deleted']==0
    assert store.get('analysis_work','work') and store.get('analysis_lifecycle','work')
    assert store.get('evidence','proof') and store.operation(job['id'])
