from app.db.store import Store, Record, now
from app.observability.state import ObservationWindow


def finding(ident,device='leaf',state='under_investigation',severity='HIGH',score=7):
    return {'id':ident,'device_id':device,'hostname':device,'component_id':ident,'scope':'host',
            'package_name':'pkg_'+ident,'affected_version':'1.0','cve_id':'CVE-TEST-'+ident,
            'status':'current','applicability':state,'severity':severity,'cvss_score':score,
            'evidence':[{'id':'large','data':'x'*100000}]}


def test_summary_pagination_counts_review_and_removal_stay_consistent():
    s=Store('sqlite:///:memory:')
    try:
        s.put('finding','a',finding('a',state='affected',severity='CRITICAL',score=5),'leaf')
        s.put('finding','b',finding('b',severity='HIGH',score=9),'leaf')
        s.put('finding','c',finding('c',device='peer',severity='LOW'),'peer')
        result=s.query_findings(device_id='leaf',limit=1,sort='cvss')
        assert result['total']==2 and result['findings'][0]['id']=='b'
        assert 'evidence' not in result['findings'][0]
        assert s.query_findings(device_id='leaf',limit=1,offset=1,sort='cvss')['findings'][0]['id']=='a'
        assert s.query_findings(search='pkg_')['total']==3
        assert s.query_findings(search='pkg%')['total']==0  # literal SQL wildcard
        assert s.query_findings(severity='critical')['total']==1
        assert s.finding_counts()['applicability']=={'affected':1,'under_investigation':2}
        s.put('finding','a',{**s.get('finding','a'),'applicability':'not_affected'},'leaf')
        assert s.finding_counts()['applicability']['not_affected']==1
        assert s.remove('finding','b')
        assert s.query_findings()['total']==2
        assert len(s.get('finding','a')['evidence'][0]['data'])==100000
    finally:s.close()


def test_existing_database_backfills_compact_records_on_reopen(tmp_path):
    url='sqlite:///'+str(tmp_path/'state.db');s=Store(url)
    with s.sessions.begin() as session:
        session.add(Record(kind='finding',id='legacy',owner='leaf',created_at=now(),updated_at=now(),payload=finding('legacy')))
    s.close();s=Store(url)
    try:
        assert s.query_findings()['total']==1
        assert s.get('finding_summary','legacy')['cve_id']=='CVE-TEST-legacy'
        assert s.finding_counts()['by_device']['leaf']['under_investigation']==1
    finally:s.close()


def test_expired_review_disappears_from_exemptions_without_a_rescan():
    s=Store('sqlite:///:memory:')
    try:
        row={**finding('expired',state='not_affected'),'decision_basis':'operator_review',
             'decision_valid_until':'2000-01-01T00:00:00Z'}
        s.put('finding','expired',row,'leaf')
        assert s.query_findings(applicability='not_affected')['total']==0
        effective=s.query_findings(applicability='under_investigation')['findings'][0]
        assert effective['assessment_stale'] is True and effective['action_type']=='defer'
        assert s.finding_counts()['applicability']=={'under_investigation':1}
        assert s.get('finding','expired')['applicability']=='not_affected'  # preserve the historical decision
    finally:s.close()


def test_bounded_collector_cache_prioritizes_affected_over_unresolved_matches():
    s=Store('sqlite:///:memory:')
    try:
        s.put('finding','actionable',finding('actionable',state='affected',severity='LOW',score=1),'leaf')
        s.put('finding','candidate',finding('candidate',state='under_investigation',severity='CRITICAL',score=9.8),'leaf')
        page=s.query_findings(device_id='leaf',limit=1,sort='priority')
        assert page['total']==2 and page['findings'][0]['id']=='actionable'
    finally:s.close()


def test_observed_windows_are_bounded_and_expire_without_inventing_values():
    clock=[1000.0];window=ObservationWindow(clock=lambda:clock[0],max_samples=3)
    for value in (1,2,3,4):window.request('/api/v1/findings',200,value)
    window.cache_lookup(True);window.cache_lookup(False)
    result=window.snapshot(2,{'configured':False,'available':None})
    assert result['api_samples']==3 and result['api_p95_seconds']==4
    assert result['cache_hit_rate_percent']==50 and result['ai_available'] is None
    clock[0]+=301
    result=window.snapshot(0,{'configured':False})
    assert result['api_samples']==0 and result['api_p95_seconds'] is None
    assert result['cache_hit_rate_percent'] is None


def test_alerts_record_transitions_within_one_tick_and_resolve_without_spam():
    clock=[1000.0];window=ObservationWindow(clock=lambda:clock[0]);s=Store('sqlite:///:memory:')
    config={'alerts_enabled':True,'alert_min_samples':2,'alert_latency_p95_seconds':2,
            'alert_error_rate_percent':5,'alert_cache_hit_rate_percent':70,'alert_queue_depth':100}
    try:
        assert window.evaluate_alerts(s,config,window.snapshot(0,{'configured':False}))==[]
        window.request('/api/v1/findings',200,3);window.request('/api/v1/findings',500,4)
        window.cache_lookup(False);window.cache_lookup(False)
        measured=window.snapshot(101,{'configured':True,'available':False,'last_check_timestamp':1000})
        alerts=window.evaluate_alerts(s,config,measured)
        assert len(alerts)==5 and all(a['status']=='firing' for a in alerts)
        assert all(a['evaluation_interval_seconds']==10 for a in alerts)
        assert window.evaluate_alerts(s,config,measured)==[]
        assert len(s.list('event'))==5
        clock[0]+=301
        resolved=window.evaluate_alerts(s,config,window.snapshot(0,{'configured':True,'available':True}))
        assert len(resolved)==5 and all(a['status']=='resolved' for a in resolved)
    finally:s.close()
