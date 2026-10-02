"""Dashboard history comes from scheduled observations and committed deltas."""
from datetime import datetime, timedelta, timezone

import pytest

from app.analytics import aggregate_history, build_analytics, capture_snapshot
from app.db.store import Store, inventory_hash, now


@pytest.fixture
def store():
    value=Store('sqlite:///:memory:')
    yield value
    value.close()


def component(name,version='1.0',scope='host',**extra):
    return {'component_id':f'{scope}:{name}:{version}:amd64','scope':scope,'name':name,
            'version':version,'architecture':'amd64',**extra}


def sync(store,device,sequence,components,removed=(),kind='checkpoint'):
    previous=store.device(device)
    current={} if kind=='checkpoint' else {c['component_id']:c for c in previous['components']}
    for ident in removed:current.pop(ident,None)
    for item in components:current[item['component_id']]=item
    envelope={'schema_version':1,'device_id':device,'hostname':device,'epoch':'analytics-test','sequence':sequence,
              'kind':kind,'collected_at':now(),'components':components,'removed':list(removed),
              'inventory_digest':inventory_hash(list(current.values()))}
    result,changed=store.sync(envelope,{'role':'admin'})
    assert result['resync_required'] is False
    return envelope,changed


def test_dashboard_reads_do_not_create_or_backfill_snapshots(store):
    sync(store,'leaf1',1,[component('curl')])
    for _ in range(2):
        result=build_analytics(store,30)
        assert result['package_trends']==[]
        assert result['cve_trends']==[]
        assert result['current_inventory']['components']==1
    assert store.list('snapshot')==[]


def test_hourly_observations_are_distinct_and_repeat_capture_updates_only_its_hour(store):
    sync(store,'leaf1',1,[component('curl')])
    base=datetime.now(timezone.utc).replace(minute=0,second=0,microsecond=0)-timedelta(hours=3)
    first=capture_snapshot(store,observed_at=(base+timedelta(minutes=7)).isoformat())
    second=capture_snapshot(store,observed_at=(base+timedelta(hours=1,minutes=9)).isoformat())
    assert first['snapshot_time']!=second['snapshot_time']
    assert len(store.list('snapshot'))==2
    repeated=capture_snapshot(store,observed_at=(base+timedelta(hours=1,minutes=40)).isoformat())
    assert repeated['snapshot_time']==second['snapshot_time']
    assert repeated['measured_at']!=second['measured_at']
    assert len(store.list('snapshot'))==2
    result=build_analytics(store,7)
    assert len(result['package_trends'])==2
    assert all(row['granularity']=='hour' for row in result['package_trends'])


def test_naive_observation_timestamp_is_rejected(store):
    with pytest.raises(ValueError,match='timezone'):
        capture_snapshot(store,observed_at='2026-09-30T12:00:00')


def test_package_families_count_real_current_scoped_occurrences(store):
    sync(store,'leaf1',1,[component('linux-image-6.1'),component('frr'),component('libssl3'),component('curl')])
    sync(store,'leaf2',1,[component('linux-image-6.1'),component('curl',scope='container:telemetry')])
    rows={row['package_type']:row for row in build_analytics(store)['package_type_breakdown']}
    assert rows['linux-kernel']=={'package_type':'linux-kernel','components':2,'unique_packages':1,'devices':2}
    assert rows['frr']['components']==1
    assert rows['openssl']['components']==1
    assert rows['standard']['components']==2
    assert sum(row['components'] for row in rows.values())==6


def test_top_updated_uses_committed_transitions_not_baseline_additions_or_duplicate_ack(store):
    curl1=component('curl');frr=component('frr')
    sync(store,'leaf1',1,[curl1,frr]);sync(store,'leaf2',1,[curl1])
    assert build_analytics(store)['top_updated_packages']==[]
    curl2=component('curl','1.1');nano=component('nano')
    envelope,changed=sync(store,'leaf1',2,[curl2,nano],removed=[curl1['component_id'],frr['component_id']],kind='delta')
    assert changed
    before=len(store.list('event'))
    _,duplicate_changed=store.sync(envelope,{'role':'admin'})
    assert duplicate_changed is False and len(store.list('event'))==before
    curl3=component('curl','1.2')
    sync(store,'leaf1',3,[curl3],removed=[curl2['component_id']],kind='delta')
    sync(store,'leaf2',2,[curl2],removed=[curl1['component_id']],kind='delta')
    result=build_analytics(store)
    assert len(result['top_updated_packages'])==1
    row=result['top_updated_packages'][0]
    assert row['package_name']=='curl' and row['updates']==3 and row['devices']==2 and row['scopes']==2
    assert row['latest_observed_version']=='1.1'
    assert result['package_change_coverage']['updates_counted']==3
    assert result['package_change_coverage']['complete'] is True


def test_truncated_and_legacy_change_events_report_partial_ranking_without_estimation(store):
    store.audit('inventory.delta','Legacy event','leaf1',details={'sequence':1})
    store.audit('inventory.delta','Truncated event','leaf1',details={'package_changes_total':600,'package_changes_complete':False,
        'package_changes':[{'component_id':'curl','scope':'host','package_name':'curl','change':'updated','previous_version':'1.0','version':'1.1'}]})
    result=build_analytics(store)
    assert result['top_updated_packages'][0]['updates']==1
    assert result['package_change_coverage']['incomplete_events']==1
    assert result['package_change_coverage']['legacy_events_without_changes']==1
    assert result['package_change_coverage']['complete'] is False


def test_failed_request_details_and_measured_duration_are_retained(store):
    record={'id':'request-failed','submitted_at':now(),'status':'failed','error_message':'Controlled fixture failure',
            'assessment_duration_ms':42,'response_cached':False,'timeline':[{'status':'in_progress','timestamp':now()},{'status':'failed','timestamp':now()}]}
    store.put('request',record['id'],record)
    result=build_analytics(store)
    assert result['request_metrics']['failed']==1
    assert result['request_metrics']['average_duration_ms']==42
    assert result['requests'][0]['error_message']=='Controlled fixture failure'
    assert result['requests'][0]['timeline'][-1]['status']=='failed'


def test_snapshot_and_package_aggregates_use_effective_expiry_and_staleness(store):
    rows=[('expired','leaf1','CVE-TEST-1','fixed',{'decision_valid_until':'2000-01-01T00:00:00Z'}),
          ('stale','leaf1','CVE-TEST-2','affected',{'assessment_stale':True}),
          ('fresh','leaf2','CVE-TEST-1','affected',{})]
    for ident,device,cve,state,extra in rows:
        store.put('finding',ident,{'id':ident,'device_id':device,'cve_id':cve,'package_name':'curl','severity':'HIGH',
                                  'status':'current','applicability':state,**extra},device)
    snapshot=capture_snapshot(store)
    assert snapshot['fixed']==0 and snapshot['under_investigation']==2 and snapshot['affected']==1
    assert snapshot['unique_cves']==2
    row=build_analytics(store)['severity_package_grid'][0]
    assert row['high']==3 and row['occurrences']==3 and row['affected_devices']==1


def test_analytics_does_not_hydrate_finding_evidence_payloads(store,monkeypatch):
    store.put('finding','f',{'id':'f','device_id':'leaf1','cve_id':'CVE-TEST-1','package_name':'curl',
                            'status':'current','severity':'HIGH','applicability':'under_investigation',
                            'evidence':[{'data':'large evidence fixture'}]},'leaf1')
    original=store.list
    def guarded(kind,*args,**kwargs):
        assert kind not in {'finding','finding_summary'},'Dashboard read hydrated finding rows instead of SQL aggregates'
        return original(kind,*args,**kwargs)
    monkeypatch.setattr(store,'list',guarded)
    assert capture_snapshot(store)['under_investigation']==1
    assert build_analytics(store)['severity_package_grid'][0]['high']==1


def observed(timestamp,affected,components=10):
    return {'date':timestamp[:10],'snapshot_time':timestamp[:13]+':00:00Z','measured_at':timestamp,
            'granularity':'hour','devices':1,'components':components,'unique_packages':components,
            'affected':affected,'under_investigation':0,'fixed':0,'not_affected':0,'unique_cves':affected}


def test_daily_history_uses_last_actual_value_and_preserves_peak_and_sample_count():
    points=[observed('2026-09-29T11:00:00Z',4,12),observed('2026-09-27T23:45:00Z',2,50),
            observed('2026-09-27T01:10:00Z',9,100)]
    daily=aggregate_history(points,'day')
    assert [row['date'] for row in daily]==['2026-09-27','2026-09-29']
    first=daily[0]
    assert first['components']==50 and first['affected']==2
    assert first['measured_at']=='2026-09-27T23:45:00Z'
    assert first['snapshot_time']=='2026-09-27T00:00:00Z'
    assert first['observation_count']==2 and first['peak_affected']==9
    assert first['first_observed_at']=='2026-09-27T01:10:00Z'
    assert daily[1]['observation_count']==1 and daily[1]['peak_affected']==4
    assert points[1]['granularity']=='hour'


def test_hourly_history_preserves_each_observation_and_unknown_peak():
    points=[observed('2026-09-27T23:45:00Z',None),observed('2026-09-27T01:10:00Z',9)]
    hourly=aggregate_history(points,'hour')
    assert len(hourly)==2 and all(row['observation_count']==1 for row in hourly)
    assert hourly[0]['affected']==9 and hourly[1]['affected'] is None
    assert hourly[1]['peak_affected'] is None


def test_daily_bucket_uses_utc_day_not_the_input_timezone_date():
    points=[observed('2026-09-28T00:30:00+02:00',8),observed('2026-09-27T23:00:00Z',3)]
    daily=aggregate_history(points,'day')
    assert len(daily)==1 and daily[0]['date']=='2026-09-27'
    assert daily[0]['affected']==3 and daily[0]['peak_affected']==8
    assert daily[0]['observation_count']==2


def test_year_window_has_at_most_366_actual_daily_points_and_no_future_or_gap_filling(monkeypatch):
    import app.analytics as module
    frozen=datetime(2026,9,30,23,59,tzinfo=timezone.utc)
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return frozen if tz else frozen.replace(tzinfo=None)
    monkeypatch.setattr(module,'datetime',Clock)
    first=frozen.replace(hour=0,minute=0,second=0,microsecond=0)-timedelta(days=365)
    points=[observed((first+timedelta(hours=index)).isoformat().replace('+00:00','Z'),index%31,index)
            for index in range(366*24)]
    points += [observed((first-timedelta(hours=1)).isoformat().replace('+00:00','Z'),999),
               observed((frozen+timedelta(days=1)).isoformat().replace('+00:00','Z'),999)]
    class HistoryStore:
        def devices(self):return []
        def get(self,kind,ident):return None
        def list(self,kind):return points if kind=='snapshot' else []
        def finding_package_counts(self):return []
        def cve_discovery_trends(self,start,end,resolution):return {'series':[]}
    result=build_analytics(HistoryStore(),366)
    assert result['history_resolution']=='day' and result['history_points']==366
    assert result['history_observations']==366*24
    assert len(result['package_trends'])==366 and len(result['cve_trends'])==366
    assert all(row['observation_count']==24 for row in result['cve_trends'])
    assert max(row['peak_affected'] for row in result['cve_trends'])==30
    missing_date=points[48]['date']
    points[:]=[point for point in points if point['date']!=missing_date]
    missing=build_analytics(HistoryStore(),366)
    assert missing['history_points']==365
    assert missing_date not in {row['date'] for row in missing['package_trends']}
    short=build_analytics(HistoryStore(),7)
    assert short['history_resolution']=='hour'
    assert all(row['observation_count']==1 for row in short['package_trends'])
