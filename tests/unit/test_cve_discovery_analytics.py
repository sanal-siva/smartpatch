"""Discovery means first retained fleet observation, not current vulnerability stock."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.analytics import build_analytics
from app.db.store import Record, Store, inventory_hash


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


@pytest.fixture
def clock(monkeypatch):
    value = [datetime(2026, 9, 30, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr('app.db.store.now', lambda: iso(value[0]))
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return value[0] if tz else value[0].replace(tzinfo=None)
    monkeypatch.setattr('app.analytics.datetime', Clock)
    return value


@pytest.fixture
def store(tmp_path, clock):
    result = Store('sqlite:///' + str(tmp_path / 'discovery.db'))
    yield result
    result.close()


def finding(ident, cve, first_seen, **extra):
    return {'id': ident, 'device_id': 'leaf', 'cve_id': cve, 'first_seen': first_seen,
            'component_id': ident, 'scope': 'host', 'status': 'current', 'severity': 'HIGH',
            'package_name': 'curl', 'applicability': 'under_investigation', **extra}


def register(store, ident, timestamp):
    components = [{'component_id': 'curl', 'scope': 'host', 'name': 'curl', 'version': '1'}]
    digest = inventory_hash(components)
    store.sync({'device_id': ident, 'epoch': 'one', 'sequence': 1, 'kind': 'checkpoint',
                'inventory_digest': digest, 'components': components, 'collected_at': iso(timestamp)}, {'role': 'admin'})
    return digest


def candidate(cve, component='curl', scope='host'):
    return {'component_id': component, 'scope_id': scope, 'cve_id': cve,
            'package_name': component, 'affected_version': '1', 'applicability': 'under_investigation'}


def test_first_seen_is_fleet_distinct_across_scopes_devices_and_reappearance(store, clock):
    clock[0] -= timedelta(days=3)
    digest = register(store, 'leaf', clock[0])
    first = iso(clock[0])
    assert store.store_findings('leaf', digest, {'findings': [candidate('CVE-2026-12345'),
        candidate('cve-2026-12345', 'curl-other', 'container:telemetry')], 'coverage': {'complete': True}}, 'initial')
    clock[0] += timedelta(days=1)
    assert store.store_findings('leaf', digest, {'findings': [], 'coverage': {'complete': True}}, 'removed')
    for row in store.list('finding'):
        assert row['status'] == 'no_longer_reported'
        store.remove('finding', row['id'])
    for row in store.list('assessment_history'):
        store.remove('assessment_history', row['id'])
    clock[0] += timedelta(days=1)
    other_digest = register(store, 'peer', clock[0])
    assert store.store_findings('peer', other_digest, {'findings': [candidate('CVE-2026-12345'),
        candidate('CVE-2026-23456')], 'coverage': {'complete': True}}, 'reappeared')
    result = build_analytics(store, 30)
    assert result['cve_discovery_summary']['distinct_cves_in_window'] == 2
    assert result['cve_discovery_summary']['total_distinct_cves'] == 2
    assert [(row['date'], row['first_seen_cves']) for row in result['cve_discovery_trends']] == [
        ('2026-09-27', 1), ('2026-09-29', 1)]
    assert store.get('cve_discovery', 'CVE-2026-12345')['first_seen'].startswith(first[:19])
    assert result['cve_discovery_summary']['candidate_matches_included'] is True
    assert result['cve_trends'] == []  # Discovery does not fabricate stock snapshots.


def test_earlier_retained_observation_corrects_discovery_once_and_later_records_cannot_move_it(store):
    store.put('finding', 'later', finding('later', 'CVE-2026-1111', '2026-09-29T10:00:00Z'), 'leaf')
    store.put('finding', 'earlier', finding('earlier', 'CVE-2026-1111', '2026-09-27T10:00:00Z'), 'peer')
    store.put('finding', 'repeat', finding('repeat', 'CVE-2026-1111', '2026-09-30T10:00:00Z'), 'peer')
    result = build_analytics(store, 30)
    assert result['cve_discovery_summary']['total_distinct_cves'] == 1
    assert result['cve_discovery_trends'][0]['date'] == '2026-09-27'


def test_migration_uses_earliest_retained_finding_or_history_and_marks_gaps(store, clock):
    # Simulate a pre-ledger database without loading any evidence-bearing ORM row.
    store.remove('status', 'cve_discovery_coverage')
    with store.sessions.begin() as session:
        for kind, ident, timestamp in [('finding_summary', 'current', '2026-09-29T00:00:00Z'),
                                       ('assessment_history', 'old', '2026-09-20T00:00:00Z')]:
            session.add(Record(kind=kind, id=ident, owner='leaf', created_at=timestamp, updated_at=timestamp,
                               payload=finding(ident, 'CVE-2026-34567', timestamp, evidence=[{'data': 'large' * 10000}])))
    url = str(store.engine.url)
    store.close()
    def forbid_hydration(_session, instance):
        if isinstance(instance, Record):
            assert instance.kind not in {'finding', 'finding_summary', 'assessment_history', 'evidence_snapshot'}
    event.listen(Session, 'loaded_as_persistent', forbid_hydration)
    reopened = None
    try:
        reopened = Store(url)
        result = reopened.cve_discovery_trends('2026-09-01T00:00:00Z', iso(clock[0]), 'day')
        assert result['series'][0]['date'] == '2026-09-20'
        assert result['total_distinct_cves'] == 1
        assert result['coverage']['history_complete'] is False
        assert result['coverage']['backfilled_distinct_cves'] == 1
    finally:
        event.remove(Session, 'loaded_as_persistent', forbid_hydration)
        if reopened:
            reopened.close()


def test_hourly_discovery_normalizes_timezones_and_honors_microsecond_window_boundaries(store):
    for ident, timestamp in [('a', '2026-09-28T00:00:00+02:00'), ('b', '2026-09-27T22:00:00.000001Z'),
                              ('c', '2026-09-27T23:00:00Z')]:
        store.put('finding', ident, finding(ident, {'a': 'CVE-2026-1111', 'b': 'CVE-2026-2222', 'c': 'CVE-2026-3333'}[ident], timestamp), 'leaf')
    start, end = '2026-09-27T22:00:00Z', '2026-09-27T22:59:59.999999Z'
    result = store.cve_discovery_trends(start, end, 'hour')
    assert result['series'] == [{'date': '2026-09-27', 'snapshot_time': '2026-09-27T22:00:00Z', 'first_seen_cves': 2}]
    assert result['total_distinct_cves'] == 3 and result['distinct_cves_in_window'] == 2


def test_invalid_unobserved_future_and_catalog_only_advisories_are_not_discoveries(store, clock):
    for index, (cve, timestamp) in enumerate([('GHSA-xxxx-yyyy-zzzz', iso(clock[0])), ('CVE-TEST-1111', iso(clock[0])),
            ('CVE-2026-1111', None), ('CVE-2026-2222', '2026-09-20T12:00:00'),
            ('CVE-2026-3333', iso(clock[0] + timedelta(microseconds=1)))]):
        store.put('finding', str(index), finding(str(index), cve, timestamp), 'leaf')
    store.put('release_finding', 'catalog', finding('catalog', 'CVE-2026-4444', iso(clock[0])), 'release')
    result = build_analytics(store, 30)
    assert result['cve_discovery_trends'] == []
    assert result['cve_discovery_summary']['total_distinct_cves'] == 0
    assert result['cve_discovery_summary']['coverage']['history_complete'] is False


def test_dashboard_discovery_read_uses_aggregate_sql_without_finding_evidence_hydration(store, monkeypatch):
    store.put('finding', 'a', finding('a', 'CVE-2026-1111', '2026-09-29T12:00:00Z',
        evidence=[{'data': 'large' * 10000}]), 'leaf')
    original = store.list
    def guarded(kind, *args, **kwargs):
        assert kind not in {'finding', 'finding_summary', 'assessment_history', 'cve_discovery', 'evidence_snapshot'}
        return original(kind, *args, **kwargs)
    monkeypatch.setattr(store, 'list', guarded)
    def forbid_hydration(_session, instance):
        if isinstance(instance, Record):
            assert instance.kind not in {'finding', 'finding_summary', 'assessment_history', 'cve_discovery', 'evidence_snapshot'}
    event.listen(store.sessions, 'loaded_as_persistent', forbid_hydration)
    try:
        result = build_analytics(store, 7)
        assert result['cve_discovery_trends'][0]['granularity'] == 'hour'
        assert result['cve_discovery_summary']['distinct_cves_in_window'] == 1
        assert store.list('snapshot') == []
    finally:
        event.remove(store.sessions, 'loaded_as_persistent', forbid_hydration)


@pytest.mark.parametrize('start,end,resolution', [
    ('2026-09-27T00:00:00Z', '2026-09-26T00:00:00Z', 'day'),
    ('2026-09-27T00:00:00', '2026-09-30T00:00:00Z', 'day'),
    ('2024-09-27T00:00:00Z', '2026-09-30T00:00:00Z', 'day'),
    ('2026-09-27T00:00:00Z', '2026-09-30T00:00:00Z', 'week'),
])
def test_discovery_queries_reject_unbounded_or_ambiguous_windows(store, start, end, resolution):
    with pytest.raises(ValueError):
        store.cve_discovery_trends(start, end, resolution)
