"""Periodic work is due by durable UTC time, independent of process uptime."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.db.store import inventory_hash
from app.runtime import Runtime


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


@pytest.fixture
def clock(monkeypatch):
    value = [datetime(2026, 9, 30, 0, 0, tzinfo=timezone.utc)]
    monkeypatch.setattr('app.db.store.now', lambda: iso(value[0]))
    return value


@pytest.fixture
def instances(tmp_path):
    opened = []
    settings = Settings(database_url='sqlite:///' + str(tmp_path / 'service.db'),
                        state_dir=tmp_path, jobs_enabled=False, bootstrap_token='fixture-token')
    def create():
        factory = lambda *args: SimpleNamespace(scanner=SimpleNamespace(status=lambda: {'status': 'ready'}))
        runtime = Runtime(settings, pipeline_factory=factory)
        opened.append(runtime)
        return runtime
    yield create
    for runtime in opened:
        runtime.stop()


def device(runtime, timestamp):
    components = [{'component_id': 'host:curl', 'scope': 'host', 'name': 'curl', 'version': '1.0'}]
    runtime.store.sync({'device_id': 'leaf', 'epoch': 'one', 'sequence': 1, 'kind': 'checkpoint',
        'components': components, 'inventory_digest': inventory_hash(components), 'collected_at': iso(timestamp)}, {'role': 'admin'})
    runtime.store.update_device('leaf', {'last_scan_at': iso(timestamp), 'scan_status': 'completed'})


def test_advisory_generation_survives_restart_without_invalidating_same_evidence(instances,monkeypatch):
    first=instances()
    first.store.put('status','advisory',{'generation':7,'db_revision':'db-before'})
    first.stop()
    restarted=instances()
    assert restarted.advisory_generation==7
    monkeypatch.setattr('app.runtime.subprocess.run',lambda *args,**kwargs:SimpleNamespace(returncode=0,stderr=''))
    restarted.pipeline.scanner.status=lambda:{'status':'ready','db_revision':'db-after'}
    restarted._job_advisory_update({'id':'fixture-only'})
    assert restarted.advisory_generation==8
    assert restarted.store.get('status','advisory')['generation']==8
    restarted.stop()
    assert instances().advisory_generation==8


def release(runtime, ident='primary', timestamp=None, **extra):
    runtime.store.put('release', ident, {'release_id': ident, 'artifact_id': 'artifact',
        'primary': ident == 'primary', 'status': 'analyzed' if timestamp else 'imported',
        'last_synced_at': iso(timestamp) if timestamp else None, **extra})


def complete(runtime, key, clock, **updates):
    ident = runtime.store.get('scheduler_cadence', key)['operation_id']
    runtime.store.update_operation(ident, 'completed', result=updates or {})
    runtime._run_scheduled_tasks(clock[0])
    return ident


def test_repeated_restarts_do_not_postpone_six_hour_scan_or_daily_refresh(instances, clock):
    runtime = instances()
    started = clock[0]
    device(runtime, started)
    release(runtime, timestamp=started)
    runtime.store.put('status', 'advisory', {'updated_at': iso(started)})
    runtime._run_scheduled_tasks(started)
    assert runtime.store.operations() == []
    for hour in (2, 4, 6, 12, 18, 24):
        runtime.stop()
        runtime = instances()
        runtime.start()  # jobs_enabled=False does not create any threads or advance cadence.
        assert runtime._threads == []
        clock[0] = started + timedelta(hours=hour)
        runtime._run_scheduled_tasks(clock[0])
        scan = runtime.store.get('scheduler_cadence', 'scan:leaf')
        if hour < 6:
            assert scan['next_due_at'] == iso(started + timedelta(hours=6))
            assert not scan.get('operation_id')
        else:
            assert scan['status'] == 'queued'
            complete(runtime, 'scan:leaf', clock, accepted=True)
        for key in ('advisory', 'release:primary'):
            row = runtime.store.get('scheduler_cadence', key)
            assert row['status'] == ('queued' if hour == 24 else 'completed')
            assert row['next_due_at'] == iso(started + timedelta(days=1))


def test_active_operation_survives_recovery_without_duplicate_enqueue(instances, clock):
    runtime = instances()
    runtime._run_scheduled_tasks(clock[0])
    row = runtime.store.get('scheduler_cadence', 'advisory')
    assert runtime.store.claim()['id'] == row['operation_id']
    runtime.stop()
    reopened = instances()
    reopened.start()
    clock[0] += timedelta(days=2)
    reopened._run_scheduled_tasks(clock[0])
    assert reopened.store.get('scheduler_cadence', 'advisory')['operation_id'] == row['operation_id']
    assert len(reopened.store.operations()) == 1


def test_failure_retry_deadline_persists_and_is_based_on_job_completion(instances, clock):
    runtime = instances()
    runtime._run_scheduled_tasks(clock[0])
    ident = runtime.store.get('scheduler_cadence', 'advisory')['operation_id']
    runtime.store.update_operation(ident, 'failed', error_message='Temporary network outage')
    runtime._run_scheduled_tasks(clock[0])
    row = runtime.store.get('scheduler_cadence', 'advisory')
    assert row['status'] == 'failed'
    assert row['last_error'] == 'Temporary network outage'
    due = clock[0] + timedelta(seconds=60)
    assert row['next_due_at'] == iso(due)
    runtime.stop()
    runtime = instances()
    clock[0] += timedelta(seconds=59)
    runtime._run_scheduled_tasks(clock[0])
    assert len(runtime.store.operations()) == 1
    clock[0] = due
    runtime._run_scheduled_tasks(clock[0])
    assert len(runtime.store.operations()) == 2
    assert runtime.store.get('scheduler_cadence', 'advisory')['operation_id'] != ident


def test_late_completion_observation_does_not_start_a_new_day_of_waiting(instances, clock):
    runtime = instances()
    runtime._run_scheduled_tasks(clock[0])
    ident = runtime.store.get('scheduler_cadence', 'advisory')['operation_id']
    runtime.store.update_operation(ident, 'completed', result={})
    runtime.stop()
    runtime = instances()
    clock[0] += timedelta(days=2)
    runtime._run_scheduled_tasks(clock[0])
    row = runtime.store.get('scheduler_cadence', 'advisory')
    assert row['status'] == 'queued' and row['operation_id'] != ident
    assert row['last_success_at'] == iso(clock[0] - timedelta(days=2))


@pytest.mark.parametrize('result', [{'status': 'failed'}, {'accepted': False}])
def test_completed_operation_with_failed_result_uses_short_retry(instances, clock, result):
    runtime = instances()
    release(runtime)
    runtime._run_scheduled_tasks(clock[0])
    complete(runtime, 'release:primary', clock, **result)
    row = runtime.store.get('scheduler_cadence', 'release:primary')
    assert row['status'] == 'failed'
    assert row['next_due_at'] == iso(clock[0] + timedelta(seconds=60))


def test_primary_releases_queue_first_and_one_failure_does_not_starve_others(instances, clock, monkeypatch):
    runtime = instances()
    release(runtime, 'aaa-secondary')
    release(runtime, 'zzz-primary', primary=True)
    release(runtime, 'bbb-secondary')
    original = runtime.enqueue
    calls = []
    def enqueue(kind, arguments, key=None):
        calls.append((kind, arguments.get('release_id')))
        if arguments.get('release_id') == 'zzz-primary':
            raise RuntimeError('Controlled enqueue failure')
        return original(kind, arguments, key)
    monkeypatch.setattr(runtime, 'enqueue', enqueue)
    runtime._run_scheduled_tasks(clock[0])
    assert calls == [('advisory_update', None), ('release_sync', 'zzz-primary'),
                     ('release_sync', 'aaa-secondary'), ('release_sync', 'bbb-secondary')]
    assert runtime.store.get('scheduler_cadence', 'release:zzz-primary')['status'] == 'failed'
    assert runtime.store.get('scheduler_cadence', 'release:bbb-secondary')['status'] == 'queued'
    clock[0] += timedelta(seconds=59)
    runtime._run_scheduled_tasks(clock[0])
    assert len(calls) == 4


def test_hourly_snapshots_survive_restart_and_do_not_backfill_missing_hours(instances, clock):
    runtime = instances()
    runtime._run_scheduled_tasks(clock[0])
    assert len(runtime.store.list('snapshot')) == 1
    runtime.stop()
    runtime = instances()
    clock[0] += timedelta(minutes=30)
    runtime._run_scheduled_tasks(clock[0])
    assert len(runtime.store.list('snapshot')) == 1
    clock[0] += timedelta(hours=5)
    runtime._run_scheduled_tasks(clock[0])
    assert len(runtime.store.list('snapshot')) == 2
    assert runtime.store.get('scheduler_cadence', 'snapshot')['next_due_at'] == iso(clock[0] + timedelta(hours=1))


def test_inline_failure_retries_without_starving_retention(instances, clock, monkeypatch):
    runtime = instances()
    calls = []
    def failing_snapshot(*args, **kwargs):
        calls.append(True)
        raise RuntimeError('Snapshot unavailable')
    monkeypatch.setattr('app.analytics.capture_snapshot', failing_snapshot)
    runtime._run_scheduled_tasks(clock[0])
    assert runtime.store.get('scheduler_cadence', 'snapshot')['status'] == 'failed'
    assert runtime.store.get('scheduler_cadence', 'retention')['status'] == 'completed'
    clock[0] += timedelta(seconds=59)
    runtime._run_scheduled_tasks(clock[0])
    assert len(calls) == 1
    clock[0] += timedelta(seconds=1)
    runtime._run_scheduled_tasks(clock[0])
    assert len(calls) == 2


def test_shorter_configured_scan_interval_takes_effect_without_restart(instances, clock):
    runtime = instances()
    device(runtime, clock[0])
    runtime._run_scheduled_tasks(clock[0])
    runtime.save_configuration({'scan_interval_seconds': 3600})
    clock[0] += timedelta(hours=1)
    runtime._run_scheduled_tasks(clock[0])
    row = runtime.store.get('scheduler_cadence', 'scan:leaf')
    assert row['status'] == 'queued' and row['interval_seconds'] == 3600


def test_import_timestamp_is_not_a_successful_release_assessment(instances, clock):
    runtime = instances()
    release(runtime, timestamp=clock[0], status='imported')
    runtime._run_scheduled_tasks(clock[0])
    assert runtime.store.get('scheduler_cadence', 'release:primary')['status'] == 'queued'


def test_missing_advisory_database_repairs_now_but_failed_repair_observes_backoff(instances, clock):
    runtime = instances()
    runtime.store.put('status', 'advisory', {'updated_at': iso(clock[0])})
    runtime.scanner_info = {'status': 'ready'}
    runtime._run_scheduled_tasks(clock[0])
    assert runtime.store.operations() == []
    runtime.scanner_info = {'status': 'unavailable'}
    runtime._run_scheduled_tasks(clock[0])
    ident = runtime.store.get('scheduler_cadence', 'advisory')['operation_id']
    runtime.store.update_operation(ident, 'failed', error_message='Network unavailable')
    runtime._run_scheduled_tasks(clock[0])
    assert runtime.store.get('scheduler_cadence', 'advisory')['status'] == 'failed'
    assert len(runtime.store.operations()) == 1
    clock[0] += timedelta(seconds=60)
    runtime._run_scheduled_tasks(clock[0])
    assert len(runtime.store.operations()) == 2


def test_disabled_jobs_start_does_not_schedule_periodic_work(instances):
    runtime = instances()
    runtime.start()
    assert runtime._threads == []
    assert runtime.store.operations() == []
    assert runtime.store.list('scheduler_cadence') == []
    assert runtime.store.list('snapshot') == []
