"""Permanent removal operates on isolated SQLite fixtures, never live state."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from app.db.store import Store
from app.services.device_purge import purge_device


TARGET = 'hardware-fixture'
VM = 'vm-fixture'
OLD = '2025-01-01T00:00:00Z'
CUTOFF = '2025-01-02T00:00:00Z'
NEW = '2025-01-03T00:00:00Z'
HARDWARE_CVE = 'CVE-2025-10001'
SHARED_CVE = 'CVE-2025-10002'
VM_CVE = 'CVE-2025-10003'
SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'purge-device.py'
TABLES = ('smart_patch_devices', 'smart_patch_records', 'smart_patch_tokens',
          'smart_patch_inventory_messages', 'smart_patch_operations')


def put(db, kind, ident, value=None, owner=None):
    payload = {'id': ident, **(value or {})}
    db.execute('INSERT OR REPLACE INTO smart_patch_records '
               '(kind,id,owner,created_at,updated_at,payload) VALUES (?,?,?,?,?,?)',
               (kind, ident, owner, OLD, OLD, json.dumps(payload)))
    return payload


def record(db, kind, ident):
    row = db.execute('SELECT payload FROM smart_patch_records WHERE kind=? AND id=?', (kind, ident)).fetchone()
    return json.loads(row[0]) if row else None


def snapshot(db):
    return {table: sorted(db.execute('SELECT * FROM '+table).fetchall()) for table in TABLES}


def operation(db, ident, arguments, status='completed'):
    db.execute('INSERT INTO smart_patch_operations '
               '(id,operation_type,status,dedup_key,created_at,updated_at,payload) VALUES (?,?,?,?,?,?,?)',
               (ident, 'scan', status, ident, OLD, OLD, json.dumps({'arguments': arguments})))


@pytest.fixture
def database(tmp_path):
    path = tmp_path / 'permanent-removal.sqlite'
    store = Store('sqlite:///' + str(path))
    store.close()
    db = sqlite3.connect(path)
    for ident in (TARGET, VM):
        payload = {'hostname': ident, 'build_id': 'fixture-build-'+ident}
        if ident == TARGET:
            payload.update(archived=True, archived_at=CUTOFF)
        db.execute('INSERT INTO smart_patch_devices (id,epoch,sequence,inventory_digest,last_seen,payload) '
                   'VALUES (?,?,?,?,?,?)', (ident, 'fixture-epoch', 2, 'fixture-digest', OLD, json.dumps(payload)))
        db.execute('INSERT INTO smart_patch_tokens (id,digest,role,device_id,description,created_at,revoked) '
                   'VALUES (?,?,?,?,?,?,?)', (ident+'-token', ident+'-fixture-digest', 'agent', ident, 'Fixture', OLD, 0))
        for sequence in range(1, 3 if ident == TARGET else 2):
            db.execute('INSERT INTO smart_patch_inventory_messages (id,device_id,epoch,sequence,digest,created_at) '
                       'VALUES (?,?,?,?,?,?)', (ident+'-'+str(sequence), ident, 'fixture-epoch', sequence, 'digest', OLD))
    db.execute('INSERT INTO smart_patch_tokens (id,digest,role,description,created_at,revoked) '
               'VALUES (?,?,?,?,?,?)', ('admin-token', 'admin-fixture-digest', 'admin', 'Fixture admin', OLD, 0))
    put(db, 'finding', 'hardware-finding', {'device_id': TARGET, 'cve_id': HARDWARE_CVE}, TARGET)
    put(db, 'finding_summary', 'hardware-finding', {'device_id': TARGET, 'cve_id': HARDWARE_CVE, 'first_seen': OLD}, TARGET)
    put(db, 'assessment_history', 'hardware-history', {'cve_id': SHARED_CVE, 'first_seen': OLD,
        'evidence_digests': ['shared-evidence', 'target-only-evidence']}, 'hardware-finding')
    put(db, 'finding_summary', 'vm-finding', {'device_id': VM, 'cve_id': SHARED_CVE, 'first_seen': NEW}, VM)
    put(db, 'assessment_history', 'vm-history', {'device_id': VM, 'cve_id': VM_CVE,
        'first_seen': CUTOFF, 'evidence_digests': ['shared-evidence']}, 'vm-finding')
    put(db, 'analysis_backlog', 'hardware-backlog', {'target_kind': 'device', 'target_id': TARGET,
                                                  'status': 'completed'}, TARGET)
    put(db, 'analysis_work', 'hardware-work', {'status': 'completed'}, 'hardware-backlog')
    put(db, 'analysis_lifecycle', 'hardware-child', {'status': 'analyzed'}, 'hardware-work')
    put(db, 'plan', 'hardware-plan', {'device_id': TARGET, 'status': 'completed'}, TARGET)
    put(db, 'action_request', 'hardware-action', {'status': 'complete', 'result_consumed': True}, TARGET)
    put(db, 'request', 'hardware-request', {'smart_patch_instance_id': TARGET, 'status': 'completed'})
    put(db, 'request', 'vm-request', {'smart_patch_instance_id': VM, 'status': 'completed'})
    put(db, 'scheduler_cadence', 'scan:'+TARGET, {'status': 'completed'})
    put(db, 'evidence', 'hardware-evidence', {'type': 'runtime'}, TARGET)
    put(db, 'evidence_snapshot', 'shared-evidence', {'observation': 'Shared exact evidence fixture'})
    put(db, 'evidence_snapshot', 'target-only-evidence', {'observation': 'Target-only evidence fixture'})
    put(db, 'evidence_snapshot', 'unrelated-evidence', {'observation': 'Unrelated shared source'})
    for kind in ('artifact', 'release', 'build_binding', 'signing_key', 'settings'):
        put(db, kind, 'shared-'+kind, {'source': 'Shared trusted fixture'})
    for ident in ('target-cache', 'vm-cache'):
        put(db, 'cache', ident, {'value': 'Derived fixture result'})
        put(db, 'assessment_response', ident+'-response', {'value': 'Cached request response'})
    for cve in (HARDWARE_CVE, SHARED_CVE, VM_CVE):
        put(db, 'cve_discovery', cve, {'cve_id': cve, 'first_seen': OLD})
    put(db, 'status', 'fleet_visibility_boundary', {'changed_at': CUTOFF})
    put(db, 'snapshot', 'before-exclusion', {'measured_at': OLD, 'devices': 2})
    put(db, 'snapshot', 'after-exclusion', {'measured_at': NEW, 'devices': 1})
    put(db, 'snapshot', 'empty-before', {'measured_at': OLD, 'devices': 0})
    operation(db, 'hardware-scan', {'device_id': TARGET})
    operation(db, 'hardware-backlog-job', {'backlog_id': 'hardware-backlog'})
    operation(db, 'hardware-plan-job', {'plan_id': 'hardware-plan'})
    operation(db, 'vm-scan', {'device_id': VM})
    db.commit()
    yield db, path
    db.close()


def test_dry_run_reports_same_selection_without_mutation(database):
    db, path = database
    before = snapshot(db)
    with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True) as readonly:
        preview = purge_device(readonly, TARGET)
    assert preview['applied'] is False
    assert preview['devices_removed'] == preview['tokens_removed'] == 1
    assert preview['inventory_messages_removed'] == 2
    assert preview['operations_removed'] == 3
    assert snapshot(db) == before
    actual = purge_device(db, TARGET, apply=True)
    assert {key:value for key,value in actual.items() if key != 'applied'} == {
        key:value for key,value in preview.items() if key != 'applied'}


def test_apply_removes_target_children_and_credentials_but_preserves_vm(database):
    db, _ = database
    retained = {kind: record(db, kind, ident) for kind, ident in (
        ('finding_summary', 'vm-finding'), ('assessment_history', 'vm-history'), ('request', 'vm-request'))}
    purge_device(db, TARGET, apply=True)
    assert db.execute('SELECT id FROM smart_patch_devices').fetchall() == [(VM,)]
    assert set(row[0] for row in db.execute('SELECT id FROM smart_patch_tokens')) == {'admin-token', VM+'-token'}
    assert db.execute('SELECT device_id FROM smart_patch_inventory_messages').fetchall() == [(VM,)]
    assert db.execute('SELECT id FROM smart_patch_operations').fetchall() == [('vm-scan',)]
    for kind, ident in (('finding', 'hardware-finding'), ('finding_summary', 'hardware-finding'),
            ('assessment_history', 'hardware-history'), ('analysis_backlog', 'hardware-backlog'),
            ('analysis_work', 'hardware-work'), ('analysis_lifecycle', 'hardware-child'), ('plan', 'hardware-plan'),
            ('action_request', 'hardware-action'), ('request', 'hardware-request'), ('scheduler_cadence', 'scan:'+TARGET)):
        assert record(db, kind, ident) is None, (kind, ident)
    for kind, ident in (('finding_summary', 'vm-finding'), ('assessment_history', 'vm-history'), ('request', 'vm-request')):
        assert record(db, kind, ident) == retained[kind]
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'


def test_shared_evidence_and_trust_preserved_while_target_evidence_and_caches_removed(database):
    db, _ = database
    shared = {kind: record(db, kind, 'shared-'+kind) for kind in ('artifact', 'release', 'build_binding', 'signing_key', 'settings')}
    purge_device(db, TARGET, apply=True)
    assert record(db, 'evidence_snapshot', 'shared-evidence')
    assert record(db, 'evidence_snapshot', 'unrelated-evidence')
    assert record(db, 'evidence_snapshot', 'target-only-evidence') is None
    assert record(db, 'evidence', 'hardware-evidence') is None
    assert db.execute("SELECT count(*) FROM smart_patch_records WHERE kind='cache'").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM smart_patch_records WHERE kind='assessment_response'").fetchone()[0] == 0
    assert all(record(db, kind, 'shared-'+kind) == payload for kind, payload in shared.items())


def test_discovery_and_fleet_snapshots_describe_retained_devices(database):
    db, _ = database
    purge_device(db, TARGET, apply=True)
    assert record(db, 'cve_discovery', HARDWARE_CVE) is None
    assert record(db, 'cve_discovery', SHARED_CVE)['first_seen'] == NEW
    assert record(db, 'cve_discovery', VM_CVE)['first_seen'] == CUTOFF
    coverage = record(db, 'status', 'cve_discovery_coverage')
    assert coverage['history_complete'] is False
    assert coverage['first_seen_basis'] == 'earliest_retained_finding_or_assessment'
    assert record(db, 'snapshot', 'before-exclusion') is None
    assert record(db, 'snapshot', 'after-exclusion')['devices'] == 1
    assert record(db, 'snapshot', 'empty-before')['devices'] == 0
    assert record(db, 'status', 'fleet_visibility_boundary') is None


def batch(db, *, retained_status='completed', target_evidence=False):
    target = {'id': 'target-entry', 'device_id': TARGET, 'finding_ids': ['hardware-finding'], 'status': 'completed'}
    if target_evidence:
        target['evidence_digests'] = ['target-only-evidence']
    vm = {'id': 'vm-entry', 'device_id': VM, 'finding_ids': ['vm-finding'], 'status': retained_status,
          'selected': True, 'plan_id': 'vm-plan', 'result': {'actual_version': '1.1'}}
    put(db, 'remediation_batch', 'mixed-batch', {'name': 'Mixed fixture', 'entries': [target, vm],
        'finding_ids': ['hardware-finding', 'vm-finding'], 'status': 'completed', 'revision': 4,
        'target_versions': {'target-entry': '1.2', 'vm-entry': '1.1'}, 'commands': {'old': 'approval'}})
    put(db, 'remediation_batch', 'target-only-batch', {'entries': [target], 'status': 'completed'})
    db.commit()
    return vm


def test_mixed_batches_remove_target_entries_preserve_vm_outcome_and_stop_authorization(database):
    db, _ = database
    vm = batch(db)
    report = purge_device(db, TARGET, apply=True)
    value = record(db, 'remediation_batch', 'mixed-batch')
    assert report['mixed_batches_updated'] == 1
    assert value['entries'] == [vm]
    assert value['finding_ids'] == ['vm-finding']
    assert value['target_versions'] == {'vm-entry': '1.1'}
    assert value['revision'] == 5 and value['status'] == 'completed'
    assert value['paused'] is True and value['stop_requested'] is True and value['commands'] == {}
    assert record(db, 'remediation_batch', 'target-only-batch') is None


def test_removed_batch_member_cannot_pin_target_only_evidence(database):
    db, path = database
    batch(db, target_evidence=True)
    before = snapshot(db)
    with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True) as readonly:
        preview = purge_device(readonly, TARGET)
    assert snapshot(db) == before
    applied = purge_device(db, TARGET, apply=True)
    assert preview['records_removed'] == applied['records_removed']
    assert record(db, 'evidence_snapshot', 'target-only-evidence') is None
    assert record(db, 'evidence_snapshot', 'shared-evidence')


def test_raw_target_evidence_referenced_by_retained_vm_blocks_purge(database):
    db, _ = database
    put(db, 'finding', 'vm-full-finding', {'device_id': VM, 'cve_id': VM_CVE,
                                         'evidence_ids': ['hardware-evidence']}, VM)
    db.commit(); before = snapshot(db)
    with pytest.raises(ValueError) as error:
        purge_device(db, TARGET, apply=True)
    assert 'evidence' in str(error.value).lower()
    assert snapshot(db) == before


def test_shared_artifact_device_association_requires_resolution_without_data_loss(database):
    db, _ = database
    put(db, 'artifact', 'shared-device-list', {'metadata': {'devices': [TARGET, VM]}})
    db.commit(); before = snapshot(db)
    with pytest.raises(ValueError, match='associations'):
        purge_device(db, TARGET, apply=True)
    assert snapshot(db) == before


def test_operation_with_another_device_history_is_not_deleted_by_archive_tag(database):
    db, _ = database
    operation(db, 'mixed-operation', {'device_id': VM})
    db.execute("UPDATE smart_patch_operations SET payload=json_set(payload,'$.archived_device_id',?) WHERE id='mixed-operation'", (TARGET,))
    db.commit(); before = snapshot(db)
    with pytest.raises(ValueError, match='other-device data'):
        purge_device(db, TARGET, apply=True)
    assert snapshot(db) == before


@pytest.mark.parametrize('status', ['queued', 'in_progress'])
@pytest.mark.parametrize('owner', [TARGET, VM])
def test_any_active_central_operation_blocks_apply_without_mutation(database, status, owner):
    db, _ = database
    operation(db, 'active-job', {'device_id': owner}, status)
    db.commit(); before = snapshot(db)
    with pytest.raises(ValueError, match='central operations'):
        purge_device(db, TARGET, apply=True)
    assert snapshot(db) == before


@pytest.mark.parametrize('kind,fields', [
    ('plan', {'status': 'installing'}),
    ('plan', {'status': 'staging_queued'}),
    ('plan', {'status': 'pending_reassessment'}),
    ('plan', {'status': 'completed', 'outcome_unknown': True}),
    ('local_remediation', {'status': 'rollback_unknown'}),
    ('action_request', {'status': 'complete', 'delivered_at': OLD, 'result_consumed': False}),
])
def test_unresolved_package_action_blocks_apply_without_mutation(database, kind, fields):
    db, _ = database
    put(db, kind, 'unresolved-package-action', fields, TARGET)
    db.commit(); before = snapshot(db)
    with pytest.raises(ValueError, match='switch package actions'):
        purge_device(db, TARGET, apply=True)
    assert snapshot(db) == before


def test_active_mixed_batch_blocks_apply_without_mutation(database):
    db, _ = database
    batch(db, retained_status='queued')
    before = snapshot(db)
    with pytest.raises(ValueError, match='mixed-batch'):
        purge_device(db, TARGET, apply=True)
    assert snapshot(db) == before


def test_unknown_device_and_repeated_removal_do_not_mutate_remaining_data(database):
    db, _ = database
    before = snapshot(db)
    with pytest.raises(ValueError, match='does not exist'):
        purge_device(db, 'not-enrolled', apply=True)
    assert snapshot(db) == before
    purge_device(db, TARGET, apply=True)
    retained = snapshot(db)
    with pytest.raises(ValueError, match='does not exist'):
        purge_device(db, TARGET, apply=True)
    assert snapshot(db) == retained


def test_cli_refuses_apply_when_pid_is_live_and_leaves_database_unchanged(database, tmp_path):
    db, path = database
    pid_file = tmp_path / 'live.pid'
    pid_file.write_text(str(os.getpid()))
    before = snapshot(db)
    result = subprocess.run([sys.executable, str(SCRIPT), '--database', str(path), '--device-id', TARGET,
                             '--apply', '--pid-file', str(pid_file)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert 'still running' in result.stderr
    assert snapshot(db) == before


def test_cli_dry_run_outputs_counts_without_pid_or_mutation(database):
    db, path = database
    before = snapshot(db)
    result = subprocess.run([sys.executable, str(SCRIPT), '--database', str(path), '--device-id', TARGET],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['applied'] is False and report['integrity'] == 'ok'
    assert report['inventory_messages_removed'] == 2
    assert snapshot(db) == before
