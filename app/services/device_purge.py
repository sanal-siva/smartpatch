"""Offline, transactional SQLite device removal; no API visibility filters.

The caller must stop the service before applying. Dry runs use the same selection
and checks in a rolled-back transaction. Shared release/trust data is preserved.
"""
import json
import re
import sqlite3
from datetime import datetime, timezone


SHARED_KINDS = ('artifact', 'release', 'release_finding', 'release_assessment_history',
                'package', 'package_cve', 'build_binding', 'repository_catalog',
                'fix_catalog', 'signing_key', 'settings', 'status', 'cve_discovery',
                'evidence_snapshot', 'remediation_batch', 'snapshot', 'cache')
ACTIVE = {'queued', 'running', 'in_progress', 'executing', 'staging', 'staging_queued', 'downloading',
          'installing', 'installed', 'restarting', 'rolling_back', 'rollback_required',
          'pending_reassessment', 'unknown', 'rollback_unknown'}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _put(db, kind, ident, payload, timestamp):
    db.execute('INSERT OR REPLACE INTO smart_patch_records '
               '(kind,id,owner,created_at,updated_at,payload) VALUES (?,?,NULL,?,?,?)',
               (kind, ident, timestamp, timestamp, _json(payload)))


def purge_device(db, device_id, *, apply=False):
    """Return counts or atomically apply a reviewed permanent-removal plan.

    Caches are derived and invalidated. Historical aggregate observations before
    exclusion cannot be separated, so they are removed instead of hidden. A
    discovery ledger is rebuilt from retained findings/history with partial
    historical coverage explicitly recorded.
    """
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    db.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
    try:
        row = db.execute('SELECT payload FROM smart_patch_devices WHERE id=?', (device_id,)).fetchone()
        if not row:
            raise ValueError('Device does not exist; no data was changed')
        device = json.loads(row[0])
        if db.execute("SELECT count(*) FROM smart_patch_operations WHERE status IN ('queued','in_progress')").fetchone()[0]:
            raise ValueError('Drain queued/running central operations before permanent removal')
        # Temporary identity tables bound memory and avoid parameter-count limits.
        db.execute('CREATE TEMP TABLE purge_records (kind TEXT,id TEXT,PRIMARY KEY(kind,id))')
        db.execute('CREATE TEMP TABLE purge_operations (id TEXT PRIMARY KEY)')
        db.execute('CREATE TEMP TABLE purge_batch_views (id TEXT PRIMARY KEY,payload TEXT)')
        shared = ','.join('?' for _ in SHARED_KINDS)
        # A record explicitly owned by another switch is never transitively deleted.
        foreign = """coalesce(r.owner,'') NOT IN (SELECT id FROM smart_patch_devices WHERE id<>?)
          AND coalesce(json_extract(r.payload,'$.device_id'),'') NOT IN
              (SELECT id FROM smart_patch_devices WHERE id<>?)
          AND coalesce(json_extract(r.payload,'$.smart_patch_instance_id'),'') NOT IN
              (SELECT id FROM smart_patch_devices WHERE id<>?)
          AND NOT (coalesce(json_extract(r.payload,'$.target_kind'),'')='device' AND
              coalesce(json_extract(r.payload,'$.target_id'),'') IN
              (SELECT id FROM smart_patch_devices WHERE id<>?))"""
        db.execute(f"""INSERT OR IGNORE INTO purge_records SELECT r.kind,r.id FROM smart_patch_records r
          WHERE r.kind NOT IN ({shared}) AND ({foreign}) AND
          (r.owner=? OR json_extract(r.payload,'$.device_id')=? OR json_extract(r.payload,'$.smart_patch_instance_id')=? OR
           (json_extract(r.payload,'$.target_kind')='device' AND json_extract(r.payload,'$.target_id')=?) OR
           json_extract(r.payload,'$.archived_device_id')=? OR
           (r.kind='scheduler_cadence' AND r.id=?))""",
          (*SHARED_KINDS, device_id, device_id, device_id, device_id,
           device_id, device_id, device_id, device_id, device_id, 'scan:'+device_id))
        while True:
            cursor = db.execute(f"""INSERT OR IGNORE INTO purge_records
              SELECT r.kind,r.id FROM smart_patch_records r WHERE r.kind NOT IN ({shared})
              AND ({foreign}) AND r.owner IN (SELECT id FROM purge_records)""",
              (*SHARED_KINDS, device_id, device_id, device_id, device_id))
            if cursor.rowcount == 0:
                break
        db.execute("""INSERT INTO purge_operations SELECT id FROM smart_patch_operations
          WHERE json_extract(payload,'$.arguments.device_id')=? OR
          json_extract(payload,'$.archived_device_id')=? OR
          (json_extract(payload,'$.arguments.target_kind')='device' AND json_extract(payload,'$.arguments.target_id')=?) OR
          json_extract(payload,'$.arguments.backlog_id') IN (SELECT id FROM purge_records WHERE kind='analysis_backlog') OR
          json_extract(payload,'$.arguments.plan_id') IN (SELECT id FROM purge_records WHERE kind='plan')""",
          (device_id, device_id, device_id))
        shared_operation = db.execute("""SELECT 1 FROM smart_patch_operations o
          JOIN purge_operations p USING(id),json_tree(o.payload) j
          JOIN smart_patch_devices d ON j.value=d.id
          WHERE j.type='text' AND d.id<>? LIMIT 1""", (device_id,)).fetchone()
        if shared_operation:
            raise ValueError('An operation contains other-device data; resolve that association before removal')
        for kind, payload in db.execute("""SELECT r.kind,r.payload FROM smart_patch_records r
          JOIN purge_records p USING(kind,id) WHERE r.kind IN ('plan','local_remediation','action_request')"""):
            value = json.loads(payload)
            resolved = kind == 'local_remediation' and value.get('central_resolution', {}).get('status') == 'completed'
            if not resolved and (value.get('outcome_unknown') or value.get('status') in ACTIVE or
                (kind == 'action_request' and value.get('delivered_at') and not value.get('result_consumed'))):
                raise ValueError('Resolve outstanding switch package actions before permanent removal')

        # Remove target members from mixed batches; retain the other members and
        # their original outcomes. Never restore authorization while doing cleanup.
        batches = []
        for ident, raw in db.execute("SELECT id,payload FROM smart_patch_records WHERE kind='remediation_batch'"):
            value = json.loads(raw)
            removed = [entry for entry in value.get('entries', []) if entry.get('device_id') == device_id]
            if not removed:
                continue
            entries = [entry for entry in value['entries'] if entry.get('device_id') != device_id]
            if not entries:
                db.execute("INSERT OR IGNORE INTO purge_records VALUES ('remediation_batch',?)", (ident,))
                continue
            if any(entry.get('status') in ACTIVE for entry in value['entries']):
                raise ValueError('Resolve active mixed-batch work before permanent removal')
            entry_ids = {entry['id'] for entry in entries}
            value.update(entries=entries, finding_ids=[fid for e in entries for fid in e.get('finding_ids', [])],
                target_versions={k:v for k,v in value.get('target_versions', {}).items() if k in entry_ids},
                revision=value.get('revision', 0)+1, updated_at=timestamp,
                name='Remediation batch', commands={}, paused=True, stop_requested=True)
            value.pop('create_hash', None)
            value.pop('pause_reason', None)
            value.pop('archived_finding_ids', None)
            value.pop('archived_device_id', None)
            value.pop('archived_device_ids', None)
            if value.get('status') not in {'completed', 'completed_with_failures', 'stopped'}:
                value['status'] = 'stopped'
            batches.append((ident, value))
            db.execute('INSERT INTO purge_batch_views VALUES (?,?)', (ident, _json(value)))

        retained_payloads = """SELECT r.payload FROM smart_patch_records r
          WHERE r.kind NOT IN ('cache','assessment_response','evidence_snapshot','cve_discovery','snapshot')
          AND NOT EXISTS (SELECT 1 FROM purge_records p WHERE p.kind=r.kind AND p.id=r.id)
          AND NOT (r.kind='remediation_batch' AND r.id IN (SELECT id FROM purge_batch_views))
          UNION ALL SELECT payload FROM purge_batch_views"""

        # A device-owned evidence row can be referenced by another switch's
        # retained assessment. Do not erase its proof or silently rewrite its
        # subject/ownership; this relationship requires an explicit resolution.
        shared_evidence = db.execute(f"""WITH retained AS ({retained_payloads})
          SELECT 1 FROM retained r,json_tree(r.payload) j
          WHERE j.type='text' AND j.value IN (SELECT id FROM purge_records WHERE kind='evidence') LIMIT 1""").fetchone()
        if shared_evidence:
            raise ValueError('Device evidence is referenced by retained records; resolve shared evidence before removal')
        # Evidence snapshots are content-addressed and can be shared. Delete only
        # target-history candidates with no reference in a retained record.
        db.execute('CREATE TEMP TABLE purge_evidence (id TEXT PRIMARY KEY)')
        db.execute("""INSERT OR IGNORE INTO purge_evidence
          SELECT j.value FROM smart_patch_records r JOIN purge_records p USING(kind,id),
          json_each(r.payload,'$.evidence_digests') j WHERE j.type='text'""")
        db.execute(f"""WITH retained AS ({retained_payloads})
          DELETE FROM purge_evidence WHERE id IN (
          SELECT j.value FROM retained r,json_tree(r.payload) j
          WHERE j.type='text' AND j.value IN (SELECT id FROM purge_evidence))""")
        db.execute("""INSERT OR IGNORE INTO purge_records SELECT kind,id FROM smart_patch_records
          WHERE kind='evidence_snapshot' AND id IN (SELECT id FROM purge_evidence)""")
        db.execute("INSERT OR IGNORE INTO purge_records SELECT kind,id FROM smart_patch_records WHERE kind IN ('cache','assessment_response')")
        cutoff = device.get('archived_at') or timestamp
        db.execute("""INSERT OR IGNORE INTO purge_records SELECT kind,id FROM smart_patch_records
          WHERE kind='snapshot' AND coalesce(json_extract(payload,'$.devices'),0)>0
          AND coalesce(json_extract(payload,'$.measured_at'),created_at)<?""", (cutoff,))
        db.execute("""INSERT OR IGNORE INTO purge_records SELECT kind,id FROM smart_patch_records
          WHERE kind='status' AND id='fleet_visibility_boundary'""")
        # Unknown cross-device/shared associations must not produce a partial
        # purge or cause us to delete another switch's records by association.
        residual = db.execute("""SELECT 1 FROM smart_patch_records r
          WHERE (r.owner=? OR instr(r.payload,?)>0)
          AND NOT EXISTS (SELECT 1 FROM purge_records p WHERE p.kind=r.kind AND p.id=r.id)
          AND NOT (r.kind='remediation_batch' AND r.id IN (SELECT id FROM purge_batch_views))
          UNION ALL SELECT 1 FROM purge_batch_views WHERE instr(payload,?)>0 LIMIT 1""",
          (device_id, device_id, device_id)).fetchone()
        if residual:
            raise ValueError('Device references remain in shared or other-device records; resolve those associations before removal')
        if db.execute("""SELECT 1 FROM smart_patch_operations WHERE instr(payload,?)>0
                       AND id NOT IN (SELECT id FROM purge_operations) LIMIT 1""", (device_id,)).fetchone():
            raise ValueError('Device references remain in shared operations; resolve those associations before removal')
        counts = dict(db.execute('SELECT kind,count(*) FROM purge_records GROUP BY kind'))
        report = {'device_id':device_id, 'applied':apply, 'records_removed':counts,
            'devices_removed':1, 'tokens_removed':db.execute('SELECT count(*) FROM smart_patch_tokens WHERE device_id=?',(device_id,)).fetchone()[0],
            'inventory_messages_removed':db.execute('SELECT count(*) FROM smart_patch_inventory_messages WHERE device_id=?',(device_id,)).fetchone()[0],
            'operations_removed':db.execute('SELECT count(*) FROM purge_operations').fetchone()[0],
            'mixed_batches_updated':len(batches), 'discovery_ledger_rebuilt':True,
            'shared_release_and_trust_data_preserved':True}
        if apply:
            db.execute('DELETE FROM smart_patch_tokens WHERE device_id=?', (device_id,))
            db.execute('DELETE FROM smart_patch_inventory_messages WHERE device_id=?', (device_id,))
            db.execute('DELETE FROM smart_patch_operations WHERE id IN (SELECT id FROM purge_operations)')
            db.execute('DELETE FROM smart_patch_records WHERE (kind,id) IN (SELECT kind,id FROM purge_records)')
            for ident, value in batches:
                db.execute("UPDATE smart_patch_records SET payload=?,updated_at=? WHERE kind='remediation_batch' AND id=?",
                           (_json(value), timestamp, ident))
            db.execute('DELETE FROM smart_patch_devices WHERE id=?', (device_id,))
            coverage = db.execute("SELECT payload FROM smart_patch_records WHERE kind='status' AND id='cve_discovery_coverage'").fetchone()
            db.execute("DELETE FROM smart_patch_records WHERE kind='cve_discovery'")
            for cve, first in db.execute("""SELECT upper(json_extract(payload,'$.cve_id')),
                min(json_extract(payload,'$.first_seen')) FROM smart_patch_records
                WHERE kind IN ('finding_summary','assessment_history') GROUP BY upper(json_extract(payload,'$.cve_id'))""").fetchall():
                if cve and re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', cve) and first and first <= timestamp:
                    _put(db, 'cve_discovery', cve, {'id':cve,'cve_id':cve,'first_seen':first,
                        'scope':'device_fleet','meaning':'First retained candidate observation; not publication or confirmed applicability'}, timestamp)
            details = json.loads(coverage[0]) if coverage else {'ledger_started_at':timestamp}
            details.update(history_complete=False, rebuilt_at=timestamp, scope='device_fleet',
                first_seen_basis='earliest_retained_finding_or_assessment',
                limitations=['Device removal rebuilt discovery from retained findings/history; earlier unavailable history cannot be reconstructed.'])
            _put(db, 'status', 'cve_discovery_coverage', details, timestamp)
            db.commit()
        else:
            db.rollback()
        return report
    except BaseException:
        db.rollback()
        raise
    finally:
        for table in ('purge_records', 'purge_operations', 'purge_evidence', 'purge_batch_views'):
            db.execute('DROP TABLE IF EXISTS temp.'+table)
