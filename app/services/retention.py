"""Bounded archive-before-delete retention for cold records and finished jobs.

Archives are immutable gzip JSONL chunks, private by default. InventoryMessage,
Device and Token tables are deliberately untouched: sequence/epoch records also
act as replay tombstones, not merely disposable logs.
"""
from collections import deque
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

from sqlalchemy import delete, select, tuple_
from app.db.store import Device, Operation, Record, Store

TERMINAL_OPERATIONS = {"completed", "failed", "cancelled", "canceled", "superseded"}
TERMINAL_RETRIES = {"completed", "exhausted", "superseded", "cancelled", "canceled"}
TERMINAL_ACTIONS = {"complete", "completed", "failed", "denied", "cancelled", "canceled", "superseded", "expired", "observed"}
ARCHIVABLE_KINDS = {"event", "request", "cache", "assessment_response", "finding", "finding_summary", "finding_history",
                    "evidence", "evidence_request", "action_request", "plan", "remediation_batch", "local_remediation", "collector_progress", "external_agent_session",
                    "external_agent_analysis", "external_agent_evidence", "assessment_history", "evidence_snapshot",
                    "snapshot", "analysis_retry", "release_analysis_retry", "release_assessment_history", "release_finding", "package_cve",
                    "analysis_backlog", "analysis_work", "analysis_lifecycle"}
NEVER_EXPIRE_KINDS = {"settings", "token", "release", "build_binding", "artifact", "package", "repository_catalog",
                     "fix_catalog", "signing_key", "status", "external_agent_latest", "cve_discovery"}


def _time(value):
    if not isinstance(value, str):
        raise ValueError("Missing retention timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Retention timestamps require a timezone")
    return result


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _snapshot(row):
    if isinstance(row, Record):
        return {"table":"record", "kind":row.kind, "id":row.id, "owner":row.owner,
                "created_at":row.created_at, "updated_at":row.updated_at, "payload":row.payload}
    return {"table":"operation", "id":row.id, "operation_type":row.operation_type, "status":row.status,
            "dedup_key":row.dedup_key, "created_at":row.created_at, "updated_at":row.updated_at, "payload":row.payload}


def _identity(snapshot):
    return (snapshot["kind"], snapshot["id"]) if snapshot["table"] == "record" else ("operation", snapshot["id"])


def _references(payload):
    """Recognize typed references, without treating arbitrary prose as an ID."""
    result = set()
    single = {"evidence_id":"evidence", "finding_id":"finding", "analysis_id":"external_agent_analysis",
              "session_id":"external_agent_session", "plan_id":"plan", "operation_id":"operation",
              "stage_request_id":"action_request", "action_request_id":"action_request", "batch_id":"remediation_batch",
              "assessment_history_id":"assessment_history", "release_finding_id":"release_finding",
              "evidence_digest":"evidence_snapshot", "snapshot_id":"snapshot",
              "backlog_id":"analysis_backlog", "work_id":"analysis_work", "lifecycle_id":"analysis_lifecycle"}
    many = {"evidence_ids":"evidence", "finding_ids":"finding", "external_agent_analysis_ids":"external_agent_analysis", "evidence_digests":"evidence_snapshot"}
    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in single and isinstance(item, str):
                    target = 'release_finding' if key=='finding_id' and value.get('target_kind')=='release' else single[key]
                    result.add((target, item))
                elif key == "retry_id" and isinstance(item,str):
                    # Active retry operations identify the release/device variant
                    # in adjacent arguments; keeping both possible namespaces is
                    # conservative and preserves whichever record exists.
                    result.add(("analysis_retry",item));result.add(("release_analysis_retry",item))
                elif key in many and isinstance(item, list):
                    result.update((many[key], ident) for ident in item if isinstance(ident, str))
                elif key in ("plan", "finding", "latest_external_analysis") and isinstance(item,dict) and isinstance(item.get("id"),str):
                    target_kind = {"plan":"plan", "finding":"finding", "latest_external_analysis":"external_agent_analysis"}[key]
                    if key=='finding' and value.get('target_kind')=='release':target_kind='release_finding'
                    result.add((target_kind,item["id"]))
                elif key == "evidence" and isinstance(item, list):
                    for evidence in item:
                        ident = evidence if isinstance(evidence, str) else evidence.get("id") if isinstance(evidence, dict) else None
                        if isinstance(ident, str):result.add(("evidence",ident))
                        if isinstance(evidence,(str,dict)):
                            result.add(("evidence_snapshot",hashlib.sha256(_json(evidence)).hexdigest()))
                visit(item)
        elif isinstance(value, list):
            for item in value:visit(item)
    visit(payload)
    return result


def _deadline_expired(payload, current_time):
    try:return _time(payload.get("expires_at")) <= current_time
    except (ValueError,TypeError):return False  # missing/invalid expiry cannot authorize deletion


def _active_record(kind, payload, current_time):
    status = payload.get("status")
    if kind in ("plan", "action_request") and payload.get("outcome_unknown"):
        return True
    if kind == "external_agent_session":
        if status == "open" and _deadline_expired(payload,current_time):return False
        return status not in ("submitted","expired","closed","cancelled")
    if kind == "remediation_batch":
        return status not in ("completed", "completed_with_failures", "stopped")
    if kind == "local_remediation":
        return payload.get('central_resolution',{}).get('status') != 'completed' and status not in ('cancelled','expired','denied','rolled_back')
    if kind == "plan":
        if status in ("draft","approved","validation_failed","target_validation_failed") and _deadline_expired(payload,current_time):return False
        return status not in ("completed","rolled_back","cancelled","denied","expired","rejected","superseded")
    if kind in ("analysis_retry","release_analysis_retry"):
        return status not in TERMINAL_RETRIES
    return status not in TERMINAL_ACTIONS


def _retry_matches_current(session, kind, payload):
    from app.services.release_service import retry_identity, release_retry_identity
    expected = payload.get("expected_identity")
    if not isinstance(expected,dict):return True  # insufficient identity cannot authorize deletion
    # Runtime settings may include environment-only values. Ignore provider
    # revision conservatively, but reuse the scheduler's exact context identity
    # calculation instead of maintaining a second identity implementation.
    context = SimpleNamespace(configuration=lambda:{})
    if kind == "analysis_retry":
        if not payload.get("device_id"):return True
        device = session.get(Device,payload.get("device_id"))
        if device is None:return False
        current = retry_identity(context,Store._device_payload(device))
    else:
        if not payload.get("release_id"):return True
        release = session.get(Record,("release",payload.get("release_id")))
        if release is None:return False
        current = release_retry_identity(context,release.payload)
    return all(current.get(key) == value for key,value in expected.items() if key != "provider_revision")


def _recent(row, cutoff):
    try:return _time(row.updated_at) >= cutoff
    except (TypeError,ValueError):return True


def _analysis_roots(session, add, cutoff):
    """Keep current retry/success tombstones; retire obsolete contexts in order.

Cold work may archive first, while its parent, lifecycle and cited proof/logs
remain. Those can archive in a later batch once no retained work refers to them.
Reference-only parent protection must not expand back to its obsolete children.
"""
    latest = {}
    terminal = {'completed','superseded','exhausted','cancelled','canceled'}
    query = select(Record).where(Record.kind=='analysis_backlog').order_by(Record.updated_at.desc(),Record.id)
    for row in session.scalars(query.execution_options(yield_per=32)):
        value = row.payload if isinstance(row.payload,dict) else {}
        target = (value.get('target_kind'),value.get('target_id'))
        if value.get('status')!='superseded' and target not in latest:
            latest[target]={'id':row.id,'identity':value.get('expected_identity'),'updated_at':row.updated_at}
            add(row.kind,row.id)
        if _recent(row,cutoff) or value.get('status') not in terminal:add(row.kind,row.id)
        for reference in _references(value):add(*reference)
    for row in session.scalars(select(Record).where(Record.kind=='analysis_work').execution_options(yield_per=32)):
        value = row.payload if isinstance(row.payload,dict) else {}
        parent_id = value.get('backlog_id') or row.owner
        parent = session.get(Record,('analysis_backlog',parent_id)) if parent_id else None
        active = latest.get((value.get('target_kind'),value.get('target_id')))
        obsolete = bool(parent and parent.payload.get('status')=='superseded') or bool(
            active and active['identity']!=value.get('expected_identity') and row.updated_at<active['updated_at'])
        operation = session.get(Operation,value['operation_id']) if value.get('operation_id') else None
        if (_recent(row,cutoff) or not obsolete or (operation and operation.status not in TERMINAL_OPERATIONS)):
            add(row.kind,row.id)
        if parent_id:add('analysis_backlog',parent_id,expand=False)
        add('analysis_lifecycle',row.id,expand=False)
        for kind,ident in _references(value):
            add(kind,ident,expand=kind!='analysis_backlog')
    for row in session.scalars(select(Record).where(Record.kind=='analysis_lifecycle').execution_options(yield_per=32)):
        value = row.payload if isinstance(row.payload,dict) else {}
        active = latest.get((value.get('target_kind'),value.get('target_id')))
        obsolete = bool(active and active['identity']!=value.get('expected_identity') and row.updated_at<active['updated_at'])
        operation = session.get(Operation,value['operation_id']) if value.get('operation_id') else None
        if (_recent(row,cutoff) or not obsolete or (operation and operation.status not in TERMINAL_OPERATIONS)):
            add(row.kind,row.id)
        for reference in _references(value):add(*reference)


def _protected(session, cutoff, current_time, max_nodes=100000):
    protected, queued, queue = set(), set(), deque()
    def add(kind, ident, expand=True):
        key = (kind, ident)
        if key not in protected:
            if len(protected) >= max_nodes:
                raise ValueError("Retention reference graph exceeds its safe budget; no records deleted")
            protected.add(key)
        if expand and key not in queued:
            queued.add(key);queue.append(key)
    # Current findings, latest proposals and active operations are roots.
    query = select(Record).where(Record.kind.in_(["finding", "release_finding", "external_agent_latest", "external_agent_analysis"])).order_by(Record.updated_at.desc())
    latest_by_finding, current_findings, current_release_findings, retry_owners = set(), set(), set(), set()
    for row in session.scalars(query.execution_options(yield_per=32)):
        payload = row.payload if isinstance(row.payload,dict) else {}
        if row.kind == "finding" and payload.get("status") in (None, "current"):
            add(row.kind,row.id);add("finding_summary",row.id)
            current_findings.add(row.id)
            if payload.get("assessment_state") == "retry_needed":retry_owners.add(("analysis_retry",row.owner))
            if payload.get("assessment_revision"):
                add("assessment_history",hashlib.sha256(_json([payload["assessment_revision"],row.id])).hexdigest())
        elif row.kind == "release_finding" and payload.get("status") in (None,"current"):
            add(row.kind,row.id);add("package_cve",row.id);current_release_findings.add(row.id)
            if payload.get("assessment_revision"):
                ident = ["release",payload.get("release_id"),payload["assessment_revision"],row.id]
                add("release_assessment_history",hashlib.sha256(_json(ident)).hexdigest())
        elif row.kind == "external_agent_latest":
            add(row.kind,row.id)
        elif row.kind == "external_agent_analysis":
            finding_id = payload.get("finding_id")
            if finding_id and finding_id not in latest_by_finding:
                latest_by_finding.add(finding_id);add(row.kind,row.id)
    for row in session.scalars(select(Operation).where(Operation.status.not_in(TERMINAL_OPERATIONS)).execution_options(yield_per=32)):
        add("operation",row.id)
    _analysis_roots(session,add,cutoff)
    for row in session.scalars(select(Record).where(Record.kind == "release_finding").execution_options(yield_per=32)):
        payload = row.payload if isinstance(row.payload,dict) else {}
        if payload.get("status") == "current" and payload.get("assessment_state") == "retry_needed":
            retry_owners.add(("release_analysis_retry",row.owner))
    for row in session.scalars(select(Record).where(Record.kind.in_(["action_request", "evidence_request", "external_agent_session", "plan", "remediation_batch", "local_remediation", "analysis_retry", "release_analysis_retry"])).execution_options(yield_per=32)):
        payload = row.payload if isinstance(row.payload,dict) else {}
        if _active_record(row.kind,payload,current_time):add(row.kind,row.id)
        elif (row.kind,row.owner) in retry_owners and _retry_matches_current(session,row.kind,payload):
            # A terminal retry for the current context is a retry-budget
            # tombstone. Removing it would recreate attempts=0 next scheduler
            # tick while a current finding still needs analysis.
            add(row.kind,row.id)
    # Kept trust/configuration records may themselves cite evidence. Retaining
    # the record while dropping its proof would turn a current decision opaque.
    for row in session.scalars(select(Record).where(Record.kind.in_(NEVER_EXPIRE_KINDS | {"reviewed_assessment"})).execution_options(yield_per=32)):
        add(row.kind,row.id)
    # Every retained history row keeps its immutable evidence snapshots readable.
    # Cold history can be archived now; its last unreferenced snapshot becomes
    # eligible in a later batch, so a retained history never points at deleted data.
    latest_history = set()
    for row in session.scalars(select(Record).where(Record.kind.in_(("assessment_history","release_assessment_history"))).order_by(Record.updated_at.desc()).execution_options(yield_per=32)):
        payload = row.payload if isinstance(row.payload,dict) else {}
        for digest in payload.get("evidence_digests",[]):
            if isinstance(digest,str):add("evidence_snapshot",digest)
        owners = current_findings if row.kind == "assessment_history" else current_release_findings
        if row.owner in owners and (row.kind,row.owner) not in latest_history:
            latest_history.add((row.kind,row.owner));add(row.kind,row.id)
        try:recent = _time(row.updated_at) >= cutoff
        except (ValueError,TypeError):recent = True
        if recent:add(row.kind,row.id)
    # Recent externally submitted proposals may still be actively reviewed even
    # when a newer proposal exists. Preserve their cited sessions/evidence too.
    for row in session.scalars(select(Record).where(Record.kind == "external_agent_analysis").execution_options(yield_per=32)):
        try:recent = _time(row.updated_at) >= cutoff
        except (ValueError,TypeError):recent = True
        if recent:add(row.kind,row.id)
    # Follow evidence/session chains, preserving registered evidence linked to
    # active sessions and to the latest externally submitted proposal.
    while queue:
        kind, ident = queue.popleft()
        row = session.get(Operation,ident) if kind == "operation" else session.get(Record,(kind,ident))
        if row is None:continue
        for reference_kind,reference_id in _references(row.payload):
            # Historical completed operation -> backlog -> child work is a
            # reference cycle, not proof that the entire old context is live.
            if (reference_kind=='analysis_backlog' and kind=='operation'
                    and row.status in TERMINAL_OPERATIONS and not _recent(row,cutoff)):
                continue
            expand = reference_kind!='analysis_backlog' or (kind=='operation' and row.status not in TERMINAL_OPERATIONS)
            add(reference_kind,reference_id,expand=expand)
        if kind == 'analysis_backlog':
            for work in session.scalars(select(Record).where(Record.kind=='analysis_work',Record.owner==ident).execution_options(yield_per=32)):
                add(work.kind,work.id)
        elif kind == 'analysis_work':
            add('analysis_lifecycle',ident)
        if kind == "external_agent_session":
            for evidence in session.scalars(select(Record).where(Record.kind == "external_agent_evidence",Record.owner == ident).execution_options(yield_per=32)):
                add(evidence.kind,evidence.id)
                record = evidence.payload.get("record",{}) if isinstance(evidence.payload,dict) else {}
                if isinstance(record,dict) and isinstance(record.get("id"),str):add("evidence",record["id"])
    return protected


def _eligible(row, protected, cutoff, current_time):
    snapshot = _snapshot(row)
    try:
        if _time(snapshot["updated_at"]) >= cutoff:return False
    except (ValueError,TypeError):
        return False
    if _identity(snapshot) in protected:return False
    if isinstance(row,Operation):return row.status in TERMINAL_OPERATIONS
    if row.kind not in ARCHIVABLE_KINDS or row.kind in NEVER_EXPIRE_KINDS:return False
    payload = row.payload if isinstance(row.payload,dict) else {}
    if row.kind in ("finding","finding_summary","release_finding","package_cve") and payload.get("status") in (None,"current"):return False
    if row.kind in ("action_request","evidence_request") and payload.get("status") not in TERMINAL_ACTIONS:return False
    if row.kind in ("external_agent_session","plan","remediation_batch","local_remediation","analysis_retry","release_analysis_retry") and _active_record(row.kind,payload,current_time):return False
    if row.kind == "request" and payload.get("status") in (None,"queued","pending","in_progress","running","retry_needed"):return False
    return True


def _write_archive(directory, rows, cutoff, timestamp):
    directory = Path(directory)
    if directory.is_symlink():raise ValueError("Archive directory must not be a symlink")
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    directory.chmod(0o700)
    name = "retention-"+timestamp.strftime("%Y%m%dT%H%M%S")+"-"+uuid.uuid4().hex
    temporary, destination = directory/("."+name+".partial"), directory/(name+".jsonl.gz")
    fd = os.open(str(temporary),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"wb") as raw:
            with gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=0,compresslevel=6) as archive:
                archive.write(_json({"type":"archive_manifest","schema_version":1,"created_at":timestamp.isoformat(),
                                     "cutoff":cutoff.isoformat(),"records":len(rows)})+b"\n")
                for row in rows:
                    archive.write(_json({"type":"row","sha256":hashlib.sha256(_json(row)).hexdigest(),"record":row})+b"\n")
            raw.flush();os.fsync(raw.fileno())
        # link() refuses replacement. Archive chunks are append-only even if an
        # unexpected filename collision occurs.
        os.link(temporary,destination)
        temporary.unlink()
        parent = os.open(str(directory),os.O_RDONLY)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _cursor_query(session, name, query, columns):
    cursor = session.get(Record,("retention_cursor",name))
    position = cursor.payload.get("position") if cursor and isinstance(cursor.payload,dict) else None
    if isinstance(position,list) and len(position) == len(columns) and all(isinstance(value,str) for value in position):
        query = query.where(tuple_(*columns) > tuple_(*position))
    return query.order_by(*columns)


def _save_cursors(store, session, positions):
    for name,position in positions.items():
        store._put(session,"retention_cursor",name,{"position":position})


def archive_expired(store, state_dir, days=365, batch_size=1000, max_archive_bytes=16*1024*1024, current_time=None):
    """Archive cold rows before transactional CAS deletion; never touch live state.

    Rows changed or newly referenced while the archive is written remain in the
    database. The already durable snapshot remains useful audit history. If disk
    I/O fails, deletion never begins. Call repeatedly for additional batches.
    """
    if type(days) is not int or days < 1:raise ValueError("Retention days must be a positive integer")
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:raise ValueError("Retention batches must contain 1-1000 rows")
    if type(max_archive_bytes) is not int or not 1024 <= max_archive_bytes <= 64*1024*1024:
        raise ValueError("Archive byte budget must be between 1 KiB and 64 MiB")
    current_time = current_time or datetime.now(timezone.utc)
    if current_time.tzinfo is None:raise ValueError("Retention time must include a timezone")
    cutoff = current_time-timedelta(days=days)
    cutoff_text = cutoff.isoformat().replace("+00:00","Z")
    rows, used, examined = [], 512, 0  # bounded allowance for the archive manifest
    positions = {}
    scan_limit = batch_size*10
    with store.lock,store.sessions() as session:
        has_records=session.scalar(select(Record.id).where(Record.kind.in_(ARCHIVABLE_KINDS),Record.updated_at < cutoff_text).limit(1))
        has_operations=session.scalar(select(Operation.id).where(Operation.status.in_(TERMINAL_OPERATIONS),Operation.updated_at < cutoff_text).limit(1))
        if not has_records and not has_operations:
            return {"archived":0,"deleted":0,"preserved_changed_or_referenced":0,"examined":0,
                    "scan_limit_reached":False,"archive":None,"cutoff":cutoff.isoformat()}
        protected = _protected(session,cutoff,current_time)
        record_query = _cursor_query(session,"records",select(Record).where(Record.kind.in_(ARCHIVABLE_KINDS),Record.updated_at < cutoff_text),
                                     (Record.updated_at,Record.kind,Record.id))
        operation_query = _cursor_query(session,"operations",select(Operation).where(Operation.status.in_(TERMINAL_OPERATIONS),Operation.updated_at < cutoff_text),
                                        (Operation.updated_at,Operation.id))
        records = iter(session.scalars(record_query.execution_options(yield_per=1)))
        operations = iter(session.scalars(operation_query.execution_options(yield_per=1)))
        # Alternate across calls as well as within each call: a one-row batch
        # or byte-full record batch must not starve the operation stream.
        streams = [("records",records),("operations",operations)]
        next_stream = session.get(Record,("retention_cursor","next_stream"))
        if next_stream and next_stream.payload.get("position") == "operations":streams.reverse()
        while streams and len(rows)<batch_size and examined<scan_limit:
            for name,stream in list(streams):
                if len(rows)>=batch_size or examined>=scan_limit:break
                try:row=next(stream)
                except StopIteration:
                    streams.remove((name,stream));positions[name]=None;continue
                examined+=1
                positions["next_stream"] = "operations" if name == "records" else "records"
                position=[row.updated_at,row.kind,row.id] if name == "records" else [row.updated_at,row.id]
                if not _eligible(row,protected,cutoff,current_time):
                    positions[name]=position;continue
                snapshot=_snapshot(row)
                size=len(_json({"type":"row","sha256":hashlib.sha256(_json(snapshot)).hexdigest(),"record":snapshot}))+1
                if size>max_archive_bytes-512:
                    positions[name]=position;continue  # retain oversized rows for explicit archival
                if used+size>max_archive_bytes:
                    positions["next_stream"] = name
                    streams=[];break
                positions[name]=position
                rows.append(snapshot);used+=size
    result={"archived":0,"deleted":0,"preserved_changed_or_referenced":0,"examined":examined,
            "scan_limit_reached":examined>=scan_limit,"archive":None,"cutoff":cutoff.isoformat()}
    if not rows:
        with store.lock,store.sessions.begin() as session:_save_cursors(store,session,positions)
        return result
    archive = _write_archive(Path(state_dir)/"archive",rows,cutoff,current_time)
    result.update(archived=len(rows),archive=str(archive))
    with store.lock,store.sessions.begin() as session:
        protected = _protected(session,cutoff,current_time)
        for snapshot in rows:
            model = Record if snapshot["table"]=="record" else Operation
            key = (snapshot["kind"],snapshot["id"]) if model is Record else snapshot["id"]
            row = session.get(model,key,with_for_update=True)
            if row is None or not _eligible(row,protected,cutoff,current_time) or _json(_snapshot(row))!=_json(snapshot):
                result["preserved_changed_or_referenced"]+=1;continue
            query = delete(model).where(model.id==snapshot["id"],model.updated_at==snapshot["updated_at"])
            if model is Record:query=query.where(model.kind==snapshot["kind"])
            else:query=query.where(model.status==snapshot["status"])
            deleted = session.execute(query.execution_options(synchronize_session=False)).rowcount
            result["deleted"]+=deleted
            if not deleted:result["preserved_changed_or_referenced"]+=1
        _save_cursors(store,session,positions)
    return result
