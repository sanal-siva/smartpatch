"""Transactional persistence for scoped inventory, jobs, credentials and evidence."""
import hashlib
import json
import re
import secrets
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sqlalchemy import Column, Integer, JSON, String, UniqueConstraint, Index, create_engine, select, delete, event, func, or_, and_, case
from sqlalchemy.orm import declarative_base, sessionmaker, aliased
from sqlalchemy.pool import StaticPool
from app.services.applicability_context import applicability_facts, assessment_facts

Base = declarative_base()

FINDING_SUMMARY_FIELDS=('device_id','hostname','cve_id','component_id','scope','package_name','affected_version','severity',
    'cvss_score','fixed_versions','candidate_fixed_versions','applicability','exposure','rationale','assessed_at','first_seen',
    'last_seen','status','inventory_digest','inventory_epoch','build_id','artifact_id','artifact_verified','binding_revision',
    'assessment_state','review_required','action_type','advisory_namespace','advisory_sources','evidence_ids',
    'decision_valid_until','decision_basis','exposure_valid_until','ruleset_version','context_hash','vex_justification',
    'build_evidence_policy','assessment_policy_revision','artifact_binding','remediation_eligible',
    'analysis_managed','analysis_attempts','analysis_success','analysis_last_attempt_at','analysis_next_attempt_at',
    'analysis_retry_exhausted','analysis_error')


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def stable_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,allow_nan=False).encode()).hexdigest()


def inventory_hash(components):
    return stable_hash(sorted(components, key=lambda c: c['component_id']))


class Device(Base):
    __tablename__ = 'smart_patch_devices'
    id = Column(String(128), primary_key=True)
    epoch = Column(String(128), nullable=False)
    sequence = Column(Integer, nullable=False, default=0)
    inventory_digest = Column(String(256), nullable=False)
    last_seen = Column(String(40), index=True)
    payload = Column(JSON, nullable=False)


class InventoryMessage(Base):
    __tablename__ = 'smart_patch_inventory_messages'
    id = Column(String(36), primary_key=True)
    device_id = Column(String(128), index=True)
    epoch = Column(String(128), nullable=False)
    sequence = Column(Integer, nullable=False)
    digest = Column(String(64), nullable=False)
    created_at = Column(String(40), nullable=False)
    __table_args__ = (UniqueConstraint('device_id', 'epoch', 'sequence'),)


class Record(Base):
    __tablename__ = 'smart_patch_records'
    kind = Column(String(40), primary_key=True)
    id = Column(String(256), primary_key=True)
    owner = Column(String(128), index=True)
    created_at = Column(String(40), nullable=False, index=True)
    updated_at = Column(String(40), nullable=False)
    payload = Column(JSON, nullable=False)
    __table_args__=(Index('ix_smart_patch_records_kind_owner_updated','kind','owner','updated_at'),)


class Token(Base):
    __tablename__ = 'smart_patch_tokens'
    id = Column(String(36), primary_key=True)
    digest = Column(String(64), unique=True, nullable=False)
    role = Column(String(16), nullable=False)
    device_id = Column(String(128))
    description = Column(String(256), nullable=False)
    created_at = Column(String(40), nullable=False)
    last_used_at = Column(String(40))
    revoked = Column(Integer, nullable=False, default=0)


class Operation(Base):
    __tablename__ = 'smart_patch_operations'
    id = Column(String(36), primary_key=True)
    operation_type = Column(String(40), nullable=False)
    status = Column(String(20), nullable=False, index=True)
    dedup_key = Column(String(128), index=True)
    created_at = Column(String(40), nullable=False)
    updated_at = Column(String(40), nullable=False)
    payload = Column(JSON, nullable=False)


class Store:
    def __init__(self, database_url):
        kwargs = {'pool_pre_ping': True}
        if database_url.startswith('sqlite:'):
            if database_url not in ('sqlite://', 'sqlite:///:memory:'):
                Path(database_url.removeprefix('sqlite:///')).parent.mkdir(parents=True, exist_ok=True)
            kwargs['connect_args'] = {'check_same_thread': False, 'timeout': 30}
            if ':memory:' in database_url or database_url == 'sqlite://':
                kwargs['poolclass'] = StaticPool
        self.engine = create_engine(database_url, **kwargs)
        if database_url.startswith('sqlite:'):
            @event.listens_for(self.engine, 'connect')
            def configure_sqlite(connection, _record):
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA busy_timeout=30000')
        Base.metadata.create_all(self.engine)
        for index in Record.__table__.indexes:
            index.create(self.engine,checkfirst=True)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.lock = threading.RLock()
        self._backfill_finding_summaries()
        self._backfill_cve_discoveries()

    @staticmethod
    def _discovery_time(value):
        try:
            parsed=value if isinstance(value,datetime) else datetime.fromisoformat(value.replace('Z','+00:00'))
            if parsed.tzinfo is None:return None
            return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
        except (AttributeError,TypeError,ValueError):return None

    @staticmethod
    def _record_cve_discovery(session, cve_id, first_seen):
        """One monotonic fleet-first observation survives finding/history expiry."""
        ident=str(cve_id or '').upper()
        instant=Store._discovery_time(first_seen)
        if not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}',ident) or not instant or instant>Store._discovery_time(now()):return
        previous=session.get(Record,('cve_discovery',ident))
        if previous and previous.payload['first_seen']<=instant:return
        Store._put(session,'cve_discovery',ident,{'id':ident,'cve_id':ident,'first_seen':instant,
                   'scope':'device_fleet','meaning':'First recorded candidate observation; not publication or confirmed applicability'})

    def _backfill_cve_discoveries(self):
        """One-time projection migration; never read historical evidence bodies."""
        with self.lock,self.sessions.begin() as session:
            if session.get(Record,('status','cve_discovery_coverage')) is not None:return
            earliest={}
            rows=session.execute(select(Record.payload['cve_id'].as_string(),Record.payload['first_seen'].as_string())
                .where(Record.kind.in_(['finding_summary','assessment_history'])).execution_options(yield_per=256))
            for cve_id,first_seen in rows:
                ident=str(cve_id or '').upper();instant=self._discovery_time(first_seen)
                if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}',ident) and instant and instant<=self._discovery_time(now()):
                    earliest[ident]=min(earliest.get(ident,instant),instant)
            for ident,instant in earliest.items():self._record_cve_discovery(session,ident,instant)
            self._put(session,'status','cve_discovery_coverage',{'ledger_started_at':now(),
                'history_complete':False,'first_seen_basis':'earliest_retained_finding_or_assessment',
                'scope':'device_fleet','backfilled_distinct_cves':len(earliest),
                'limitations':['Preexisting archives and deleted findings cannot be reconstructed from current database records.',
                               'An empty interval does not establish successful collection or absence of vulnerabilities.']})

    def cve_discovery_trends(self, start, end, resolution='day'):
        """Aggregate a bounded UTC window without hydrating findings or evidence."""
        lower,upper=self._discovery_time(start),self._discovery_time(end)
        if resolution not in {'hour','day'} or not lower or not upper or lower>upper:
            raise ValueError('Discovery interval requires ordered timezone-aware times and hour/day resolution')
        if datetime.fromisoformat(upper.replace('Z','+00:00'))-datetime.fromisoformat(lower.replace('Z','+00:00'))>timedelta(days=367):
            raise ValueError('Discovery interval exceeds 367 days')
        instant=Record.payload['first_seen'].as_string()
        bucket=func.substr(instant,1,13 if resolution=='hour' else 10)
        with self.sessions() as session:
            total,earliest=session.execute(select(func.count(),func.min(instant)).where(Record.kind=='cve_discovery')).one()
            rows=session.execute(select(bucket,func.count()).where(Record.kind=='cve_discovery',instant>=lower,instant<=upper)
                                 .group_by(bucket).order_by(bucket)).all()
            coverage=session.get(Record,('status','cve_discovery_coverage'))
            details=dict(coverage.payload) if coverage else {'history_complete':False,'ledger_started_at':None}
        series=[{'date':key[:10],'snapshot_time':key+(':00:00Z' if resolution=='hour' else 'T00:00:00Z'),
                 'first_seen_cves':count} for key,count in rows]
        return {'series':series,'distinct_cves_in_window':sum(count for _,count in rows),
                'total_distinct_cves':total,'earliest_recorded_first_seen':earliest,'coverage':details}

    def _backfill_finding_summaries(self):
        """Upgrade existing records once; never hydrate evidence on dashboard reads."""
        summary=aliased(Record)
        with self.lock,self.sessions.begin() as session:
            devices={}
            ids=list(session.scalars(select(Record.id).outerjoin(summary,and_(summary.kind=='finding_summary',summary.id==Record.id))
                .where(Record.kind=='finding',or_(summary.id.is_(None),summary.updated_at<Record.updated_at,
                    summary.payload['_summary_schema'].as_integer().is_(None),summary.payload['_summary_schema'].as_integer()!=5))))
            for offset in range(0,len(ids),128):
                records=list(session.scalars(select(Record).where(Record.kind=='finding',Record.id.in_(ids[offset:offset+128]))))
                for record in records:
                    row=self._finding_summary(record.payload)
                    if record.owner not in devices:devices[record.owner]=session.get(Device,record.owner)
                    device=devices[record.owner]
                    if device:
                        identity={**device.payload,'inventory_digest':device.inventory_digest,'inventory_epoch':device.epoch,
                                  'artifact_verified':bool(device.payload.get('artifact_verified')),
                                  'binding_revision':device.payload.get('binding_revision','unverified')}
                        if any(record.payload.get(key)!=identity.get(key) for key in
                               ('inventory_digest','inventory_epoch','build_id','artifact_id','artifact_verified','binding_revision')):
                            row['assessment_stale']=True
                    self._put(session,'finding_summary',record.id,row,record.owner)

    @staticmethod
    def _finding_summary(payload):
        result={key:payload.get(key) for key in FINDING_SUMMARY_FIELDS}
        result['_summary_schema']=5
        result['assessment_stale']=bool(payload.get('assessment_stale'))
        for key in ('decision_valid_until','exposure_valid_until'):
            if result.get(key):
                try:
                    value=datetime.fromisoformat(result[key].replace('Z','+00:00'))
                    if value.tzinfo is None:raise ValueError('timezone is required')
                    result[key]=value.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
                except (AttributeError,TypeError,ValueError):result[key]='0001-01-01T00:00:00Z'
        return result

    @staticmethod
    def _summary_decision_expired():
        decision=Record.payload['decision_valid_until'].as_string()
        exposure=Record.payload['exposure_valid_until'].as_string()
        return or_(Record.payload['assessment_stale'].as_boolean().is_(True),
            and_(decision.is_not(None),decision<=now()),and_(exposure.is_not(None),exposure<=now()),
            and_(Record.payload['decision_basis'].as_string()=='operator_review',
                 Record.payload['applicability'].as_string().in_(['fixed','not_affected']),decision.is_(None)),
            and_(Record.payload['exposure'].as_string().in_(['reachable','constrained']),exposure.is_(None)))

    def health(self):
        with self.engine.connect() as connection:
            connection.exec_driver_sql('SELECT 1')
        return True

    def close(self):
        self.engine.dispose()

    @staticmethod
    def _put(session, kind, ident, payload, owner=None):
        item = session.get(Record, (kind, ident))
        if item is None:
            session.add(Record(kind=kind, id=ident, owner=owner, created_at=now(), updated_at=now(), payload=payload))
        else:
            item.payload, item.owner, item.updated_at = payload, owner, now()
        if kind=='finding':
            Store._put(session,'finding_summary',ident,Store._finding_summary(payload),owner)
            Store._record_cve_discovery(session,payload.get('cve_id'),payload.get('first_seen'))

    def put(self, kind, ident, payload, owner=None):
        with self.lock, self.sessions.begin() as session:
            self._put(session, kind, ident, payload, owner)
        return payload

    def get(self, kind, ident):
        with self.sessions() as session:
            item = session.scalar(select(Record).where(Record.kind==kind,Record.id==ident))
            return item.payload if item else None

    def list(self, kind, owner=None, limit=100000):
        with self.sessions() as session:
            query = select(Record).where(Record.kind == kind)
            if owner is not None:
                query = query.where(Record.owner == owner)
            return [v.payload for v in session.scalars(query.order_by(Record.updated_at.desc()).limit(limit))]

    def remove(self, kind, ident):
        with self.lock, self.sessions.begin() as session:
            record = session.get(Record, (kind, ident))
            if record:
                session.delete(record)
                if kind=='finding':
                    summary=session.get(Record,('finding_summary',ident))
                    if summary:session.delete(summary)
            return bool(record)

    def audit(self, event_type, message, device_id=None, details=None, severity='info'):
        ident = str(uuid.uuid4())
        payload = dict(id=ident, type=event_type, message=message, device_id=device_id,
                       details=details or {}, severity=severity, created_at=now())
        return self.put('event', ident, payload, device_id)

    def issue_token(self, description, role='agent', device_id=None, value=None):
        token = value or ('sp_' + secrets.token_urlsafe(36))
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.lock, self.sessions.begin() as session:
            existing = session.scalar(select(Token).where(Token.digest == digest))
            if existing:
                return {'token': token, 'token_id': existing.id}
            record = Token(id=str(uuid.uuid4()), digest=digest, role=role,
                           device_id=device_id, description=description, created_at=now())
            session.add(record)
        return {'token': token, 'token_id': record.id}

    def authenticate(self, value):
        if not value or len(value) > 512:
            return None
        digest = hashlib.sha256(value.encode()).hexdigest()
        with self.sessions() as session:
            token = session.scalar(select(Token).where(Token.digest == digest, Token.revoked == 0))
            if not token:
                return None
            identity=dict(id=token.id, role=token.role, device_id=token.device_id)
            last_used=token.last_used_at
        cutoff=(datetime.now(timezone.utc)-timedelta(seconds=60)).isoformat().replace('+00:00','Z')
        # Revocation is checked on every request; only observational timestamp
        # writes are coalesced to avoid serializing an otherwise read-only burst.
        if not last_used or last_used<cutoff:
            with self.lock,self.sessions.begin() as session:
                token=session.get(Token,identity['id'])
                if not token or token.revoked:return None
                if not token.last_used_at or token.last_used_at<cutoff:token.last_used_at=now()
        return identity

    def tokens(self):
        with self.sessions() as session:
            return [dict(id=t.id, token_id=t.id, description=t.description, role=t.role,
                         device_id=t.device_id, created_at=t.created_at,
                         last_used_at=t.last_used_at, revoked=bool(t.revoked))
                    for t in session.scalars(select(Token).order_by(Token.created_at.desc()))]

    def revoke(self, ident):
        with self.lock, self.sessions.begin() as session:
            token = session.get(Token, ident)
            if not token:
                return False
            token.revoked = 1
        return True

    def device(self, ident):
        with self.sessions() as session:
            device = session.get(Device, ident)
            return self._device_payload(device) if device else None

    def devices(self):
        with self.sessions() as session:
            return [self._device_payload(d) for d in session.scalars(select(Device))]

    def device_summaries(self):
        fields=('hostname','platform','sonic_version','build_id','ip_address','components_count','scopes_count',
                'scan_status','coverage','artifact_verified','artifact_binding','artifact_id','binding_revision',
                'runtime_attestation','last_scan_at','assessment_revision','last_error','resources')
        fields += ('inventory_collected_at','inventory_collection_status','inventory_ttl_seconds','inventory_time_basis')
        fields += ('assessment_build_evidence_policy','assessment_policy_revision','maintenance')
        columns=[Device.id,Device.epoch,Device.sequence.label('last_sequence'),Device.inventory_digest,Device.last_seen]
        columns += [Device.payload[name].label(name) for name in fields]
        with self.sessions() as session:
            return [{**dict(row),'device_id':row['id']} for row in session.execute(select(*columns)).mappings()]

    def finding_counts(self):
        current=(Record.kind=='finding_summary',Record.payload['status'].as_string()=='current')
        applicability=case((self._summary_decision_expired(),'under_investigation'),
                           else_=func.coalesce(Record.payload['applicability'].as_string(),'under_investigation'))
        severity=func.coalesce(Record.payload['severity'].as_string(),'UNKNOWN')
        with self.sessions() as session:
            apps=dict(session.execute(select(applicability,func.count()).where(*current).group_by(applicability)).all())
            severities=dict(session.execute(select(severity,func.count()).where(*current).group_by(severity)).all())
            by_device={}
            for owner,state,count in session.execute(select(Record.owner,applicability,func.count()).where(*current).group_by(Record.owner,applicability)):
                by_device.setdefault(owner,{})[state]=count
            exposed=session.scalar(select(func.count()).select_from(Record).where(*current,
                applicability=='affected',Record.payload['exposure'].as_string()=='reachable'))
            unique_cves=session.scalar(select(func.count(func.distinct(Record.payload['cve_id'].as_string()))).where(
                *current,Record.payload['cve_id'].as_string()!=''))
        return {'total':sum(apps.values()),'applicability':apps,'severity':severities,'by_device':by_device,
                'exposed':exposed,'unique_cves':unique_cves}

    def finding_package_counts(self):
        """Aggregate summaries in SQL; evidence payloads stay outside dashboard reads."""
        current=(Record.kind=='finding_summary',Record.payload['status'].as_string()=='current')
        package=func.coalesce(Record.payload['package_name'].as_string(),'unknown')
        severity=func.upper(func.coalesce(Record.payload['severity'].as_string(),'UNKNOWN'))
        effective=case((self._summary_decision_expired(),'under_investigation'),
                       else_=func.coalesce(Record.payload['applicability'].as_string(),'under_investigation'))
        rows={}
        with self.sessions() as session:
            for name,level,count in session.execute(select(package,severity,func.count()).where(*current).group_by(package,severity)):
                row=rows.setdefault(name,{'package_name':name,'critical':0,'high':0,'medium':0,'low':0,
                                          'unknown':0,'affected_devices':0,'occurrences':0})
                key=level.lower() if level in ('CRITICAL','HIGH','MEDIUM','LOW') else 'unknown'
                row[key]+=count;row['occurrences']+=count
            affected_owner=case((effective=='affected',Record.owner),else_=None)
            for name,count in session.execute(select(package,func.count(func.distinct(affected_owner))).where(*current).group_by(package)):
                rows[name]['affected_devices']=count
        return sorted(rows.values(),key=lambda row:(-row['critical'],-row['high'],-row['occurrences'],row['package_name']))

    def query_findings(self,device_id=None,applicability=None,severity=None,search='',limit=1000,offset=0,sort='severity',fix_available=None):
        """Filter, count and page summaries in SQL; evidence stays in detail reads."""
        fields=FINDING_SUMMARY_FIELDS
        where=[Record.kind=='finding_summary',Record.payload['status'].as_string()=='current']
        if device_id:where.append(Record.owner==device_id)
        expired=self._summary_decision_expired()
        effective=case((expired,'under_investigation'),else_=Record.payload['applicability'].as_string())
        if applicability:where.append(effective==applicability)
        if severity:where.append(func.upper(Record.payload['severity'].as_string())==severity.upper())
        if fix_available is not None:
            # Use the displayed fixed versions, not candidates withheld by the
            # applicability guard. Keep this in SQL so counts and pages agree.
            versions=Record.payload['fixed_versions']
            json_type=func.json_typeof if self.engine.dialect.name=='postgresql' else func.json_type
            version_count=case((json_type(versions)=='array',func.json_array_length(versions)),else_=0)
            where.append(version_count>0 if fix_available else version_count==0)
        if search:
            literal=search[:512].replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            where.append(or_(*(Record.payload[name].as_string().ilike('%'+literal+'%',escape='\\')
                               for name in ('cve_id','package_name','hostname','scope'))))
        rank=case({'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1},value=func.upper(Record.payload['severity'].as_string()),else_=0)
        score=func.coalesce(Record.payload['cvss_score'].as_float(),0)
        ordering=[score.desc(),rank.desc()] if sort=='cvss' else [rank.desc(),score.desc()]
        if sort=='priority':
            ordering=[case({'affected':0,'under_investigation':1},value=effective,else_=2),*ordering]
        boolean_fields={'artifact_verified','remediation_eligible','review_required','analysis_managed',
                        'analysis_success','analysis_retry_exhausted'}
        columns=[Record.id]+[(Record.payload[name].as_boolean() if name in boolean_fields else Record.payload[name]).label(name)
                            for name in fields if name not in ('applicability','exposure','rationale','action_type')]
        columns += [effective.label('applicability'),expired.label('assessment_stale'),
            case((expired,'unknown'),else_=Record.payload['exposure'].as_string()).label('exposure'),
            case((expired,'Supporting decision evidence expired; reassess before relying on this verdict.'),
                 else_=Record.payload['rationale'].as_string()).label('rationale'),
            case((expired,'defer'),else_=Record.payload['action_type'].as_string()).label('action_type')]
        with self.sessions() as session:
            total=session.scalar(select(func.count()).select_from(Record).where(*where))
            rows=session.execute(select(*columns).where(*where).order_by(*ordering,
                Record.payload['cve_id'].as_string(),Record.id).offset(max(0,offset)).limit(min(max(1,limit),5000))).mappings()
            return {'findings':[dict(row) for row in rows],'total':total}

    def operation_counts(self):
        with self.sessions() as session:
            return dict(session.execute(select(Operation.status,func.count()).group_by(Operation.status)).all())

    def analysis_lifecycles(self,target_kind,target_id,finding_id=None,limit=100):
        where=[Record.kind=='analysis_lifecycle',Record.owner==target_id,
               Record.payload['target_kind'].as_string()==target_kind]
        if finding_id:where.append(Record.payload['finding_id'].as_string()==finding_id)
        with self.sessions() as session:
            return list(session.scalars(select(Record.payload).where(*where).order_by(Record.updated_at.desc(),Record.id)
                                        .limit(min(max(int(limit),1),1000))))

    @staticmethod
    def _device_payload(device):
        return {**device.payload, 'id': device.id, 'device_id': device.id,
                'epoch': device.epoch, 'last_sequence': device.sequence,
                'inventory_digest': device.inventory_digest, 'last_seen': device.last_seen}

    @staticmethod
    def _inventory_metadata(facts, fallback=None):
        observed=next((f for f in facts if f.get('collector')=='inventory'),None)
        if observed:
            return {'inventory_collected_at':observed.get('collected_at'),
                    'inventory_collection_status':observed.get('status','unknown'),
                    'inventory_ttl_seconds':observed.get('ttl_seconds',600),
                    'inventory_time_basis':observed.get('time_basis','device_reported')}
        return {'inventory_collected_at':fallback,'inventory_collection_status':'reported',
                'inventory_ttl_seconds':600,'inventory_time_basis':'device_reported'} if fallback else {}

    def update_device(self, ident, updates):
        with self.lock, self.sessions.begin() as session:
            device = session.get(Device, ident)
            if device:
                changed=any(key in updates and updates[key]!=device.payload.get(key)
                            for key in ('artifact_id','artifact_verified','binding_revision','assessment_ruleset_version'))
                device.payload = {**device.payload, **updates}
                if changed:self._invalidate_finding_summaries(session,ident)

    @staticmethod
    def _invalidate_finding_summaries(session,device_id):
        for summary in session.scalars(select(Record).where(Record.kind=='finding_summary',Record.owner==device_id)):
            summary.payload={**summary.payload,'assessment_stale':True}
            summary.updated_at=now()

    def sync(self, envelope, principal, ip_address=''):
        """Atomically acknowledge changes only after reconstructing and checking their hash."""
        if principal.get('role') not in ('agent','admin'):
            raise PermissionError('Agent or administrator credentials are required for inventory synchronization')
        ident, epoch, sequence = envelope['device_id'], envelope['epoch'], envelope['sequence']
        kind = envelope['kind']
        with self.lock, self.sessions.begin() as session:
            if principal['role'] == 'agent':
                token = session.get(Token, principal['id'])
                if not token or token.revoked:
                    raise PermissionError('Agent credential was revoked')
                if token.device_id not in (None, ident):
                    raise PermissionError('Token is bound to another device')
                if token.device_id is None and kind != 'checkpoint':
                    raise PermissionError('New agent credentials must enroll with a checkpoint')
            else:
                token = None
            device = session.scalar(select(Device).where(Device.id == ident).with_for_update())
            if device and token and token.device_id is None:
                raise PermissionError('Existing devices require an explicitly bound replacement credential')
            stored_sequence = device.sequence if device else 0
            if kind != 'checkpoint' and (not device or device.epoch != epoch):
                return dict(ack_sequence=stored_sequence, resync_required=True), False
            if device and kind == 'heartbeat':
                if sequence != device.sequence or envelope['inventory_digest'] != device.inventory_digest:
                    return dict(ack_sequence=device.sequence, resync_required=True), False
                old_facts = device.payload.get('facts', [])
                new_facts = envelope.get('facts') or old_facts
                relevant = lambda facts: [{k:v for k,v in f.items() if k not in ('collected_at','fact_id')}
                                          for f in applicability_facts(facts)]
                context_changed = stable_hash(relevant(old_facts)) != stable_hash(relevant(new_facts))
                quality=lambda facts:[{k:f.get(k) for k in ('collector','scope','status','value','time_basis')}
                                      for f in facts if f.get('collector')=='inventory']
                context_changed=context_changed or stable_hash(quality(old_facts))!=stable_hash(quality(new_facts))
                manifest_changed=(envelope.get('manifest_digest','')!=device.payload.get('manifest_digest','') or
                                  stable_hash(envelope.get('manifest',{}))!=stable_hash(device.payload.get('manifest',{})))
                device.last_seen = now()
                device.payload = {**device.payload, 'resources': envelope.get('resources', {}),
                                  'facts': new_facts,**self._inventory_metadata(new_facts),
                                  'manifest_digest':envelope.get('manifest_digest',''),
                                  'manifest':envelope.get('manifest',{}),'clock_alignment':envelope.get('clock_alignment',{})}
                if manifest_changed:device.payload={**device.payload,'artifact_verified':False,'artifact_binding':'unverified'}
                if context_changed or manifest_changed:
                    device.payload={**device.payload,'scan_status':'pending'}
                    self._invalidate_finding_summaries(session,ident)
                return dict(ack_sequence=sequence, resync_required=False), context_changed or manifest_changed
            digest = stable_hash(envelope)
            prior = session.scalar(select(InventoryMessage).where(
                InventoryMessage.device_id == ident, InventoryMessage.epoch == epoch,
                InventoryMessage.sequence == sequence))
            retired_epoch = device and device.epoch != epoch and session.scalar(select(InventoryMessage.id).where(
                InventoryMessage.device_id == ident, InventoryMessage.epoch == epoch).limit(1))
            if retired_epoch:
                return dict(ack_sequence=stored_sequence, resync_required=True), False
            if prior:
                if prior.digest != digest:
                    raise ValueError('Sequence already committed with different content')
                return dict(ack_sequence=stored_sequence, resync_required=False), False
            if kind == 'delta' and sequence != stored_sequence + 1:
                return dict(ack_sequence=stored_sequence, resync_required=True), False
            if kind == 'checkpoint' and device and device.epoch == epoch and sequence <= stored_sequence:
                return dict(ack_sequence=stored_sequence, resync_required=True), False
            previous_components = device.payload.get('components', []) if device else []
            current = {} if kind == 'checkpoint' else {c['component_id']: c for c in previous_components}
            for removed in envelope.get('removed', []):
                current.pop(removed, None)
            for component in envelope.get('components', []):
                current[component['component_id']] = component
            components = sorted(current.values(), key=lambda c: c['component_id'])
            calculated = inventory_hash(components)
            if envelope['inventory_digest'].removeprefix('sha256:') != calculated:
                raise ValueError('Inventory digest does not match reconstructed components')
            old_payload = device.payload if device else {}
            payload = {**old_payload, **{k: v for k, v in envelope.items()
                       if k not in ('sequence','kind','removed','components')},
                       'components': components, 'ip_address': ip_address,
                       'components_count': len(components), 'scopes_count': len({c['scope'] for c in components}),
                       'scan_status': 'pending', 'artifact_verified': False,
                       'artifact_claimed_verified': bool(envelope.get('artifact_verified')),
                       **self._inventory_metadata(envelope.get('facts',[]),envelope.get('collected_at'))}
            self._invalidate_finding_summaries(session,ident)
            if device is None:
                device = Device(id=ident, epoch=epoch, sequence=sequence,
                                inventory_digest=envelope['inventory_digest'], last_seen=now(), payload=payload)
                session.add(device)
            else:
                device.epoch, device.sequence = epoch, sequence
                device.inventory_digest, device.last_seen, device.payload = envelope['inventory_digest'], now(), payload
            if token and token.device_id is None:
                token.device_id = ident
            session.add(InventoryMessage(id=str(uuid.uuid4()), device_id=ident,
                         epoch=epoch, sequence=sequence, digest=digest, created_at=now()))
            occurrence=lambda c:(c['scope'],c['name'],c.get('architecture',''))
            before={occurrence(c):c for c in previous_components}
            after={occurrence(c):c for c in components}
            changes=[]
            for key in sorted(before.keys() | after.keys()):
                old,new=before.get(key),after.get(key)
                if old and new and old['version']==new['version']:continue
                observed=new or old
                changes.append({'component_id':observed['component_id'],'scope':observed['scope'],
                    'package_name':observed['name'],'architecture':observed.get('architecture',''),
                    'previous_version':old['version'] if old else None,'version':new['version'] if new else None,
                    'change':'updated' if old and new else 'added' if new else 'removed'})
            event_id=str(uuid.uuid4());timestamp=now()
            session.add(Record(kind='event',id=event_id,owner=ident,created_at=timestamp,updated_at=timestamp,
                payload={'id':event_id,'type':'inventory.'+kind,'device_id':ident,'severity':'info',
                    'message':f'Inventory {kind} accepted: {len(components)} components','created_at':timestamp,
                    'details':{'sequence':sequence,'epoch':epoch,'inventory_digest':calculated,
                        'package_changes':changes[:500],'package_changes_total':len(changes),
                        'package_changes_complete':len(changes)<=500}}))
        return dict(ack_sequence=sequence, resync_required=False), True

    def pending_scan_devices(self):
        """Recover inventory commits whose API process stopped before enqueueing."""
        with self.sessions() as session:
            return list(session.scalars(select(Device.id).where(
                Device.payload['scan_status'].as_string()=='pending').limit(500)))

    def enqueue(self, operation_type, arguments, dedup_key=None, *,
                reassessment_requests=(), coalesce_scan=False):
        with self.lock, self.sessions.begin() as session:
            device=session.get(Device,arguments.get('device_id')) if arguments.get('device_id') else None
            # Record each execution/context attempt in the same transaction as
            # enqueueing. Replayed reports and service restarts may reconcile it
            # repeatedly without retrying a completed or failed job forever.
            requests = [(stable_hash([item['id'], dedup_key]), item)
                        for item in reassessment_requests]
            dispatched = [session.get(Record, ('maintenance_scan_dispatch', key)) for key, _ in requests]
            if requests and all(dispatched):
                previous = session.get(Operation, dispatched[-1].payload['operation_id'])
                # A queued operation can have been retargeted to a newer
                # context. Its old dispatch marker no longer proves an attempt
                # for this context if evidence later returns to the old value.
                if previous and previous.dedup_key == dedup_key:
                    return self._operation_payload(previous)
            existing = None
            if dedup_key:
                existing = session.scalar(select(Operation).where(Operation.dedup_key == dedup_key,
                    Operation.status.in_(['queued','in_progress'])))
            queued = []
            if coalesce_scan and operation_type == 'scan' and device:
                queued = list(session.scalars(select(Operation).where(Operation.operation_type == 'scan',
                    Operation.status == 'queued', Operation.payload['arguments']['device_id'].as_string() == device.id)
                    .order_by(Operation.created_at)))
                if not existing and queued:
                    existing = queued[0]
                    existing.dedup_key = dedup_key
                    existing.updated_at = now()
                    fresh_payload = {key: value for key, value in existing.payload.items()
                                     if key not in ('progress_data', 'started_at', 'completed_at')}
                    existing.payload = {**fresh_payload, 'arguments': arguments, 'progress_percentage': 0,
                        'result': None, 'error_message': None,
                        'logs': (existing.payload.get('logs', []) + [{'timestamp': now(),
                            'message': 'Updated queued scan to the latest accepted inventory and context'}])[-500:]}
            operation = existing
            if operation is None:
                ident = str(uuid.uuid4())
                payload = dict(arguments=arguments, progress_percentage=0, logs=[], result=None, error_message=None, attempts=0)
                operation = Operation(id=ident, operation_type=operation_type, status='queued', dedup_key=dedup_key,
                                      created_at=now(), updated_at=now(), payload=payload)
                session.add(operation)
            # A worker is never cancelled. Only redundant jobs which have not
            # been claimed are retired, with their replacement recorded.
            for obsolete in queued:
                if obsolete.id == operation.id:
                    continue
                self._retire_queued_scan(session, obsolete, operation, dedup_key)
            for key, request in requests:
                self._put(session, 'maintenance_scan_dispatch', key,
                    {**request, 'id': key, 'request_id': request['id'],
                     'scan_context': dedup_key, 'operation_id': operation.id,
                     'dispatched_at': now()}, device.id)
        return self._operation_payload(operation)

    @staticmethod
    def _retire_queued_scan(session, obsolete, replacement, context_key):
        """Retire unclaimed work and rebind only its matching-context demands."""
        obsolete.status, obsolete.updated_at, obsolete.dedup_key = 'completed', now(), None
        progress = obsolete.payload.get('progress_data')
        obsolete.payload = {**obsolete.payload, 'completed_at': now(), 'progress_percentage': 100,
            **({'progress_data': {**progress, 'phase': 'superseded'}} if progress else {}),
            'result': {'accepted': False, 'superseded': True, 'replacement_operation_id': replacement.id,
                       'reason': 'A current scan already covers this queued request'}}
        for marker in session.scalars(select(Record).where(Record.kind == 'maintenance_scan_dispatch',
                Record.payload['operation_id'].as_string() == obsolete.id,
                Record.payload['scan_context'].as_string() == context_key)):
            marker.payload = {**marker.payload, 'operation_id': replacement.id,
                              'coalesced_operation_id': obsolete.id}
            marker.updated_at = now()

    def bind_scan_operation(self, ident, dedup_key, arguments, *, coalesce=False):
        """The scanner may discover its DB or inventory identity after enqueue."""
        with self.lock, self.sessions.begin() as session:
            operation = session.get(Operation, ident)
            if not operation or operation.status != 'in_progress':
                return False
            operation.dedup_key, operation.updated_at = dedup_key, now()
            operation.payload = {**operation.payload, 'arguments': arguments, 'scan_context_bound': True}
            if coalesce and operation.operation_type == 'scan':
                duplicates = session.scalars(select(Operation).where(Operation.operation_type == 'scan',
                    Operation.status == 'queued', Operation.dedup_key == dedup_key,
                    Operation.payload['arguments']['device_id'].as_string() == arguments['device_id']))
                for obsolete in duplicates:
                    self._retire_queued_scan(session, obsolete, operation, dedup_key)
            # The operation itself can move from an unknown DB or an older
            # queued snapshot to its actual captured context without any queued
            # duplicate. Preserve each originating execution demand for that
            # actual attempt too, so failure cannot create a second automatic
            # attempt merely because the scanner resolved its DB revision.
            markers = list(session.scalars(select(Record).where(Record.kind == 'maintenance_scan_dispatch',
                Record.payload['operation_id'].as_string() == operation.id)))
            for marker in markers:
                request_id = marker.payload.get('request_id')
                if not request_id:
                    continue
                key = stable_hash([request_id, dedup_key])
                current = session.get(Record, ('maintenance_scan_dispatch', key))
                self._put(session, 'maintenance_scan_dispatch', key,
                    {**marker.payload, **(current.payload if current else {}), 'id': key,
                     'scan_context': dedup_key, 'operation_id': operation.id, 'bound_at': now()},
                    arguments['device_id'])
            return True

    @staticmethod
    def _operation_payload(operation):
        return {**operation.payload, 'id': operation.id, 'operation_id': operation.id,
                'operation_type': operation.operation_type, 'status': operation.status,
                'created_at': operation.created_at, 'updated_at': operation.updated_at}

    def operation(self, ident):
        with self.sessions() as session:
            op = session.scalar(select(Operation).where(Operation.id==ident))
            return self._operation_payload(op) if op else None

    def operations(self, limit=200):
        with self.sessions() as session:
            return [self._operation_payload(o) for o in session.scalars(
                select(Operation).order_by(Operation.created_at.desc()).limit(limit))]

    def claim(self):
        with self.lock, self.sessions.begin() as session:
            operation = session.scalar(select(Operation).where(Operation.status == 'queued')
                .order_by(Operation.created_at).with_for_update(skip_locked=True).limit(1))
            if not operation:
                return None
            operation.status = 'in_progress'
            operation.updated_at = now()
            operation.payload = {**operation.payload, 'started_at': now(), 'attempts': operation.payload.get('attempts',0) + 1}
            return self._operation_payload(operation)

    def update_operation(self, ident, status=None, **updates):
        with self.lock, self.sessions.begin() as session:
            op = session.get(Operation, ident)
            if not op:
                return
            if status:
                op.status = status
            if status in ('completed','failed'):
                updates['completed_at'] = now()
                progress = updates.get('progress_data', op.payload.get('progress_data'))
                if progress:
                    phase = ('failed' if status == 'failed' else 'superseded'
                             if (updates.get('result') or {}).get('accepted') is False else 'complete')
                    updates['progress_data'] = {**progress, 'phase': phase}
                    if status == 'failed':
                        updates['progress_data']['stopped_phase'] = progress.get('phase')
                    else:
                        updates['progress_percentage'] = 100
                else:
                    updates['progress_percentage'] = 100
            op.payload = {**op.payload, **updates}
            op.updated_at = now()

    def operation_log(self, ident, message):
        with self.lock, self.sessions.begin() as session:
            op = session.get(Operation, ident)
            if op:
                logs = op.payload.get('logs', []) + [{'timestamp': now(), 'message': message}]
                op.payload = {**op.payload, 'logs': logs[-500:]}
                op.updated_at=now()

    def recover_jobs(self):
        with self.lock, self.sessions.begin() as session:
            for op in session.scalars(select(Operation).where(Operation.status == 'in_progress')):
                op.status, op.updated_at = 'queued', now()
                op.payload = {**op.payload, 'recovered_after_restart': True}

    def store_findings(self, device_id, digest, result, revision, expected_identity=None, *, complete_scan=True, assessment_kind='scan'):
        with self.lock, self.sessions.begin() as session:
            device = session.scalar(select(Device).where(Device.id == device_id).with_for_update())
            if not device or device.inventory_digest != digest:
                return False
            if expected_identity:
                current_identity = {'epoch':device.epoch,'build_id':device.payload.get('build_id'),
                    'review_revision':device.payload.get('review_revision'),
                    'assessment_revision':device.payload.get('assessment_revision'),
                    'artifact_id':device.payload.get('artifact_id'),'artifact_verified':bool(device.payload.get('artifact_verified')),
                    'binding_revision':device.payload.get('binding_revision','unverified'),
                    'baseline_digest':device.payload.get('baseline_digest'),
                    'manifest_digest':stable_hash(device.payload.get('manifest',{})),
                    'facts_digest':stable_hash(assessment_facts(device.payload.get('facts',[])))}
                if any(current_identity.get(key)!=value for key,value in expected_identity.items()):
                    return False
            existing_query=select(Record).where(Record.kind=='finding',Record.owner==device_id)
            if not complete_scan:
                selected_ids=[stable_hash([device_id,raw.get('component_id') or raw.get('component',{}).get('component_id',''),
                              raw.get('scope_id',raw.get('scope','')),raw.get('cve_id')]) for raw in result.get('findings',[])]
                existing_query=existing_query.where(Record.id.in_(selected_ids))
            existing = {r.id:r for r in session.scalars(existing_query)}
            evidence_index = {e.get('id'): e for e in result.get('evidence', [])}
            current_ids = set()
            for raw in result.get('findings', []):
                component_id = raw.get('component_id') or raw.get('component', {}).get('component_id', '')
                fid = stable_hash([device_id,component_id,raw.get('scope_id',raw.get('scope','')),raw.get('cve_id')])
                current_ids.add(fid)
                previous = existing.get(fid)
                payload = previous.payload if previous else {}
                finding = {**raw, 'id':fid, 'device_id':device_id, 'hostname':device.payload.get('hostname'),
                    'assessment_policy_revision':device.payload.get('assessment_policy_revision'),
                    'inventory_epoch':device.epoch,'build_id':device.payload.get('build_id'),
                    'artifact_id':device.payload.get('artifact_id'),'artifact_verified':bool(device.payload.get('artifact_verified')),
                    'binding_revision':device.payload.get('binding_revision','unverified'),
                    'context_hash':stable_hash(applicability_facts(device.payload.get('facts',[]))),
                    'component_id':component_id, 'scope':raw.get('scope_id',raw.get('scope','host')),
                    'rationale':raw.get('rationale',raw.get('justification','')),
                    'inventory_digest':digest, 'assessment_revision':revision, 'assessed_at':now(),
                    'first_seen':payload.get('first_seen',now()), 'last_seen':now(), 'status':'current',
                    'evidence':raw.get('evidence') or [evidence_index[e] for e in raw.get('evidence_ids',[]) if e in evidence_index]}
                if previous:
                    previous.payload, previous.updated_at = finding, now()
                else:
                    session.add(Record(kind='finding',id=fid,owner=device_id,created_at=now(),updated_at=now(),payload=finding))
                self._put(session,'finding_summary',fid,self._finding_summary(finding),device_id)
                self._record_cve_discovery(session,finding.get('cve_id'),finding['first_seen'])
                evidence_digests=[]
                for evidence in finding['evidence']:
                    evidence_digest=stable_hash(evidence);evidence_digests.append(evidence_digest)
                    if session.get(Record,('evidence_snapshot',evidence_digest)) is None:
                        session.add(Record(kind='evidence_snapshot',id=evidence_digest,owner=None,
                            created_at=now(),updated_at=now(),payload=evidence))
                history_id=stable_hash([revision,fid])
                if session.get(Record,('assessment_history',history_id)) is None:
                    history={**self._finding_summary(finding),'id':history_id,'finding_id':fid,
                        'assessment_revision':revision,'assessment_kind':assessment_kind,'recorded_at':now(),'risk_score':finding.get('risk_score'),
                        'confidence':finding.get('confidence'),'decision_basis':finding.get('decision_basis'),
                        'source_revision':result.get('source_revision'),
                        'scanner':result.get('scanner',{}),'evidence_digests':evidence_digests}
                    session.add(Record(kind='assessment_history',id=history_id,owner=fid,
                        created_at=now(),updated_at=now(),payload=history))
                if not previous or payload.get('applicability') != finding.get('applicability'):
                    event_id = str(uuid.uuid4())
                    details = {'finding_id':fid,'previous':payload.get('applicability'),'applicability':finding.get('applicability')}
                    session.add(Record(kind='event',id=event_id,owner=device_id,created_at=now(),updated_at=now(),
                        payload={'id':event_id,'type':'finding.changed','device_id':device_id,'severity':'info',
                                 'message':f"{finding.get('cve_id')}: {finding.get('applicability')}",'created_at':now(),'details':details}))
            if complete_scan and result.get('coverage',{}).get('complete'):
                for fid, old in existing.items():
                    if fid not in current_ids and old.payload.get('status')=='current':
                        old.payload = {**old.payload,'status':'no_longer_reported','last_seen':now(),
                                       'resolution_basis':'complete scan of current inventory'}
                        self._put(session,'finding_summary',fid,self._finding_summary(old.payload),device_id)
            updates={'assessment_revision':revision,'last_analysis_at':now()}
            if assessment_kind=='scan':
                updates.update(last_scan_at=now(),scan_status='completed' if result.get('coverage',{}).get('complete') else 'partial',
                    coverage=result.get('coverage',{}),scanner=result.get('scanner',{}),errors=result.get('errors',[]))
            else:updates['last_analysis_errors']=result.get('errors',[])[:100]
            device.payload={**device.payload,**updates}
            if complete_scan and assessment_kind == 'scan':
                from app.services.maintenance_reassessment import remember_scan, reconcile
                remember_scan(self, session, device, result, revision)
                reconcile(self, session, device_id)
                from app.services.remediation_status import reconcile_local
                reconcile_local(self, session, device_id)
        return True

    def reconcile_maintenance_plans(self, device_id=None):
        from app.services.maintenance_reassessment import reconcile
        with self.lock, self.sessions.begin() as session:
            result = reconcile(self, session, device_id)
            from app.services.remediation_status import reconcile_local
            result['scan_requests'].extend(reconcile_local(self, session, device_id))
            result['needs_scan'] = sorted({request['device_id'] for request in result['scan_requests']})
            return result

    def retention(self, days=365, state_dir=None):
        if state_dir is None:raise ValueError('An archive directory is required before expiring durable records')
        from app.services.retention import archive_expired
        return archive_expired(self,state_dir,days=days)
