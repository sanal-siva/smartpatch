"""Service orchestration: durable queues, shared analysis and safe result delivery."""
import copy
import json
import os
import re
import secrets
import subprocess
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.fernet import Fernet

from app.db.store import Store, now, stable_hash
from app.services.pipeline import AnalysisPipeline, inventory_coverage, result_cache_fresh
from app.services.assessment import RULESET_VERSION
from app.services.applicability_context import applicability_facts, assessment_facts
from app.services.sbom_parser import SBOMParser
from app.observability.state import ObservationWindow


def age_seconds(timestamp):
    try:
        return max(0, (datetime.now(timezone.utc)-datetime.fromisoformat(timestamp.replace('Z','+00:00'))).total_seconds())
    except (ValueError, TypeError, AttributeError):
        return float('inf')


class Runtime:
    def __init__(self, settings, pipeline_factory=AnalysisPipeline):
        self.settings = settings
        self.state_dir = Path(settings.state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store = Store(settings.database_url)
        self._factory = pipeline_factory
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads = []
        self.started = time.monotonic()
        self.scanner_info = {'status':'initializing'}
        self.advisory_generation = int((self.store.get('status','advisory') or {}).get('generation') or 0)
        self.metrics = Counter()
        self.observations = ObservationWindow()
        self._metrics_lock = threading.Lock()
        self._prepare_secrets()
        self.pipeline = self.make_pipeline()

    def _prepare_secrets(self):
        key_file = self.state_dir/'settings.key'
        if not key_file.exists():
            fd = os.open(key_file, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(Fernet.generate_key())
        self.cipher = Fernet(key_file.read_bytes())
        token_path = self.state_dir/'bootstrap-token'
        value = self.settings.bootstrap_token
        if not value:
            if token_path.exists():
                value = token_path.read_text().strip()
            else:
                value = 'sp_' + secrets.token_urlsafe(36)
                fd = os.open(token_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'w') as stream:
                    stream.write(value+'\n')
        # Existing revoked bootstrap token is never silently re-enabled.
        self.store.issue_token('Local bootstrap administrator','admin',value=value)

    def configuration(self, public=False):
        config = self.settings.model_dump(mode='json')
        overrides = self.store.get('settings','service') or {}
        config.update({k:v for k,v in overrides.items() if k != 'ai_api_key_encrypted'})
        config['assessment_policy_revision'] = (self.store.get('status', 'ruleset') or {}).get('policy_revision')
        if overrides.get('ai_api_key_encrypted'):
            config['ai_api_key'] = self.cipher.decrypt(overrides['ai_api_key_encrypted'].encode()).decode()
        config['scanner_env'] = {'GRYPE_DB_CACHE_DIR':str(Path(config['scanner_db_dir']).resolve()),
                                 'GRYPE_DB_AUTO_UPDATE':'false','GRYPE_CHECK_FOR_APP_UPDATE':'false'}
        if not config.get('ai_enabled'):
            config['ai_api_key'] = ''
        if public:
            allowed = ['ai_provider','ai_model','ai_api_url','ai_enabled','source_roots','source_revision',
                       'scan_interval_seconds','scanner_binary','worker_count','online_threshold_seconds',
                       'ai_max_calls','ai_max_findings','ai_max_tool_calls','ai_max_input_chars','ai_max_output_tokens',
                       'alerts_enabled','alert_min_samples','alert_latency_p95_seconds','alert_cache_hit_rate_percent',
                       'alert_error_rate_percent','alert_queue_depth','build_evidence_policy']
            result = {k:config[k] for k in allowed}
            result.update(ai_api_key_set=bool(config.get('ai_api_key') or overrides.get('ai_api_key_encrypted')),
                          auth_required=True,host=config['host'],port=config['port'])
            return result
        return config

    def save_configuration(self, changes):
        allowed = {'ai_provider','ai_model','ai_api_url','ai_api_key','ai_enabled','source_roots','source_revision',
                   'scan_interval_seconds','ai_max_calls','ai_max_findings','ai_max_tool_calls','ai_max_input_chars','ai_max_output_tokens',
                   'alerts_enabled','alert_min_samples','alert_latency_p95_seconds','alert_cache_hit_rate_percent',
                   'alert_error_rate_percent','alert_queue_depth','build_evidence_policy'}
        unknown = set(changes)-allowed
        if unknown:
            raise ValueError('Unsupported configuration fields: '+', '.join(sorted(unknown)))
        merged = self.configuration()
        merged.update(changes)
        self.settings.__class__(**{k:v for k,v in merged.items() if k!='scanner_env'})
        for root in changes.get('source_roots',[]):
            if not Path(root).is_dir():
                raise ValueError('Source root must be an existing directory')
        updates = dict(changes)
        if 'ai_api_key' in updates:
            key = updates.pop('ai_api_key')
            updates['ai_api_key_encrypted'] = self.cipher.encrypt(key.encode()).decode() if key else ''
        with self.store.lock:
            old = self.store.get('settings','service') or {}
            self.store.put('settings','service',{**old,**updates})
            if 'build_evidence_policy' in changes:
                self.ensure_ruleset_current()
            if any(name.startswith('ai_') or name.startswith('source_') or name == 'build_evidence_policy' for name in changes):
                self.pipeline = self.make_pipeline()
        self.store.audit('settings.updated','Service settings updated',details={'fields':sorted(changes)})
        return self.configuration(public=True)

    def make_pipeline(self):
        config = self.configuration()
        reviewed = self.store.list('reviewed_assessment')
        config['trusted_assessments'] = reviewed
        config['trusted_evidence'] = self.store.list('evidence')
        return self._factory(config['source_roots'],config['scanner_binary'],config)

    def refresh_reviewed_assessments(self):
        """Refresh policy evidence without resetting provider failure/cooldown state."""
        from app.services.assessment import AssessmentEngine
        reviewed=self.store.list('reviewed_assessment')
        self.pipeline.engine=AssessmentEngine(reviewed, build_evidence_policy=self.configuration().get('build_evidence_policy', 'required'))
        self.pipeline.settings['trusted_assessments']=reviewed
        self.pipeline.settings['trusted_evidence']=self.store.list('evidence')

    def start(self):
        self.store.recover_jobs()
        previous=self.store.get('status','ruleset') or {}
        policy=self.configuration().get('build_evidence_policy','required')
        # An actual policy change must invalidate saved results even with workers
        # disabled; ordinary read-only restarts must preserve scheduler cadence.
        if self.settings.jobs_enabled or previous.get('build_evidence_policy','required')!=policy:
            self.ensure_ruleset_current()
        if self.settings.jobs_enabled:
            # Resolve the local DB before durable demand recovery. Otherwise a
            # restart invents an "unknown DB" context for an already attempted
            # known-DB execution and can enqueue the same failed work again.
            try:
                self.scanner_info = self.pipeline.scanner.status()
            except Exception as exc:
                self.store.audit('scheduler.failed', str(exc)[:1000], details={'cadence': 'scanner_status'}, severity='error')
            self.reconcile_maintenance()
            for index in range(self.settings.worker_count):
                thread = threading.Thread(target=self._worker,name=f'smart-patch-worker-{index}',daemon=True)
                thread.start();self._threads.append(thread)
            thread = threading.Thread(target=self._scheduler,name='smart-patch-scheduler',daemon=True)
            thread.start();self._threads.append(thread)

    def ensure_ruleset_current(self):
        previous=self.store.get('status','ruleset') or {}
        policy=self.configuration().get('build_evidence_policy', 'required')
        if previous.get('version')==RULESET_VERSION and previous.get('build_evidence_policy', 'required')==policy:return []
        policy_changed=previous.get('build_evidence_policy', 'required') != policy
        policy_revision=str(uuid.uuid4()) if policy_changed else previous.get('policy_revision')
        pending=[]
        with self.store.lock:
            for device in self.store.device_summaries():
                self.store.update_device(device['id'],{'assessment_ruleset_version':RULESET_VERSION,
                    'assessment_build_evidence_policy':policy,'assessment_policy_revision':policy_revision,'scan_status':'pending'})
                pending.append(device['id'])
            # Old findings remain inspectable but cannot authorize action. Store.put
            # refreshes the finding summary so fleet totals also reflect staleness.
            for kind in ('finding', 'release_finding', 'package_cve'):
                for finding in self.store.list(kind, limit=None):
                    if finding.get('status') == 'current':
                        self.store.put(kind, finding['id'], {**finding, 'assessment_stale': True},
                                       finding.get('device_id') or finding.get('release_id'))
            for release in self.store.list('release', limit=None):
                self.store.put('release', release['release_id'], {**release, 'status': 'pending',
                    'assessment_build_evidence_policy': policy, 'assessment_policy_revision':policy_revision}, release['release_id'])
                cadence=self.store.get('scheduler_cadence', 'release:' + release['release_id'])
                if cadence:
                    self.store.put('scheduler_cadence', cadence['id'], {**cadence, 'status': 'due', 'next_due_at': now()})
            if policy_changed:
                for record in self.store.list('reviewed_assessment', limit=None):
                    if record.get('verification') in {'reviewed', 'artifact_verified'}:
                        self.store.put('reviewed_assessment', record['id'], {**record, 'verification': 'invalidated',
                            'invalidated_at': now(), 'invalidation_reason': 'Build evidence policy changed; a fresh scoped review is required'})
                for plan in self.store.list('plan', limit=None):
                    if plan.get('status') not in {'completed', 'rolled_back', 'cancelled', 'superseded'}:
                        self.store.put('plan', plan['id'], {**plan, 'status': 'requires_revalidation', 'approved': False,
                            'staging_eligible': False, 'execution_eligible': False,
                            'outcome_unknown': bool(plan.get('outcome_unknown') or plan.get('status') in {'unknown', 'rollback_unknown'}),
                            'invalidation_reason': 'Build evidence policy changed'}, plan.get('device_id'))
                for action in self.store.list('action_request', limit=None):
                    if action.get('status') == 'queued':
                        self.store.put('action_request', action['request_id'], {**action, 'status': 'superseded',
                            'reason': 'Build evidence policy changed'}, action.get('device_id'))
                for package in self.store.list('package', limit=None):
                    if package.get('cves_fixed'):
                        evidence={**package.get('field_evidence', {})}
                        evidence.pop('cves_fixed', None)
                        self.store.put('package', package['id'], {**package, 'cves_fixed': [], 'field_evidence': evidence,
                            'field_unknown_reasons': {**package.get('field_unknown_reasons', {}),
                                'cves_fixed': 'Build evidence policy changed; reassessment is required'}}, package.get('release_id'))
            self.store.put('status','ruleset',{'version':RULESET_VERSION,'build_evidence_policy':policy,
                'policy_revision':policy_revision,'changed_at':now()})
        self.store.audit('assessment.policy_changed','Current inventories require assessment under the updated ruleset',
                         details={'ruleset_version':RULESET_VERSION,'build_evidence_policy':policy,'devices_pending':len(pending)})
        return pending

    def stop(self):
        self._stop.set();self._wake.set()
        for thread in self._threads:
            thread.join(timeout=self.settings.scan_timeout_seconds+5)
        self.store.close()

    @staticmethod
    def _cadence_time(value):
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
        except (AttributeError, TypeError, ValueError):
            return None

    def _run_cadence(self, key, interval, callback, timestamp, *, asynchronous=False, last_success_at=None, urgent=False):
        """Persist deadlines, and reconcile durable jobs without changing worker behavior.

        Only a completed job advances the regular cadence. Failures retry in one
        minute, including across restarts; active jobs retain their original ID.
        """
        def iso(value):
            return value.isoformat().replace('+00:00', 'Z')

        with self.store.lock:
            previous = self.store.get('scheduler_cadence', key)
            record = dict(previous or {'id': key, 'status': 'due', 'next_due_at': iso(timestamp)})
            operation_id = record.get('operation_id')
            if operation_id:
                operation = self.store.operation(operation_id)
                if operation and operation['status'] in ('queued', 'in_progress'):
                    record['status'] = operation['status']
                    if record != previous:
                        self.store.put('scheduler_cadence', key, record)
                    return record
                finished = self._cadence_time((operation or {}).get('completed_at')) or timestamp
                finished = min(finished, timestamp)
                result = (operation or {}).get('result') or {}
                failed = (not operation or operation['status'] != 'completed' or
                          (isinstance(result, dict) and (result.get('status') == 'failed' or result.get('accepted') is False)))
                record.update(operation_id=None, last_operation_id=operation_id,
                              status='failed' if failed else 'completed',
                              next_due_at=iso(finished + timedelta(seconds=60 if failed else interval)))
                if failed:
                    record.update(last_failure_at=iso(finished),
                                  last_error=(operation or {}).get('error_message') or 'Scheduled operation did not succeed')
                else:
                    record.update(last_success_at=iso(finished), last_error=None)

            # Migration also honors successful work triggered outside the scheduler.
            observed = self._cadence_time(last_success_at)
            saved = self._cadence_time(record.get('last_success_at'))
            if observed and observed <= timestamp and (saved is None or observed > saved):
                record.update(last_success_at=iso(observed), status='completed', last_error=None,
                              next_due_at=iso(observed + timedelta(seconds=interval)))
            if record.get('status') == 'completed':
                saved = self._cadence_time(record.get('last_success_at'))
                if saved:
                    record['next_due_at'] = iso(saved + timedelta(seconds=interval))
            record['interval_seconds'] = interval
            due = self._cadence_time(record.get('next_due_at')) or timestamp
            # A missing/invalid local advisory DB needs repair even if its last
            # refresh was recent. A failed repair still respects the retry delay.
            if urgent and record['status'] == 'completed':
                due = timestamp
                record['next_due_at'] = iso(timestamp)
            if timestamp >= due:
                record['last_attempt_at'] = iso(timestamp)
                try:
                    result = callback()
                    if asynchronous:
                        record.update(status=result['status'], operation_id=result['id'])
                    else:
                        record.update(status='completed', last_success_at=iso(timestamp), last_error=None,
                                      next_due_at=iso(timestamp + timedelta(seconds=interval)))
                except Exception as exc:
                    record.update(status='failed', last_failure_at=iso(timestamp), last_error=str(exc)[:1000],
                                  next_due_at=iso(timestamp + timedelta(seconds=60)))
                    self.store.audit('scheduler.failed', str(exc)[:1000], details={'cadence': key}, severity='error')
            if record != previous:
                self.store.put('scheduler_cadence', key, record)
            return record

    def _run_scheduled_tasks(self, timestamp=None):
        """One clock-controlled periodic tick; never backfill unobserved history."""
        from app.analytics import capture_snapshot
        timestamp = timestamp or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            raise ValueError('Scheduler timestamp must include a timezone')
        timestamp = timestamp.astimezone(timezone.utc)
        self._run_cadence('advisory', 86400,
            lambda: self.enqueue('advisory_update', {}, 'advisory-update'), timestamp, asynchronous=True,
            last_success_at=(self.store.get('status', 'advisory') or {}).get('updated_at'),
            urgent=self.scanner_info.get('status') == 'unavailable')
        releases = sorted(self.store.list('release'),
                          key=lambda release: (not bool(release.get('primary')), release['release_id']))
        for release in releases:
            if release.get('sbom_source') or release.get('artifact_id'):
                ident = release['release_id']
                self._run_cadence('release:' + ident, 86400,
                    lambda ident=ident: self.enqueue('release_sync', {'release_id': ident}, 'release:' + ident),
                    timestamp, asynchronous=True,
                    last_success_at=release.get('last_synced_at') if release.get('status') in ('analyzed', 'partial') else None)
        interval = self.configuration()['scan_interval_seconds']
        for device in self.store.device_summaries():
            self._run_cadence('scan:' + device['id'], interval,
                lambda ident=device['id']: self.schedule_scan(ident), timestamp, asynchronous=True,
                last_success_at=device.get('last_scan_at'))
        self._run_cadence('snapshot', 3600,
            lambda: capture_snapshot(self.store, observed_at=timestamp.isoformat()), timestamp)
        self._run_cadence('retention', 86400,
            lambda: self.store.retention(self.settings.retention_days, self.state_dir), timestamp)

    def _scheduler(self):
        from app.services.release_service import advance_retry_schedule
        from app.services.analysis_lifecycle import advance_analysis_backlog
        from app.services.request_lifecycle import reconcile_assessment_requests
        try:
            self.scanner_info = self.pipeline.scanner.status()
        except Exception as exc:
            self.store.audit('scheduler.failed', str(exc)[:1000], details={'cadence': 'scanner_status'}, severity='error')
        while not self._stop.is_set():
            try:
                self.recover_pending_scans()
                self._run_scheduled_tasks()
                advance_retry_schedule(self)
                advance_analysis_backlog(self)
                reconcile_assessment_requests(self)
                self.reconcile_remediation_batches()
                self.observations.evaluate_alerts(self.store,self.configuration(),self.observability_snapshot())
            except Exception as exc:
                self.store.audit('scheduler.failed', str(exc)[:1000], severity='error')
            self._stop.wait(10)

    def enqueue(self, operation_type, arguments, dedup_key=None):
        result = self.store.enqueue(operation_type,arguments,dedup_key)
        self._wake.set()
        return result

    def observability_snapshot(self):
        health=self.pipeline.ai.health()
        health['configured']=bool(health.get('configured') and self.configuration()['ai_enabled'])
        return self.observations.snapshot(self.store.operation_counts().get('queued',0),health)

    @staticmethod
    def _scan_queue_key(device, configuration, *, db_revision, advisory_generation,
                        investigate=False, finding_ids=None):
        # Collected-at/fact-ID changes alone do not create fresh work. All
        # semantic evidence, inventory, build, review and policy changes do.
        facts = [{key:value for key,value in fact.items() if key not in ('collected_at','fact_id')}
                 for fact in assessment_facts(device.get('facts', []))]
        identity = {key:device.get(key) for key in ('epoch','build_id','artifact_id','artifact_verified',
            'binding_revision','review_revision','baseline_digest','manifest','bound_manifest')}
        return stable_hash([device['id'],device['inventory_digest'],identity,facts,db_revision,
                            advisory_generation,RULESET_VERSION,
                            configuration.get('build_evidence_policy', 'required'),
                            configuration.get('assessment_policy_revision'),
                            'investigate' if investigate else 'scan',sorted(finding_ids or [])])

    def bind_running_scan_context(self, operation, device, configuration, db_revision, advisory_generation):
        """Bind deduplication to the worker's captured inputs, never newer state."""
        finding_ids = operation['arguments'].get('finding_ids')
        investigate = operation['operation_type'] == 'investigate'
        key = self._scan_queue_key(device, configuration, db_revision=db_revision,
            advisory_generation=advisory_generation, investigate=investigate, finding_ids=finding_ids)
        arguments = {**operation['arguments'], 'inventory_digest': device['inventory_digest'],
                     'inventory_epoch': device['epoch'], 'required_db_revision': db_revision,
                     'advisory_generation': advisory_generation}
        self.store.bind_scan_operation(operation['id'], key, arguments,
                                       coalesce=not investigate and not finding_ids)

    def schedule_scan(self, device_id, investigate=False, finding_ids=None, *, reassessment_requests=()):
        with self.store.lock:
            device = self.store.device(device_id)
            if not device:
                raise KeyError('Device not found')
            configuration = self.configuration()
            key = self._scan_queue_key(device, configuration, db_revision=self.scanner_info.get('db_revision'),
                advisory_generation=self.advisory_generation, investigate=investigate, finding_ids=finding_ids)
            arguments={'device_id':device_id,'required_db_revision':self.scanner_info.get('db_revision'),
                       'advisory_generation':self.advisory_generation,
                       'inventory_digest':device['inventory_digest'],'inventory_epoch':device['epoch']}
            if finding_ids:arguments['finding_ids']=sorted(set(finding_ids))[:100]
            operation=self.store.enqueue('investigate' if investigate else 'scan',arguments,key,
                reassessment_requests=reassessment_requests,coalesce_scan=not investigate and not finding_ids)
            self._wake.set()
            if operation['status'] in ('queued','in_progress'):
                updates={'scan_status':'running' if operation['status']=='in_progress' else 'queued'}
                # A progress report may request proof, but cannot rewrite the
                # inventory's assessment identity while making that request.
                if not reassessment_requests:
                    updates.update(assessment_build_evidence_policy=configuration.get('build_evidence_policy', 'required'),
                                   assessment_policy_revision=configuration.get('assessment_policy_revision'))
                self.store.update_device(device_id,updates)
        return operation

    def recover_pending_scans(self):
        operations = [self.schedule_scan(ident) for ident in self.store.pending_scan_devices()]
        # Reports and their execution timestamps are durable even when an API
        # process stops before enqueueing or before fresh inventory arrives.
        self.reconcile_maintenance()
        return operations

    def reconcile_maintenance(self, device_id=None):
        result = self.store.reconcile_maintenance_plans(device_id)
        # Both CLI and centrally approved plans defer until their exact target
        # inventory is present. Persist one attempt per execution/context in the
        # queue transaction; replay/restarts do not trigger unbounded retries.
        with self.store.lock:
            for ident in result['needs_scan']:
                self.schedule_scan(ident, reassessment_requests=[request for request in result['scan_requests']
                    if request['device_id'] == ident])
        self.reconcile_remediation_batches()
        return result

    def recover_superseded_scan(self, device_id):
        from app.db.store import Device
        from app.services.maintenance_reassessment import current_scan_complete
        with self.store.lock:
            with self.store.sessions() as session:
                device = session.get(Device, device_id)
                if not device:
                    return None
                if (current_scan_complete(session, device)
                        and (not self.scanner_info.get('db_revision') or self.scanner_info['db_revision'] ==
                             device.payload.get('scanner', {}).get('db_revision'))):
                    return None
            return self.schedule_scan(device_id)

    def reconcile_remediation_batches(self):
        from app.services.remediation_batches import reconcile_batches
        return reconcile_batches(self)

    def _worker(self):
        while not self._stop.is_set():
            operation = self.store.claim()
            if operation is None:
                self._wake.wait(1);self._wake.clear();continue
            ident = operation['id']
            self.store.operation_log(ident,'Started '+operation['operation_type'])
            try:
                handler = getattr(self,'_job_'+operation['operation_type'],None)
                if handler is None:
                    raise ValueError('Unsupported operation type')
                result = handler(operation)
                self.store.update_operation(ident,'completed',result=result)
                self.store.operation_log(ident,'Completed')
                self.reconcile_remediation_batches()
                if isinstance(result,dict) and result.get('accepted') is False and result.get('device_id'):
                    self.recover_superseded_scan(result['device_id'])
            except Exception as exc:
                message = str(exc)[:2000]
                self.store.update_operation(ident,'failed',error_message=message)
                self.store.operation_log(ident,'Failed: '+message)
                device_id = operation['arguments'].get('device_id')
                if device_id:
                    self.store.update_device(device_id,{'scan_status':'failed','last_error':message})
                    self.store.reconcile_maintenance_plans(device_id)
                    self.reconcile_remediation_batches()
                self.store.audit('operation.failed',message,device_id,{'operation_id':ident},'error')

    @staticmethod
    def to_inventory(device):
        scopes = {}
        for raw in device.get('components',[]):
            component = copy.deepcopy(raw)
            scope_id = component['scope']
            distro = component.get('distro') or {}
            if isinstance(distro,str):
                name,_,version = distro.partition(':');distro={'name':name,'version':version}
            distro = {'name':distro.get('name',distro.get('id','')),
                      'version':distro.get('version',distro.get('version_id',''))}
            # Distribution feeds use Debian major releases, not minor point-release names.
            if distro['name']=='debian':
                distro['version']=distro['version'].split('.')[0]
            scope=scopes.setdefault(scope_id,{'id':scope_id,'kind':'host' if scope_id=='host' else 'container',
                    'distro':distro,'components':[],'image_digest':component.get('image_digest','')})
            component['id']=component['component_id']
            component['arch']=component.get('architecture','')
            component['ecosystem']=component.get('ecosystem','deb')
            scope['components'].append(component)
        return {'build_id':device.get('build_id') or device.get('sonic_version'),
                'artifact_id':device.get('build_id') or device.get('sonic_version'), 'scopes':list(scopes.values())}

    def _source_revision(self, device):
        revision=(device.get('bound_manifest') or {}).get('source_revision','') if device.get('artifact_verified') else ''
        candidate = re.search(r'-([0-9a-f]{7,40})$',device.get('sonic_version',''))
        if re.fullmatch(r'[0-9a-f]{40}',revision):candidate=re.match(r'([0-9a-f]{40})',revision)
        if not candidate:
            return ''
        for root in self.configuration()['source_roots']:
            result = subprocess.run(['git','-C',root,'rev-parse','--verify',candidate.group(1)+'^{commit}'],
                                    capture_output=True,text=True,timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        return ''

    def bound_inventory(self,device):
        observed=self.to_inventory(device)
        if not device.get('artifact_verified'):return observed
        artifact=self.store.get('artifact',device.get('artifact_id',''))
        if not artifact:
            for scope in observed['scopes']:
                for component in scope['components']:component['custom_build']=True
            return observed
        from app.services.baseline import bind_inventory
        baseline=SBOMParser().to_inventory(artifact['sbom'],device.get('build_id'))
        return bind_inventory(observed,baseline,device.get('bound_manifest',{}),artifact['id'])

    def _job_scan(self, operation):
        from app.services.scan_progress import ScanProgress
        from app.services.scanner import assessment_cache_context, ScanError
        device = self.store.device(operation['arguments']['device_id'])
        if not device:
            raise ValueError('Device no longer exists')
        digest=device['inventory_digest'];ident=operation['id']
        generation=self.advisory_generation
        self.store.update_device(device['id'],{'scan_status':'running'})
        progress=ScanProgress(self.store,ident)
        progress.emit({'phase':'preparing','detail':'Preparing current inventory and scanner context'})
        status=self.pipeline.scanner.status();self.scanner_info=status
        matching_identity, matching_reusable = assessment_cache_context(self.pipeline.scanner, status)
        if status.get('status') != 'ready' or not status.get('db_revision'):
            raise ScanError('Central scanner database is unavailable; cached assessments cannot establish current coverage')
        from app.services.analysis_lifecycle import analysis_identity, restore_completed_progress
        expected_analysis=analysis_identity(self,'device',device['id'])
        relevant_facts=applicability_facts(device.get('facts',[]))
        context={'runtime_facts':assessment_facts(device.get('facts',[])),'inventory_digest':digest,'device_id':device['id'],
                 'context_hash':stable_hash(relevant_facts),
                 'source_revision':self._source_revision(device),'artifact_verified':bool(device.get('artifact_verified'))}
        # A plain function remains deepcopy-compatible for extension pipelines.
        context['_progress']=lambda event: progress.emit(event)
        identity={'epoch':device['epoch'],'build_id':device.get('build_id'),
                  'review_revision':device.get('review_revision'),
                  'artifact_id':device.get('artifact_id'),'artifact_verified':bool(device.get('artifact_verified')),
                  'binding_revision':device.get('binding_revision','unverified'),
                  'baseline_digest':device.get('baseline_digest'),'manifest_digest':stable_hash(device.get('manifest',{})),
                  'facts_digest':stable_hash(assessment_facts(device.get('facts',[])))}
        context_key=assessment_facts(context['runtime_facts'])
        configuration=self.configuration()
        self.bind_running_scan_context(operation,device,configuration,status.get('db_revision'),generation)
        context['build_evidence_policy']=configuration.get('build_evidence_policy', 'required')
        key=stable_hash([digest,device.get('build_id'),device.get('baseline_digest'),identity['manifest_digest'],device.get('artifact_id'),
                         context['artifact_verified'],matching_identity,context_key,context['source_revision'],
                         RULESET_VERSION,self.store.list('reviewed_assessment'),
                         configuration.get('build_evidence_policy', 'required'),configuration.get('assessment_policy_revision'),
                         {k:configuration.get(k) for k in ('ai_enabled','ai_provider','ai_model','ai_api_url','ai_max_calls')}])
        if operation['arguments'].get('finding_ids'):
            context['finding_ids']=operation['arguments']['finding_ids']
            key=stable_hash([key,context['finding_ids']])
        cached=self.store.get('cache',key)
        facts_current=all(age_seconds(f.get('collected_at')) < min(int(f.get('ttl_seconds',300)),3600)
                          for f in context['runtime_facts'] if f.get('name')=='exposure')
        inventory=self.bound_inventory(device)
        _,collection_errors=inventory_coverage(context,inventory['scopes'])
        facts_current=facts_current and not collection_errors
        reuse_assessment = bool(cached and matching_reusable and facts_current
            and result_cache_fresh(cached['result'],context)
            and age_seconds(cached['created_at']) < self.settings.cache_ttl_hours*3600
            and operation['operation_type']!='investigate')
        if reuse_assessment:
            result=restore_completed_progress(self,'device',device['id'],cached['result']);self.metrics['cache_hits']+=1
            self.store.operation_log(ident,'Reused matching inventory, advisory and context assessment')
            coverage=result.setdefault('coverage',{})
            covered=coverage.get('components_scanned',coverage.get('components_total',0))
            coverage.update(components_matched=0,components_reused=covered,components_removed=0)
            result.setdefault('scanner',{}).update(scan_mode='assessment_cached',assessment_cache_hit=True,cache_hits=0)
            # Scope work in the cached object describes its original scan, not
            # this operation. Retain logical coverage without claiming that work.
            result['scanner'].pop('scope_work',None)
            progress.emit({'phase':'cached','detail':'Reused a current complete assessment; no new package matching',
                           'scopes_total':len(inventory['scopes']),'scopes_completed':len(inventory['scopes']),
                           'packages_total':coverage.get('components_total',covered),'packages_matched':0,
                           'packages_reused':covered,'packages_removed':0,'findings_total':len(result.get('findings',[])),
                           'findings_completed':len(result.get('findings',[])),'scan_mode':'assessment_cached'})
        else:
            self.metrics['cache_misses']+=1
            self.store.operation_log(ident,f"Central scan: {device.get('scopes_count')} scopes, {device.get('components_count')} components")
            from app.services.analysis_lifecycle import lifecycle_callback
            context['_analysis_lifecycle']=lifecycle_callback(self,operation,'device',device['id'])
            result=self.pipeline.analyze(inventory,context)
            progress.emit({'phase':'saving','detail':'Saving assessment cache','saving_step':0,'force':True})
        # Outer-cache hits and fresh matching both need the same final identity
        # check. Otherwise the outer cache could bypass scope-cache safeguards.
        after_status=self.pipeline.scanner.status()
        after_matching, after_reusable=assessment_cache_context(self.pipeline.scanner, after_status)
        if after_matching != matching_identity or after_status.get('status') != 'ready':
            raise ScanError('Scanner, advisory database or configuration changed during assessment; retry current inputs')
        if (not reuse_assessment and matching_reusable and after_reusable and result.get('coverage',{}).get('complete')
                and not result.get('errors') and result.get('scanner',{}).get('db_revision') == status.get('db_revision')):
            self.store.put('cache',key,{'created_at':now(),'result':result})
        progress.emit({'phase':'saving','detail':'Saving current findings','saving_step':1,'force':True})
        result['source_revision']=context.get('source_revision')
        if inventory.get('provenance_coverage'):
            result['coverage']['provenance']=inventory['provenance_coverage']
        revision=str(uuid.uuid4())
        with self.store.lock:
            accepted=(generation==self.advisory_generation
                      and analysis_identity(self,'device',device['id'])==expected_analysis
                      and (not self.scanner_info.get('db_revision') or self.scanner_info['db_revision']==result.get('scanner',{}).get('db_revision'))
                      and self.store.store_findings(device['id'],digest,result,revision,expected_identity=identity))
        progress.emit({'phase':'saving','detail':'Finalizing accepted assessment' if accepted else 'Inventory changed; result superseded',
                       'saving_step':2,'force':True})
        if accepted:self.queue_evidence_requests(device['id'],result.get('evidence_requests',[]))
        if accepted:
            from app.services.analysis_lifecycle import seed_backlog
            seed_backlog(self,'device',device['id'],
                expected_identity={**expected_analysis,'advisory_revision':result.get('scanner',{}).get('db_revision')},
                assessment_revision=revision)
            self.schedule_analysis_retry(device, result, identity)
        self.metrics['scans_completed']+=1
        for name,value in result.get('ai_usage',{}).items():
            if isinstance(value,(int,float)):
                self.metrics['ai_'+name]+=value
        if generation==self.advisory_generation:self.scanner_info=result.get('scanner',status)
        self.store.audit('assessment.completed' if accepted else 'assessment.superseded',
            f"Assessed {len(result.get('findings',[]))} findings; coverage {'complete' if result.get('coverage',{}).get('complete') else 'partial'}",
            device['id'],{'operation_id':ident,'assessment_revision':revision,'coverage':result.get('coverage',{})})
        progress.emit({'phase':'saving','detail':'Assessment saved' if accepted else 'Superseded result recorded',
                       'saving_step':3,'force':True})
        return {'device_id':device['id'],'assessment_revision':revision,'accepted':accepted,
                'findings_count':len(result.get('findings',[])),'coverage':result.get('coverage',{}),
                'scanner':result.get('scanner',{}),'ai_usage':result.get('ai_usage',{}),'errors':result.get('errors',[])}

    _job_investigate = _job_scan

    def _job_plan_validate(self,operation):
        from app.services.maintenance_jobs import validate_plan_target
        return validate_plan_target(self,operation)

    def _job_advisory_update(self, operation):
        config=self.configuration();env={**os.environ,**config['scanner_env']}
        result=subprocess.run([config['scanner_binary'],'db','update'],env=env,capture_output=True,text=True,timeout=600)
        if result.returncode:
            raise RuntimeError('Advisory update failed: '+result.stderr[-1500:])
        self.scanner_info=self.pipeline.scanner.status()
        self.advisory_generation+=1
        self.store.put('status','advisory',{'updated_at':now(),'generation':self.advisory_generation,**self.scanner_info})
        jobs=[self.schedule_scan(d['id'])['id'] for d in self.store.devices()]
        self.store.audit('advisory.updated','Advisory database updated; current inventories queued',details={'jobs':jobs})
        return {'scanner':self.scanner_info,'scan_jobs':jobs}

    def _job_release_sync(self, operation):
        from app.services.release_service import sync_release
        return sync_release(self, operation)

    def _job_source_clone(self, operation):
        from app.services.release_service import clone_source
        return clone_source(self, operation)

    def schedule_analysis_retry(self, device, result, identity):
        from app.services.release_service import schedule_analysis_retry
        return schedule_analysis_retry(self, device, result, identity)

    def _job_analysis_backlog(self, operation):
        from app.services.analysis_lifecycle import run_analysis_backlog
        return run_analysis_backlog(self, operation)

    def _job_retry_analysis(self, operation):
        from app.services.release_service import retry_analysis
        result=retry_analysis(self, operation)
        if result.get('accepted') and result.get('device_id'):
            self.queue_evidence_requests(result['device_id'],result.get('evidence_requests',[]))
        return result

    def queue_evidence_requests(self,device_id,requests):
        device=self.store.device(device_id)
        if not device:return []
        allowed_scopes={'host'} | {c['scope'] for c in device.get('components',[])}
        allowed_collectors={'services','listeners','features','interfaces','routing','resources','inventory','processes','kernel','bgp','package_versions'}
        queued=[]
        for request in requests[:16]:
            if (request.get('collector') not in allowed_collectors or request.get('scope') not in allowed_scopes
                    or request.get('inventory_digest')!=device['inventory_digest']):continue
            ident=request.get('request_id') or stable_hash([device_id,device['inventory_digest'],request['scope'],request['collector']])
            # AI-provided IDs are namespaced to the authenticated device by the server.
            ident=stable_hash([device_id,ident])
            existing=self.store.get('evidence_request',ident)
            if existing and existing.get('status')=='queued':
                queued.append(existing);continue
            item={**request,'request_id':ident,'id':ident,'device_id':device_id,'status':'queued','created_at':now()}
            self.store.put('evidence_request',ident,item,device_id);queued.append(item)
            self.store.audit('evidence.requested','Named runtime observation requested',device_id,
                             {'request_id':ident,'collector':request['collector'],'scope':request['scope']})
        return queued

    def overview(self):
        devices=self.store.device_summaries()
        counts=self.store.finding_counts()
        apps=Counter(counts['applicability']);severity=counts['severity']
        jobs=self.store.operation_counts()
        complete=sum(1 for d in devices if (d.get('coverage') or {}).get('complete'))
        summary={'devices_total':len(devices),'devices_online':sum(age_seconds(d['last_seen'])<=self.settings.online_threshold_seconds for d in devices),
            'findings_total':counts['total'],
            'findings_affected':apps['affected'],'findings_exposed':counts['exposed'],
            'findings_unknown':apps['under_investigation'],'findings_fixed':apps['fixed'],'findings_not_affected':apps['not_affected'],
            'coverage_pct':round(complete/len(devices)*100,1) if devices else 0,
            'scans_running':jobs.get('in_progress',0),'queue_depth':jobs.get('queued',0),
            'last_advisory_update':(self.store.get('status','advisory') or {}).get('updated_at') or self.scanner_info.get('db_built_at')}
        config=self.configuration(public=True)
        return {'summary':summary,'severity_counts':dict(severity),'applicability_counts':dict(apps),
            'recent_events':self.store.list('event',limit=20),'scanner':self.scanner_info,
            'ai':{'enabled':config['ai_enabled'],'provider':config['ai_provider'],'model':config['ai_model'],
                  'requests':self.metrics['ai_calls'],'tokens':self.metrics['ai_input_tokens']+self.metrics['ai_output_tokens']},
            'resources':{'uptime_seconds':round(time.monotonic()-self.started),'cache_hits':self.metrics['cache_hits'],
                         'cache_misses':self.metrics['cache_misses'],'scans_completed':self.metrics['scans_completed']}}
