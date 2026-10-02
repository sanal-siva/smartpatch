"""Background release analysis, pinned source preparation and bounded AI retries."""
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.db.store import now, stable_hash
from .github_sync import GitHubSync
from .sbom_parser import SBOMParser
from .repository_catalog import RepositoryCatalog
from .applicability_context import applicability_facts, assessment_facts
from .package_metadata import package_fields
from .release_history import commit_release_assessment, release_assessment_identity


def sync_release(runtime, operation):
    from .analysis_lifecycle import analysis_identity, lifecycle_callback, seed_backlog
    release_id = operation['arguments']['release_id']
    release = runtime.store.get('release', release_id)
    if not release:
        raise ValueError('Unknown release')
    expected_identity = release_assessment_identity(release)
    expected_analysis = analysis_identity(runtime,'release',release_id)
    generation = runtime.advisory_generation
    runtime.store.operation_log(operation['id'], 'Validating release SBOM and reconstructing scoped inventory')
    parser = SBOMParser()
    existing = None
    if release.get('sbom_source'):
        document = parser.load_sbom(release['sbom_source'])
    else:
        existing = runtime.store.get('artifact', release.get('artifact_id', ''))
        if not existing or not existing.get('sbom'):
            raise ValueError('Release needs a validated SBOM upload or configured artifact source')
        document = parser.load_sbom(existing['sbom'])
    artifact_id = stable_hash(document)
    raw_digest = parser.source_sha256 or (existing or {}).get('source_sha256')
    previous_artifact = runtime.store.get('artifact', artifact_id) or {}
    same_source = bool(raw_digest and previous_artifact.get('source_sha256') == raw_digest)
    source_changed = bool(previous_artifact.get('source_sha256') and raw_digest and not same_source)
    packages = parser.parse_packages(document)
    repository_result = RepositoryCatalog(runtime.state_dir / 'repository-catalog').lookup(release.get('repositories', []), packages)
    availability = {package['component_id']: package for package in repository_result['packages']}
    for proof in repository_result['evidence']:
        runtime.store.put('evidence', proof['id'], proof)
    inventory = parser.to_inventory(document, release_id)
    inventory['artifact_id'] = artifact_id
    runtime.store.put('artifact', artifact_id, {**(previous_artifact if same_source else {}),
        'id': artifact_id, 'sbom': document, 'release_id': release_id, 'source_sha256': raw_digest,
        'source': release.get('sbom_source') or 'operator_upload', 'digest': 'sha256:' + artifact_id,
        'imported_at': now(), 'verification': previous_artifact.get('verification', 'unverified') if same_source else 'unverified'}, release_id)
    if source_changed:
        for binding in runtime.store.list('build_binding'):
            if binding.get('artifact_id') == artifact_id and binding.get('verification') == 'signature_verified':
                runtime.store.put('build_binding', binding['build_id'], {**binding, 'verification': 'source_changed',
                    'invalidated_at': now(), 'reason': 'Exact SBOM source bytes changed; signature binding must be verified again'})
                for device in runtime.store.devices():
                    if device.get('build_id') == binding['build_id']:
                        runtime.store.update_device(device['id'], {'artifact_verified': False, 'artifact_binding': 'source_changed'})
                        runtime.schedule_scan(device['id'])
        runtime.store.audit('artifact.source_changed', 'Canonical SBOM content was reimported with different source bytes; old binding invalidated',
                            details={'artifact_id': artifact_id, 'previous_sha256': previous_artifact['source_sha256'], 'source_sha256': raw_digest})
    runtime.store.update_operation(operation['id'], progress_percentage=25)
    package_records = []
    for package in packages:
        ident = stable_hash([release_id, artifact_id, package['id']])
        metadata = {**package, 'metadata_type_source':'cyclonedx.type' if document.get('bomFormat')=='CycloneDX' else None}
        package_records.append({**metadata, **package_fields(metadata), 'id': ident, 'component_id': package['id'],
            'release_id': release_id, 'artifact_id': artifact_id, 'status': 'current', 'created_at': now(),
            'repository_availability': availability.get(package['id'], {'status': 'unknown'}),
            'latest_available_version': availability.get(package['id'], {}).get('latest_available_version')})
    runtime.store.operation_log(operation['id'], f'Central release scan: {len(inventory["scopes"])} scopes, {len(packages)} component records')
    result = runtime.pipeline.analyze(inventory, {'artifact_verified': False, 'artifact_id':artifact_id,
        'source_revision': release.get('resolved_commit') or release.get('source_revision') or '', 'runtime_facts': [],
        '_analysis_lifecycle':lifecycle_callback(runtime,operation,'release',release_id,{**expected_analysis,'artifact_id':artifact_id})})
    runtime.store.update_operation(operation['id'], progress_percentage=85)
    count = len(result.get('findings',[]))
    release_status = 'analyzed' if result.get('coverage', {}).get('complete') else 'partial'
    if not result.get('coverage', {}).get('scopes_scanned'):
        release_status = 'failed'
    revision = stable_hash([operation['id'],artifact_id,now()])
    updates = {'last_synced_at': now(), 'packages_count': len(packages),
        'artifact_id': artifact_id, 'status': release_status, 'findings_count': count,
        'coverage': result.get('coverage', {}), 'scanner': result.get('scanner', {}),
        'errors': result.get('errors', []), 'ai_usage': result.get('ai_usage', {}),
        'repository_coverage': repository_result['coverage'], 'repository_errors': repository_result['errors'],
        'new_repository_packages': [e for e in repository_result['evidence'] if e.get('new_packages_count')]}
    accepted = commit_release_assessment(runtime.store,release_id,result,revision,expected_identity=expected_identity,
        artifact_id=artifact_id,source_revision=release.get('resolved_commit') or release.get('source_revision'),
        package_records=package_records,release_updates=updates,complete_scan=bool(result.get('coverage',{}).get('complete')),
        identity_guard=lambda:generation==runtime.advisory_generation and analysis_identity(runtime,'release',release_id)==expected_analysis)
    if accepted:
        seed_backlog(runtime,'release',release_id,
            expected_identity={**expected_analysis,'artifact_id':artifact_id,
                               'advisory_revision':result.get('scanner',{}).get('db_revision')},
            assessment_revision=revision)
    if not accepted:release_status='superseded'
    runtime.store.audit('release.analyzed' if accepted else 'release.superseded', f'Release {release_id}: {count} candidate findings; {release_status}',
                        details={'release_id': release_id, 'artifact_id': artifact_id, 'coverage': result.get('coverage', {}),
                                 'assessment_revision':revision,'accepted':accepted})
    return {'release_id': release_id, 'artifact_id': artifact_id, 'packages_count': len(packages),
            'findings_count': count, 'status': release_status, 'coverage': result.get('coverage', {}),
            'assessment_revision':revision,'accepted':accepted,
            'scanner': result.get('scanner', {}), 'errors': result.get('errors', []), 'ai_usage': result.get('ai_usage', {}),
            'repository_coverage': repository_result['coverage'], 'repository_errors': repository_result['errors']}


def clone_source(runtime, operation):
    release_id = operation['arguments']['release_id']
    release = runtime.store.get('release', release_id)
    if not release:
        raise ValueError('Unknown release')
    url = release.get('source_url') or 'https://github.com/sonic-net/sonic-buildimage'
    branch = release.get('branch') or 'master'
    commit = release.get('source_revision') or release.get('commit')
    if not commit:
        raise ValueError('Source analysis requires an explicit pinned commit, not a moving branch')
    path = runtime.state_dir / 'sources' / stable_hash([url, branch])[:24]
    runtime.store.operation_log(operation['id'], 'Preparing pinned source repository; existing mirrors are reused')
    runtime.store.update_operation(operation['id'], progress_percentage=10)
    source = GitHubSync(url, str(path))
    if not source.clone_repo(branch, commit):
        raise RuntimeError('Source clone failed: ' + (source.last_error or 'unknown error'))
    runtime.store.update_operation(operation['id'], progress_percentage=90)
    resolved = source.resolved_commit
    updated = runtime.store.get('release', release_id) or release
    runtime.store.put('release', release_id, {**updated, 'source_root': str(path), 'resolved_commit': resolved,
                                             'source_status': 'available', 'source_synced_at': now()})
    # Releases can be configured only by administrators. Register their source roots but
    # do not change the global source revision or claim these sources match a running switch.
    roots = runtime.configuration()['source_roots']
    if str(path) not in roots:
        runtime.save_configuration({'source_roots': [*roots, str(path)]})
    runtime.store.audit('source.ready', 'Pinned release source is available to bounded evidence tools',
                        details={'release_id': release_id, 'root': str(path), 'revision': resolved})
    return {'release_id': release_id, 'source_root': str(path), 'resolved_commit': resolved, 'artifact_verified': False}


def retry_identity(runtime, device):
    config = runtime.configuration()
    return {'epoch': device['epoch'], 'build_id': device.get('build_id'),
            'artifact_id': device.get('artifact_id'), 'artifact_verified': bool(device.get('artifact_verified')),
            'binding_revision': device.get('binding_revision', 'unverified'), 'review_revision': device.get('review_revision'),
            'inventory_digest': device['inventory_digest'], 'baseline_digest': device.get('baseline_digest'),
            'manifest_digest': stable_hash(device.get('manifest', {})), 'facts_digest': stable_hash(assessment_facts(device.get('facts', []))),
            'advisory_revision': device.get('scanner', {}).get('db_revision'),
            'build_evidence_policy': config.get('build_evidence_policy', 'required'),
            'assessment_policy_revision': config.get('assessment_policy_revision'),
            'provider_revision': stable_hash({k: config.get(k) for k in ('ai_enabled', 'ai_provider', 'ai_model', 'ai_api_url')})}


def schedule_analysis_retry(runtime, device, result=None, identity=None):
    if not runtime.configuration().get('ai_enabled'):
        return
    if result is not None and not any(error.get('stage') == 'ai' for error in result.get('errors', [])):
        return
    if result is not None and result.get('findings') and all(f.get('analysis_managed') for f in result['findings']):
        return  # Per-CVE durable backlog owns modern processing and retry limits.
    current = runtime.store.device(device['id'])
    if current is None:
        return
    if identity and any(retry_identity(runtime, current).get(key) != value for key, value in identity.items()):
        return
    device = current
    expected = retry_identity(runtime, device)
    ident = stable_hash([device['id'], expected])
    if runtime.store.get('analysis_retry', ident) is not None:
        return
    record = {'id': ident, 'device_id': device['id'], 'expected_identity': expected, 'attempts': 0,
              'status': 'retry_needed', 'next_attempt_at': (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
              'created_at': now()}
    runtime.store.put('analysis_retry', ident, record, device['id'])
    runtime.store.audit('analysis.retry_needed', 'Transient AI analysis failure scheduled for retry', device['id'],
                        {'retry_id': ident, 'attempt': 0, 'next_attempt_at': record['next_attempt_at']})


def advance_retry_schedule(runtime):
    """Called once per scheduler tick; no network, sleep or scanner work here."""
    if not runtime.configuration().get('ai_enabled'):
        return
    for device in runtime.store.devices():
        findings = [f for f in runtime.store.list('finding', owner=device['id']) if f.get('status') == 'current']
        retryable = [f for f in findings if f.get('assessment_state') == 'retry_needed' and not f.get('analysis_managed')]
        if not retryable:
            continue
        identity = retry_identity(runtime, device)
        ident = stable_hash([device['id'], identity])
        record = runtime.store.get('analysis_retry', ident)
        if record is None:
            schedule_analysis_retry(runtime, device)
            record = runtime.store.get('analysis_retry', ident)
        if record['status'] in {'completed', 'exhausted', 'superseded'}:
            continue
        # A crash can leave a durable retry record in_progress; recover_jobs requeues
        # its operation, so do not create a competing operation.
        if record['status'] in {'queued', 'analyzing'}:
            continue
        if datetime.fromisoformat(record['next_attempt_at'].replace('Z', '+00:00')) > datetime.now(timezone.utc):
            continue
        operation = runtime.enqueue('retry_analysis', {'device_id': device['id'], 'retry_id': ident}, 'retry:' + ident)
        runtime.store.put('analysis_retry', ident, {**record, 'status': 'queued', 'operation_id': operation['id']}, device['id'])
    advance_release_retries(runtime)


def retry_analysis(runtime, operation):
    from .analysis_lifecycle import analysis_identity, lifecycle_callback, seed_backlog
    args = operation['arguments']
    if args.get('release_id'):
        return retry_release_analysis(runtime, operation)
    record = runtime.store.get('analysis_retry', args['retry_id'])
    if not record:
        raise ValueError('Unknown analysis retry')
    device = runtime.store.device(record['device_id'])
    if not device or retry_identity(runtime, device) != record['expected_identity']:
        runtime.store.put('analysis_retry', record['id'], {**record, 'status': 'superseded', 'updated_at': now()}, record['device_id'])
        return {'device_id': record['device_id'], 'retry_state': 'superseded', 'reason': 'Inventory or context changed'}
    if record.get('attempts', 0) >= 5:
        runtime.store.put('analysis_retry', record['id'], {**record, 'status': 'exhausted'}, record['device_id'])
        return {'device_id': record['device_id'], 'retry_state': 'exhausted'}
    expected_analysis=analysis_identity(runtime,'device',device['id'])
    generation=runtime.advisory_generation
    attempt = record.get('attempts', 0) + 1
    record = {**record, 'attempts': attempt, 'status': 'analyzing', 'updated_at': now()}
    runtime.store.put('analysis_retry', record['id'], record, record['device_id'])
    runtime.store.audit('analysis.analyzing', 'Retrying AI evidence analysis', record['device_id'], {'retry_id': record['id'], 'attempt': attempt})
    try:
        findings = [f for f in runtime.store.list('finding', owner=device['id']) if f.get('status') == 'current']
        context = {'runtime_facts': assessment_facts(device.get('facts', [])), 'inventory_digest': device['inventory_digest'],
                   'source_revision': runtime._source_revision(device), 'artifact_verified': bool(device.get('artifact_verified')),
                   'build_id': device.get('build_id'), 'device_id': device['id'],
                   'context_hash': stable_hash(applicability_facts(device.get('facts', []))),
                   '_analysis_lifecycle':lifecycle_callback(runtime,operation,'device',device['id'],expected_analysis)}
        retried = runtime.pipeline.retry_findings(findings, context)
        retried.update(coverage=device.get('coverage', {}), scanner=device.get('scanner', {}))
        expected = {key: record['expected_identity'][key] for key in ('epoch', 'build_id', 'artifact_id', 'artifact_verified',
                    'binding_revision', 'review_revision', 'baseline_digest', 'manifest_digest', 'facts_digest')}
        expected['assessment_revision']=device.get('assessment_revision')
        revision = stable_hash([record['id'], attempt, now()])
        with runtime.store.lock:
            accepted=(generation==runtime.advisory_generation
                and analysis_identity(runtime,'device',device['id'])==expected_analysis
                and runtime.store.store_findings(device['id'],device['inventory_digest'],retried,revision,
                    expected_identity=expected,complete_scan=False,assessment_kind='ai_retry'))
        if accepted:seed_backlog(runtime,'device',device['id'],expected_identity=expected_analysis,assessment_revision=revision)
        result = {'device_id': device['id'], 'accepted': accepted, 'coverage': retried['coverage'],
                  'errors': retried['errors'], 'ai_usage': retried['ai_usage'], 'assessment_revision': revision,
                  'evidence_requests': retried.get('evidence_requests', [])}
        if result.get('accepted') is False:
            status = 'superseded'
        elif any(error.get('stage') == 'ai' for error in result.get('errors', [])):
            status = 'exhausted' if attempt >= 5 else 'retry_needed'
        elif not result.get('coverage', {}).get('complete'):
            status = 'exhausted' if attempt >= 5 else 'retry_needed'
        else:
            status = 'completed'
        error = None
    except Exception as exc:
        status = 'exhausted' if attempt >= 5 else 'retry_needed'
        error = str(exc)[:500]
        result = {'device_id': record['device_id'], 'errors': [{'stage': 'retry', 'message': error}]}
    delay = min(30 * (2 ** attempt), 900)
    runtime.store.put('analysis_retry', record['id'], {**record, 'status': status, 'last_error': error,
        'next_attempt_at': (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(), 'updated_at': now()}, record['device_id'])
    runtime.store.audit('analysis.' + status, 'AI retry attempt finished', record['device_id'],
                        {'retry_id': record['id'], 'attempt': attempt, 'state': status})
    return {**result, 'retry_state': status, 'retry_attempt': attempt}


def release_retry_identity(runtime, release):
    config = runtime.configuration()
    return {'artifact_id': release.get('artifact_id'), 'source_revision': release.get('resolved_commit') or release.get('source_revision'),
            'advisory_revision': release.get('scanner', {}).get('db_revision'),
            'build_evidence_policy': config.get('build_evidence_policy', 'required'),
            'assessment_policy_revision': config.get('assessment_policy_revision'),
            'provider_revision': stable_hash({key: config.get(key) for key in ('ai_enabled', 'ai_provider', 'ai_model', 'ai_api_url')})}


def advance_release_retries(runtime):
    for release in runtime.store.list('release'):
        retryable = [f for f in runtime.store.list('release_finding', owner=release['release_id'])
                     if f.get('status') == 'current' and f.get('assessment_state') == 'retry_needed' and not f.get('analysis_managed')]
        if not retryable:
            continue
        expected = release_retry_identity(runtime, release)
        ident = stable_hash([release['release_id'], expected])
        record = runtime.store.get('release_analysis_retry', ident)
        if record is None:
            record = {'id': ident, 'release_id': release['release_id'], 'expected_identity': expected, 'attempts': 0,
                      'status': 'retry_needed', 'next_attempt_at': (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()}
            runtime.store.put('release_analysis_retry', ident, record, release['release_id'])
            runtime.store.audit('analysis.retry_needed', 'Release AI analysis queued for retry', details={'release_id': release['release_id'], 'retry_id': ident})
        if record['status'] != 'retry_needed' or datetime.fromisoformat(record['next_attempt_at']) > datetime.now(timezone.utc):
            continue
        operation = runtime.enqueue('retry_analysis', {'release_id': release['release_id'], 'retry_id': ident}, 'retry-release:' + ident)
        runtime.store.put('release_analysis_retry', ident, {**record, 'status': 'queued', 'operation_id': operation['id']}, release['release_id'])


def retry_release_analysis(runtime, operation):
    from .analysis_lifecycle import analysis_identity, lifecycle_callback, seed_backlog
    args = operation['arguments']
    record = runtime.store.get('release_analysis_retry', args['retry_id'])
    if not record:
        raise ValueError('Unknown release analysis retry')
    release = runtime.store.get('release', record['release_id'])
    if not release or release_retry_identity(runtime, release) != record['expected_identity']:
        runtime.store.put('release_analysis_retry', record['id'], {**record, 'status': 'superseded'}, record['release_id'])
        return {'release_id': record['release_id'], 'retry_state': 'superseded'}
    if record.get('attempts', 0) >= 5:
        return {'release_id': record['release_id'], 'retry_state': 'exhausted'}
    expected_assessment = release_assessment_identity(release)
    expected_analysis = analysis_identity(runtime,'release',release['release_id'])
    generation = runtime.advisory_generation
    attempt = record.get('attempts', 0) + 1
    runtime.store.put('release_analysis_retry', record['id'], {**record, 'attempts': attempt, 'status': 'analyzing'}, record['release_id'])
    runtime.store.audit('analysis.analyzing', 'Retrying release AI analysis', details={'release_id': record['release_id'], 'retry_id': record['id'], 'attempt': attempt})
    try:
        findings = [f for f in runtime.store.list('release_finding', owner=release['release_id']) if f.get('status') == 'current']
        result = runtime.pipeline.retry_findings(findings, {'artifact_id': release['artifact_id'], 'artifact_verified': False,
                    'runtime_facts': [], 'source_revision': release.get('resolved_commit') or release.get('source_revision'),
                    '_analysis_lifecycle':lifecycle_callback(runtime,operation,'release',release['release_id'],expected_analysis)})
        result.setdefault('scanner',release.get('scanner',{}))
        latest = runtime.store.get('release', release['release_id'])
        if not latest or release_retry_identity(runtime, latest) != record['expected_identity']:
            status = 'superseded'
        else:
            revision = stable_hash([operation['id'],record['id'],attempt,now()])
            accepted = commit_release_assessment(runtime.store,release['release_id'],result,revision,
                expected_identity=expected_assessment,artifact_id=release['artifact_id'],
                source_revision=release.get('resolved_commit') or release.get('source_revision'),assessment_kind='ai_retry',
                identity_guard=lambda:generation==runtime.advisory_generation and analysis_identity(runtime,'release',release['release_id'])==expected_analysis)
            if accepted:seed_backlog(runtime,'release',release['release_id'],expected_identity=expected_analysis,assessment_revision=revision)
            result.update(accepted=accepted,assessment_revision=revision)
            status = (('exhausted' if attempt >= 5 else 'retry_needed') if result['errors'] else 'completed') if accepted else 'superseded'
        error = None
    except Exception as exc:
        error = str(exc)[:500]
        result = {'errors': [{'stage': 'ai', 'message': error}], 'ai_usage': {}}
        status = 'exhausted' if attempt >= 5 else 'retry_needed'
    runtime.store.put('release_analysis_retry', record['id'], {**record, 'attempts': attempt, 'status': status, 'last_error': error,
        'next_attempt_at': (datetime.now(timezone.utc) + timedelta(seconds=min(30 * 2 ** attempt, 900))).isoformat()}, release['release_id'])
    runtime.store.audit('analysis.' + status, 'Release AI retry finished', details={'release_id': release['release_id'], 'attempt': attempt, 'retry_id': record['id']})
    return {'release_id': release['release_id'], 'retry_state': status, 'retry_attempt': attempt,
            'errors': result['errors'], 'ai_usage': result['ai_usage'],
            'assessment_revision':result.get('assessment_revision'),'accepted':result.get('accepted',False)}
