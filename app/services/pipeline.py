"""Central analysis orchestration. All heavyweight processes run in this service."""
import copy
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from .ai_client import AIClient
from .assessment import AssessmentEngine, result_cache_fresh, finding_decision_fresh, RULESET_VERSION
from .scanner import GrypeScanner, ScanError
from .sbom_parser import normalize_inventory, stable_id
from .source_tools import SourceTools
from .applicability_context import applicability_facts, assessment_facts
from .scan_progress import matching_counts


ANALYSIS_FIELDS = ('analysis_managed', 'analysis_attempts', 'analysis_success', 'analysis_last_attempt_at',
                   'analysis_next_attempt_at', 'analysis_retry_exhausted', 'analysis_error')
MAX_ANALYSIS_ATTEMPTS = 5


def analysis_due(finding, at=None):
    if finding.get('pending_evidence_requests') or int(finding.get('analysis_attempts', 0)) >= MAX_ANALYSIS_ATTEMPTS:
        return False
    deadline = finding.get('analysis_next_attempt_at')
    if not deadline:
        return True
    try:
        parsed = datetime.fromisoformat(deadline.replace('Z', '+00:00'))
        return parsed.tzinfo is not None and parsed <= (at or datetime.now(timezone.utc))
    except (TypeError, ValueError, AttributeError):
        return False


def _transition(finding, state, callback=None, **details):
    finding['assessment_state'] = state
    finding['analysis_managed'] = True
    finding.setdefault('analysis_attempts', 0)
    finding.setdefault('analysis_next_attempt_at', None)
    finding.setdefault('analysis_retry_exhausted', False)
    if 'success' in details:
        finding['analysis_success'] = details['success']
    if callback:
        return callback(copy.deepcopy(finding), state, **details)
    return None


def _reuse_analysis(finding, previous):
    # Reuse processing/proposal evidence, never restore a previous safety verdict.
    for key in (*ANALYSIS_FIELDS, 'ai_analysis', 'ai_proposed_applicability', 'review_required'):
        if key in previous:
            finding[key] = copy.deepcopy(previous[key])
    finding['evidence_ids'] = sorted(set(finding.get('evidence_ids', []) + previous.get('evidence_ids', [])))
    finding['evidence'] = copy.deepcopy(previous.get('evidence', []))
    proposal = previous.get('ai_analysis', {}).get('proposal', {})
    if proposal.get('rationale'):
        finding['rationale'] += ' AI evidence review: ' + proposal['rationale']
    finding['assessment_state'] = 'analyzed'


def pre_analysis(inventory, context):
    """Extension hook; intentionally does nothing by default."""


def post_analysis(result):
    """Extension hook; intentionally does nothing by default."""


def merge_candidate_matches(candidates):
    """One finding per occurrence/advisory, retaining every raw match as evidence."""
    grouped = {}
    def authority(item):
        exact = any(m.get('type') == 'exact-direct-match' for m in item.get('match_details', []))
        distro = str(item.get('distro', {}).get('name', '')).lower()
        return bool(exact and distro and distro in str(item.get('advisory_namespace', '')).lower())
    for candidate in candidates:
        key = (candidate['scope_id'], candidate['component_id'], candidate['cve_id'])
        if key not in grouped:
            grouped[key] = copy.deepcopy(candidate)
            grouped[key]['advisory_sources'] = [candidate.get('advisory_namespace')]
            continue
        previous = grouped[key]
        selected = copy.deepcopy(candidate if authority(candidate) and not authority(previous) else previous)
        selected['evidence_ids'] = sorted(set(previous['evidence_ids'] + candidate['evidence_ids']))
        selected['match_details'] = previous.get('match_details', []) + candidate.get('match_details', [])
        selected['advisory_sources'] = sorted(set(previous.get('advisory_sources', []) + [candidate.get('advisory_namespace')]) - {None})
        grouped[key] = selected
    return list(grouped.values())


def inventory_coverage(context, scopes, max_age=86400):
    """Scanner completion cannot upgrade stale/failed collection to complete coverage."""
    facts = [f for f in context.get('runtime_facts', []) if f.get('collector') == 'inventory']
    errors = []
    profile = context.get('inventory_profile') or ('debian_package_metadata' if facts or context.get('inventory_digest') else 'sbom')
    for fact in facts:
        message = None
        if fact.get('status') != 'observed':
            message = 'Inventory collector did not complete successfully'
        elif not context.get('inventory_digest') or fact.get('inventory_digest') != context['inventory_digest']:
            message = 'Inventory coverage fact belongs to a different inventory digest'
        else:
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(fact['collected_at'].replace('Z', '+00:00'))).total_seconds()
                ttl = min(int(fact.get('ttl_seconds', max_age)), max_age)
                if age < -30 or age > ttl:
                    message = 'Inventory coverage observation is stale or has an invalid future timestamp'
            except (KeyError, TypeError, ValueError):
                message = 'Inventory coverage timestamp is invalid'
        if message:
            errors.append({'stage': 'inventory_collection', 'scope_id': 'device', 'message': message})
            continue
        values = fact.get('value')
        if not isinstance(values, list):
            errors.append({'stage': 'inventory_collection', 'scope_id': 'device', 'message': 'Inventory scope coverage is malformed'})
            continue
        reported = set()
        for value in values:
            if not isinstance(value, dict):
                errors.append({'stage': 'inventory_collection', 'scope_id': 'device', 'message': 'Malformed scope status'})
                continue
            scope_id = value.get('scope') or value.get('scope_id')
            reported.add(scope_id)
            if value.get('status') != 'complete':
                errors.append({'stage': 'inventory_collection', 'scope_id': scope_id or 'unknown',
                               'message': 'Scope inventory is ' + str(value.get('status', 'unknown')) + '; previous components may be retained'})
        for scope in scopes:
            if scope['id'] not in reported:
                errors.append({'stage': 'inventory_collection', 'scope_id': scope['id'], 'message': 'No current collection coverage for this scope'})
    return profile, errors


class AnalysisPipeline:
    def __init__(self, source_roots=(), scanner_binary='grype', settings=None, *, pre_hook=None, post_hook=None):
        self.settings = settings.model_dump() if hasattr(settings, 'model_dump') else dict(settings or {})
        config = self.settings
        self.ai_enabled = bool(config.get('ai_enabled', True))
        if not source_roots and config.get('source_root'):
            source_roots = [config['source_root']]
        self.source_roots = source_roots
        self.tools = SourceTools(source_roots, config.get('build_facts'), default_revision=config.get('source_revision'))
        cache_dir = config.get('scanner_cache_dir')
        if cache_dir is None and (config.get('scanner_env') or {}).get('GRYPE_DB_CACHE_DIR'):
            cache_dir = str(Path(config['scanner_env']['GRYPE_DB_CACHE_DIR']).parent / 'match-cache')
        self.scanner = GrypeScanner(scanner_binary, config.get('scan_timeout_seconds', 180),
                                    config.get('scanner_max_output_bytes', 64 * 1024 * 1024), config.get('scanner_env'),
                                    cache_dir=cache_dir, cache_max_bytes=config.get('scanner_cache_max_bytes', 256 * 1024 * 1024),
                                    cache_max_entries=config.get('scanner_cache_max_entries', 256))
        self.engine = AssessmentEngine(config.get('trusted_assessments', []), config.get('build_evidence_policy', 'required'))
        self.ai = AIClient(config.get('ai_provider', 'openai'), config.get('ai_api_key', ''),
                           model=config.get('ai_model'), api_url=config.get('ai_api_url'),
                           max_calls=config.get('ai_max_calls', 4), max_tool_calls=config.get('ai_max_tool_calls', 6),
                           max_input_chars=config.get('ai_max_input_chars', 36000),
                           max_output_tokens=config.get('ai_max_output_tokens', 700), timeout=config.get('ai_timeout_seconds', 30))
        self.pre_hook, self.post_hook = pre_hook or pre_analysis, post_hook or post_analysis

    def _provider_ready(self):
        return (self.ai_enabled and int(self.settings.get('ai_max_calls', 4)) > 0
                and self.ai.health().get('configured', False))

    def _investigate(self, finding, records, tools, result, callback=None, scanner_revision=None):
        details = {'scanner_revision': scanner_revision}
        if self.ai.health().get('circuit_open'):
            finding['analysis_next_attempt_at'] = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
            finding['analysis_error'] = 'AI circuit breaker is open'
            _transition(finding, 'retry_needed', callback, **details)
            return
        finding['analysis_last_attempt_at'] = datetime.now(timezone.utc).isoformat()
        finding['analysis_attempts'] = int(finding.get('analysis_attempts', 0)) + 1
        _transition(finding, 'analyzing', callback, **details)
        investigation = self.ai.investigate(finding, [records[eid] for eid in finding.get('evidence_ids', []) if eid in records], tools)
        finding['ai_analysis'] = investigation
        for key, value in investigation['usage'].items():
            result['ai_usage'][key] = result['ai_usage'].get(key, 0) + value
        _transition(finding, 'analyzed', callback, success=bool(investigation['success']), **details)
        if investigation['success']:
            proposal = investigation['proposal']
            finding['ai_proposed_applicability'] = proposal['applicability']
            finding['rationale'] = finding.get('justification', finding.get('rationale', '')) + ' AI evidence review: ' + proposal['rationale']
            finding['evidence_ids'] = sorted(set(finding.get('evidence_ids', []) + proposal['evidence_ids']))
            finding['review_required'] = proposal['applicability'] in {'fixed', 'not_affected'}
            finding['analysis_next_attempt_at'] = None
            finding['analysis_error'] = None
            finding['analysis_retry_exhausted'] = False
        else:
            finding['analysis_error'] = investigation['error']
            finding['analysis_retry_exhausted'] = finding['analysis_attempts'] >= MAX_ANALYSIS_ATTEMPTS
            finding['analysis_next_attempt_at'] = (datetime.now(timezone.utc) + timedelta(seconds=min(30 * 2 ** finding['analysis_attempts'], 900))).isoformat()
            _transition(finding, 'retry_needed', callback, success=False, error=investigation['error'], **details)
            result['errors'].append({'finding_id': finding['id'], 'stage': 'ai', 'message': investigation['error']})

    def retry_findings(self, findings, context=None):
        """Continue bounded per-CVE work against saved evidence; never run Grype."""
        context = dict(context or {})
        callback = context.pop('_analysis_lifecycle', None)
        context = copy.deepcopy(context)
        context['runtime_facts'] = assessment_facts(context.get('runtime_facts'))
        context.setdefault('context_hash', stable_id(applicability_facts(context.get('runtime_facts', []))))
        revision = context.get('source_revision') if 'source_revision' in context else self.settings.get('source_revision')
        tools = SourceTools(self.source_roots, self.settings.get('build_facts'), context.get('runtime_facts'), revision or None)
        result = {'findings': copy.deepcopy(findings), 'evidence': [], 'errors': [], 'evidence_requests': [],
                  'ruleset_version': RULESET_VERSION,
                  'build_evidence_policy': self.engine.build_evidence_policy,
                  'ai_usage': {'calls': 0, 'tool_calls': 0, 'input_tokens': 0, 'output_tokens': 0, 'input_characters': 0}}
        records = {record['id']: record for finding in findings for record in finding.get('evidence', []) if isinstance(record, dict) and record.get('id')}
        tools.records = list(records.values())
        tools.components = [{**f.get('component', {}), 'scope_id': f.get('scope_id', f.get('scope'))} for f in findings if f.get('component')]
        tools.allowed_scopes = {f.get('scope_id') or f.get('scope') for f in findings}
        tools.inventory_digest = context.get('inventory_digest')
        tools.allow_runtime_requests = bool(self._provider_ready() and context.get('device_id'))
        tools.max_fact_requests = int(self.settings.get('ai_max_evidence_requests', 4))
        count = 0
        # Least-attempted cases first: failures and successful unknowns cannot
        # repeatedly consume the budget before untouched tail CVEs get a turn.
        ordered = sorted(result['findings'], key=lambda f: (int(f.get('analysis_attempts', 0)), f.get('analysis_last_attempt_at') or '', f.get('id', '')))
        for finding in ordered:
            previous_state = finding.get('assessment_state')
            finding.setdefault('scope_id', finding.get('scope'))
            evaluated = self.engine.evaluate(finding, context.get('artifact_id') or context.get('build_id'), context)
            for key in ('applicability', 'exposure', 'decision_valid_until', 'exposure_valid_until', 'decision_basis',
                        'review_record_id', 'vex_verdict', 'vex_justification', 'action_type', 'rationale', 'justification', 'ruleset_version',
                        'build_evidence_policy', 'artifact_binding', 'remediation_eligible', 'review_required', 'assessment_stale'):
                if key in evaluated:
                    finding[key] = evaluated[key]
                else:
                    finding.pop(key, None)
            if finding['applicability'] != 'under_investigation':
                _transition(finding, 'analyzed', callback, success=True, scanner_revision=context.get('advisory_revision'))
                continue
            if previous_state not in ('pending_analysis', 'retry_needed', 'analyzing') or not analysis_due(finding):
                continue
            if not self._provider_ready() or count >= max(0, min(int(self.settings.get('ai_max_findings', 10)), 100)):
                continue
            _transition(finding, 'pending_analysis', callback, scanner_revision=context.get('advisory_revision'))
            count += 1
            self._investigate(finding, records, tools, result, callback, context.get('advisory_revision'))
        records.update(tools.evidence)
        trusted = {e['id']: e for e in self.settings.get('trusted_evidence', []) if isinstance(e, dict) and e.get('id')}
        referenced = {eid for f in result['findings'] for eid in f.get('evidence_ids', [])}
        records.update({eid: trusted[eid] for eid in referenced if eid in trusted})
        result['evidence'] = list(records.values())
        result['evidence_requests'] = list(tools.requests.values())
        for finding in result['findings']:
            finding['evidence'] = [records[eid] for eid in finding.get('evidence_ids', []) if eid in records]
            pending = [r['request_id'] for r in result['evidence_requests'] if finding.get('id') in r.get('finding_ids', [])]
            if pending:
                finding['pending_evidence_requests'] = pending
                _transition(finding, 'pending_analysis', callback, scanner_revision=context.get('advisory_revision'))
        result['analysis_selection'] = {'provider_cases_run': count}
        return result

    def analyze(self, inventory, context=None):
        started = time.monotonic()
        inventory = normalize_inventory(inventory)
        context = dict(context or {})
        callback = context.pop('_analysis_lifecycle', None)
        progress = context.pop('_progress', None) or (lambda event: None)
        context = copy.deepcopy(context)
        context['runtime_facts'] = assessment_facts(context.get('runtime_facts'))
        context.setdefault('context_hash', stable_id(applicability_facts(context.get('runtime_facts', []))))
        digest = stable_id(inventory)
        context.setdefault('inventory_digest', digest)
        self.pre_hook(copy.deepcopy(inventory), copy.deepcopy(context))
        # Per-run tools prevent one device's runtime evidence leaking to another concurrent run.
        revision = context.get('source_revision') if 'source_revision' in context else self.settings.get('source_revision')
        tools = SourceTools(self.source_roots, self.settings.get('build_facts'), context.get('runtime_facts'), revision or None)
        result = {'inventory_digest': digest, 'findings': [], 'evidence': [], 'errors': [], 'evidence_requests': [],
                  'ruleset_version': RULESET_VERSION,
                  'build_evidence_policy': self.engine.build_evidence_policy,
                  'coverage': {'complete': True, 'scopes_total': len(inventory['scopes']), 'scopes_scanned': 0,
                               'components_total': sum(len(s['components']) for s in inventory['scopes']), 'components_scanned': 0,
                               'components_matched': 0, 'components_reused': 0, 'components_removed': 0, 'errors': []},
                  'scanner': {'status': 'pending', 'version': None, 'db_revision': None, 'db_built_at': None, 'cache_hits': 0, 'scope_work': []},
                  'ai_usage': {'calls': 0, 'tool_calls': 0, 'input_tokens': 0, 'output_tokens': 0, 'input_characters': 0}}
        candidates = []
        work = {'scopes_total': result['coverage']['scopes_total'], 'scopes_completed': 0,
                'packages_total': result['coverage']['components_total'], 'packages_matched': 0, 'packages_reused': 0,
                'packages_removed': 0}
        progress({'phase': 'matching', 'detail': 'Matching current inventory', **work})
        db_revisions = set()
        for warning in inventory.get('coverage_warnings', []):
            error = {'stage': 'sbom_containment', 'message': str(warning)}
            result['coverage']['complete'] = False
            result['coverage']['errors'].append(error)
            result['errors'].append(error)
        profile, collection_errors = inventory_coverage(context, inventory['scopes'], int(self.settings.get('inventory_max_age_seconds', 86400)))
        result['coverage']['inventory_profile'] = profile
        result['coverage']['artifact_binding'] = 'verified' if context.get('artifact_verified') is True else 'unverified'
        result['coverage']['build_evidence_policy'] = self.engine.build_evidence_policy
        if collection_errors:
            result['coverage']['complete'] = False
            result['coverage']['errors'].extend(collection_errors)
            result['errors'].extend(collection_errors)
        for fact in context.get('runtime_facts', []):
            fact['id'] = 'runtime-' + stable_id(fact)[:24]
            result['evidence'].append({'id': fact['id'], 'type': 'runtime_fact', 'data': copy.deepcopy(fact)})
        for scope in inventory['scopes']:
            progress({'phase': 'matching', 'scope_id': scope['id'], 'detail': 'Matching scope', 'scan_mode': None, **work})
            try:
                scanned = self.scanner.scan_scope(scope)
            except ScanError as exc:
                error = {'scope_id': scope['id'], 'stage': 'scanner', 'message': str(exc)}
                result['errors'].append(error)
                result['coverage']['errors'].append(error)
                result['coverage']['complete'] = False
                work['scopes_completed'] += 1
                progress({'phase': 'matching', 'scope_id': scope['id'], 'detail': 'Scope matching failed',
                          'scan_mode': 'failed', 'force': True, **work})
                continue
            result['coverage']['scopes_scanned'] += 1
            result['scanner']['cache_hits'] += int(scanned.get('cache_hit', False))
            result['coverage']['components_scanned'] += scanned['components_scanned']
            counts = matching_counts(scanned)
            mode = scanned.get('scan_mode', 'cached' if scanned.get('cache_hit') else 'full')
            result['scanner']['scope_work'].append({'scope_id': scope['id'], 'scan_mode': mode, **counts,
                **({'incremental_fallback_reason': scanned['incremental_fallback_reason']} if scanned.get('incremental_fallback_reason') else {})})
            for key, value in counts.items():
                result['coverage'][key] += value
                work[key.replace('components_', 'packages_')] += value
            work['scopes_completed'] += 1
            progress({'phase': 'matching', 'scope_id': scope['id'], 'detail': 'Scope matching finished',
                      'scan_mode': mode,
                      'force': True, **work})
            if scanned['missing_versions']:
                error = {'scope_id': scope['id'], 'stage': 'inventory', 'message': 'Components without versions remain unassessed', 'component_ids': scanned['missing_versions']}
                result['coverage']['errors'].append(error)
                result['coverage']['complete'] = False
            result['evidence'].extend(scanned['evidence'])
            candidates.extend(scanned['findings'])
            meta = scanned['scanner']
            db = meta.get('database') or {}
            if isinstance(db.get('status'), dict):
                db = db['status']
            result['scanner'].update(version=meta.get('version'), db_revision=db.get('checksum') or db.get('built') or db.get('builtAt'), db_built_at=db.get('built') or db.get('builtAt'))
            if result['scanner']['db_revision']:
                db_revisions.add(result['scanner']['db_revision'])
        if len(db_revisions) > 1:
            error = {'stage': 'scanner_database', 'message': 'Advisory database changed between scopes; reassessment required'}
            result['coverage']['complete'] = False
            result['coverage']['errors'].append(error)
            result['errors'].append(error)
        if not result['scanner']['db_revision']:
            status = self.scanner.status()
            for key in ('version', 'db_revision', 'db_built_at'):
                if not result['scanner'][key]:
                    result['scanner'][key] = status.get(key)
        result['scanner']['status'] = 'complete' if result['coverage']['complete'] else ('partial' if result['coverage']['scopes_scanned'] else 'failed')
        max_ai_findings = max(0, min(int(self.settings.get('ai_max_findings', 10)), 100))
        ai_cases = 0
        requested_ids = set(context.get('finding_ids') or [])
        matched_selection = []
        records = {record['id']: record for record in result['evidence']}
        tools.records = list(records.values())
        tools.components = [{**component, 'scope_id': scope['id']} for scope in inventory['scopes'] for component in scope['components']]
        tools.allowed_scopes = {scope['id'] for scope in inventory['scopes']}
        tools.inventory_digest = context.get('inventory_digest')
        tools.allow_runtime_requests = bool(self.ai_enabled and self.ai.health()['configured'] and context.get('device_id'))
        tools.max_fact_requests = int(self.settings.get('ai_max_evidence_requests', 4))
        # Persist every initial pending state before starting the first provider
        # call, so a slow provider/crash does not hide the remaining CVEs.
        merged = merge_candidate_matches(candidates)
        progress({'phase': 'assessing', 'detail': 'Evaluating findings and saving evidence', 'scope_id': None,
                  'findings_completed': 0, 'findings_total': len(merged), **work})
        for candidate in merged:
            finding = self.engine.evaluate(candidate, inventory.get('artifact_id') or inventory.get('build_id'), context)
            finding['evidence'] = [records[eid] for eid in finding.get('evidence_ids', []) if eid in records]
            state = 'pending_analysis' if finding['applicability'] == 'under_investigation' else 'analyzed'
            reused = _transition(finding, state, callback, success=None if state == 'pending_analysis' else True,
                                 scanner_revision=result['scanner'].get('db_revision'))
            if reused and reused.get('progress'):
                finding.update(reused['progress'])
                if finding.get('analysis_retry_exhausted') or int(finding.get('analysis_attempts', 0)) >= MAX_ANALYSIS_ATTEMPTS:
                    finding['assessment_state'] = 'retry_needed'
            if state == 'pending_analysis' and reused and reused.get('reuse'):
                _reuse_analysis(finding, reused['reuse'])
                records.update({r['id']: r for r in finding.get('evidence', []) if r.get('id')})
                _transition(finding, 'analyzed', callback, success=True, scanner_revision=result['scanner'].get('db_revision'), reused=True)
            result['findings'].append(finding)
            progress({'phase': 'assessing', 'findings_completed': len(result['findings']), 'findings_total': len(merged)})
        progress({'phase': 'reviewing_evidence', 'detail': 'Checking evidence and optional AI analysis',
                  'findings_completed': len(merged), 'findings_total': len(merged), 'evidence_completed': 0})
        for index, finding in enumerate(result['findings'], 1):
            stored_id = stable_id([context.get('device_id'), finding['component_id'], finding['scope_id'], finding['cve_id']])
            selected = not requested_ids or finding['id'] in requested_ids or stored_id in requested_ids
            if selected:
                matched_selection.append(stored_id if stored_id in requested_ids else finding['id'])
            if (selected and finding['assessment_state'] == 'pending_analysis' and self._provider_ready()
                    and ai_cases < max_ai_findings and analysis_due(finding)):
                ai_cases += 1
                self._investigate(finding, records, tools, result, callback, result['scanner'].get('db_revision'))
            progress({'phase': 'reviewing_evidence', 'evidence_completed': index})
        result['evidence_requests'] = list(tools.requests.values())
        result['analysis_selection'] = {'requested_finding_ids': sorted(requested_ids), 'matched_finding_ids': matched_selection,
                                        'provider_cases_run': ai_cases}
        for finding in result['findings']:
            pending = [r['request_id'] for r in result['evidence_requests'] if finding.get('id') in r.get('finding_ids', [])]
            if pending:
                finding['pending_evidence_requests'] = pending
                _transition(finding, 'pending_analysis', callback, scanner_revision=result['scanner'].get('db_revision'))
        records.update(tools.evidence)
        result['evidence'] = list(records.values())
        known = {e['id'] for e in result['evidence']}
        referenced = {eid for f in result['findings'] for eid in f.get('evidence_ids', [])}
        result['evidence'].extend(e for e in self.settings.get('trusted_evidence', [])
                                 if isinstance(e, dict) and e.get('id') in referenced and e['id'] not in known)
        evidence_index = {record['id']: record for record in result['evidence']}
        for finding in result['findings']:
            finding['evidence'] = [evidence_index[eid] for eid in finding.get('evidence_ids', []) if eid in evidence_index]
        result['assessment_duration_ms'] = round((time.monotonic() - started) * 1000)
        progress({'phase': 'saving', 'detail': 'Preparing assessment result', 'saving_step': 0, 'force': True})
        self.post_hook(copy.deepcopy(result))
        return result
