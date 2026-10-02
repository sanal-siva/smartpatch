"""Operator-authorized interactive-agent investigation, independent of API providers.

A frozen context, recorded typed evidence, and a proposal are separate from an
administrator's applicability review. No provider login/key is synthesized here.
"""
import copy
import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Literal
from urllib.request import Request, build_opener
from urllib.parse import urlparse

import jsonschema
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.db.store import now, stable_hash
from .source_tools import SourceTools
from .ai_client import NoRedirects
from .applicability_context import applicability_facts, assessment_facts


class ExternalAgentError(ValueError):
    def __init__(self, message, status_code=422):
        super().__init__(message)
        self.status_code = status_code


class ExternalAnalysisSubmission(BaseModel):
    model_config = ConfigDict(extra='forbid')
    snapshot_hash: str = Field(pattern=r'^[0-9a-f]{64}$')
    cve_id: str = Field(min_length=1, max_length=128)
    component_id: str = Field(min_length=1, max_length=256)
    scope_id: str = Field(min_length=1, max_length=256)
    proposed_applicability: Literal['affected', 'fixed', 'not_affected', 'under_investigation']
    rationale: str = Field(min_length=20, max_length=6000)
    evidence_ids: list[str] = Field(min_length=1, max_length=30)
    unknowns: list[str] = Field(default_factory=list, max_length=20)
    recommended_action: Literal['collect_evidence', 'manual_review', 'maintenance_review', 'no_change_pending_verification'] = 'manual_review'
    agent_name: str = Field(default='Codex interactive session', min_length=1, max_length=100)
    external_references: list[str] = Field(default_factory=list, max_length=10)

    @field_validator('unknowns')
    @classmethod
    def bounded_unknowns(cls, values):
        if any(len(value) > 500 for value in values):
            raise ValueError('Unknown-evidence entries must be at most 500 characters')
        return values

    @field_validator('external_references')
    @classmethod
    def reference_urls(cls, values):
        if any(len(value) > 2048 or not re.fullmatch(r'https://[^\s]+', value) or urlparse(value).username or urlparse(value).password for value in values):
            raise ValueError('External references must be HTTPS URLs; they are not evidence until fetched by a recorded tool')
        return values


_SECRET = re.compile(r'password|secret|authorization|api[_-]?key|private[_-]?key|auth[_-]?token', re.I)


def _bounded(value, depth=0):
    if depth > 8:
        return '[nested content omitted]'
    if isinstance(value, dict):
        if isinstance(value.get('name'), str) and _SECRET.search(value['name']) and 'value' in value:
            return {'name': value['name'], 'value': '[redacted]'}
        return {str(k): _bounded(v, depth + 1) for k, v in list(value.items())[:35] if not _SECRET.search(str(k))}
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:16]]
    if isinstance(value, str):
        value = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}', 'Bearer [redacted]', value)
        value = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '[redacted private key]', value, flags=re.S)
        return value[:5000]
    return value


def _evidence(record):
    safe = _bounded(record)
    encoded = json.dumps(safe, sort_keys=True)
    if len(encoded) > 9000:
        safe = {'id': record['id'], 'type': record.get('type'), 'provenance': _bounded(record.get('provenance', {})),
                'data': {'status': 'partial', 'preview': encoded[:6500]}, 'complete': False}
    safe['original_digest'] = stable_hash(record)
    return safe


def _role(principal):
    if not isinstance(principal, dict) or principal.get('role') not in {'operator', 'admin'} or not principal.get('id'):
        raise ExternalAgentError('Operator or administrator permission required', 403)


def _snapshot(runtime, finding):
    device = runtime.store.device(finding['device_id'])
    if not device:
        raise ExternalAgentError('Finding device no longer exists', 409)
    relevant = applicability_facts(device.get('facts', []))
    config = runtime.configuration()
    status = runtime.pipeline.scanner.status()
    return {'device_id': device['id'], 'epoch': device['epoch'], 'inventory_digest': device['inventory_digest'],
            'build_id': device.get('build_id'), 'artifact_id': device.get('artifact_id'),
            'artifact_verified': bool(device.get('artifact_verified')), 'binding_revision': device.get('binding_revision', 'unverified'),
            'build_evidence_policy': config.get('build_evidence_policy', 'required'),
            'assessment_policy_revision': config.get('assessment_policy_revision'),
            'source_revision': runtime._source_revision(device) or None,
            'source_roots_hash': stable_hash(config.get('source_roots', [])),
            'advisory_db_revision': status.get('db_revision'), 'advisory_generation': getattr(runtime, 'advisory_generation', 0),
            'context_hash': stable_hash(relevant), 'scope_id': finding.get('scope_id') or finding.get('scope'),
            'component_id': finding['component_id'], 'cve_id': finding['cve_id'],
            'finding_evidence_hash': stable_hash(finding.get('evidence', [])),
            'assessment_revision': finding.get('assessment_revision')}, device


def _finding_current(finding, device, policy='required'):
    context_hash = stable_hash(applicability_facts(device.get('facts', [])))
    return (not finding.get('assessment_stale') and finding.get('build_evidence_policy', 'required') == policy
            and finding.get('assessment_policy_revision') == device.get('assessment_policy_revision')
            and finding.get('status') == 'current' and finding.get('inventory_digest') == device['inventory_digest']
            and finding.get('inventory_epoch', device['epoch']) == device['epoch']
            and finding.get('build_id', device.get('build_id')) == device.get('build_id')
            and finding.get('artifact_id') == device.get('artifact_id')
            and bool(finding.get('artifact_verified')) == bool(device.get('artifact_verified'))
            and finding.get('binding_revision', 'unverified') == device.get('binding_revision', 'unverified')
            and finding.get('context_hash', context_hash) == context_hash)


def _make_tools(runtime, session, finding, device):
    root_tools = SourceTools(runtime.configuration().get('source_roots', []))
    approved = {}
    revision = session['snapshot']['source_revision']
    if revision:
        for name in root_tools.roots:
            try:
                root, _ = root_tools._repository(name, revision)
                approved[name] = str(root)
                if len(approved) >= 4:
                    break
            except Exception:
                continue
    component = {**finding.get('component', {}), 'id': finding['component_id'], 'scope_id': session['snapshot']['scope_id'],
                 'name': finding['package_name'], 'version': finding['affected_version']}
    tools = SourceTools(approved, {'artifact_binding': {'verified': session['snapshot']['artifact_verified'],
                        'artifact_id': session['snapshot']['artifact_id'], 'binding_revision': session['snapshot']['binding_revision']},
                        'source_revision': {'value': revision, 'basis': 'reported revision; artifact binding shown separately'}},
                        assessment_facts(device.get('facts', [])), revision, evidence_records=finding.get('evidence', []), components=[component])
    tools.inventory_digest = session['snapshot']['inventory_digest']
    tools.allowed_scopes = {session['snapshot']['scope_id']}
    tools.allow_runtime_requests = True  # explicit authenticated interactive investigation, not automatic provider mode
    tools.current_finding_id = finding['id']
    tools.requests = copy.deepcopy(session.get('pending_requests', {}))
    return tools


def _tool_schemas(tools, cve_id):
    schemas = tools.list_tools()
    if re.fullmatch(r'CVE-\d{4}-\d{4,}', cve_id):
        schemas.append({'type': 'function', 'function': {'name': 'fetch_official_advisory',
            'description': 'Fetch only the selected CVE from the official Debian security tracker over verified HTTPS. Bounded public source; no arbitrary URL or credentials.',
            'parameters': {'type': 'object', 'properties': {'cve_id': {'type': 'string', 'const': cve_id}},
                           'required': ['cve_id'], 'additionalProperties': False}}})
    return schemas


def create_external_session(runtime, finding_id, principal):
    _role(principal)
    finding = runtime.store.get('finding', finding_id)
    if not finding:
        raise ExternalAgentError('Finding not found', 404)
    snapshot, device = _snapshot(runtime, finding)
    if not _finding_current(finding, device, snapshot['build_evidence_policy']):
        raise ExternalAgentError('Finding is stale; assess current inventory before opening a session', 409)
    ident = str(uuid.uuid4())
    selected, size = [], 0
    for raw in finding.get('evidence', [])[:8]:
        if not isinstance(raw, dict) or not isinstance(raw.get('id'), str):
            continue
        item = _evidence(raw)
        amount = len(json.dumps(item))
        if selected and size + amount > 14000:
            break
        size += amount
        selected.append(item)
    if not selected:
        raise ExternalAgentError('Finding has no recorded evidence; a fresh central scan is required', 409)
    session = {'id': ident, 'session_id': ident, 'finding_id': finding_id, 'device_id': device['id'],
        'source': 'codex_interactive', 'created_by': principal['id'], 'created_at': now(),
        'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(), 'status': 'open',
        'snapshot': snapshot, 'snapshot_hash': stable_hash(snapshot), 'tool_calls': 0, 'response_chars': 0,
        'evidence_ids': [item['id'] for item in selected], 'pending_requests': {},
        'limits': {'max_tool_calls': 12, 'max_context_chars': 16000, 'max_bundle_chars': 32000,
                   'max_response_chars': 48000, 'max_fact_requests': 4,
                   'context_budget_scope': 'snapshot + finding + evidence; tool/submission schemas count toward max_bundle_chars'}}
    tools = _make_tools(runtime, session, finding, device)
    fields = ('id', 'cve_id', 'component_id', 'package_name', 'affected_version', 'severity', 'cvss_score', 'fixed_versions',
              'applicability', 'exposure', 'rationale', 'artifact_binding', 'advisory_match_status',
              'build_evidence_policy', 'decision_basis', 'review_required')
    bundle = {'session_id': ident, 'source': 'codex_interactive', 'status': 'open', 'created_at': session['created_at'],
        'expires_at': session['expires_at'], 'snapshot_hash': session['snapshot_hash'], 'snapshot': snapshot,
        'finding': {**{field: _bounded(finding.get(field)) for field in fields}, 'scope_id': snapshot['scope_id']},
        'evidence': selected, 'tools': _tool_schemas(tools, finding['cve_id']), 'limits': session['limits'],
        'submission_schema': ExternalAnalysisSubmission.model_json_schema(),
        'agent_identity_verified': False, 'agent_name_origin': 'self_reported',
        'authentication_basis': 'operator API credential; enterprise/provider identity is not verified by this service',
        'policy': 'Recorded evidence supports a proposal. Submission does not change applicability, VEX, or remediation authorization.'}
    if isinstance(bundle['finding'].get('rationale'), str):
        bundle['finding']['rationale'] = bundle['finding']['rationale'][:1500]
    bundle['finding']['fixed_versions'] = [str(version)[:256] for version in finding.get('fixed_versions', [])[:12]]
    context_size = lambda: len(json.dumps({key: bundle[key] for key in ('snapshot', 'finding', 'evidence')}))
    while (context_size() > session['limits']['max_context_chars'] or len(json.dumps(bundle)) > 32000) and len(selected) > 1:
        selected.pop()
    if context_size() > session['limits']['max_context_chars']:
        original = selected[0]
        selected[0] = {'id': original['id'], 'type': original.get('type'), 'original_digest': original['original_digest'],
                       'complete': False, 'data': {'status': 'partial', 'preview': json.dumps(original)[:3500]}}
    if context_size() > session['limits']['max_context_chars'] or len(json.dumps(bundle)) > session['limits']['max_bundle_chars']:
        raise ExternalAgentError('Finding context exceeds the bounded interactive bundle profile', 413)
    bundle['context_chars'] = context_size()
    session['evidence_ids'] = [item['id'] for item in selected]
    session['bundle'] = bundle
    with runtime.store.lock:
        current, _ = _snapshot(runtime, runtime.store.get('finding', finding_id))
        if current != snapshot:
            raise ExternalAgentError('Context changed while opening the session; retry', 409)
        runtime.store.put('external_agent_session', ident, session, device['id'])
        for item in selected:
            runtime.store.put('external_agent_evidence', stable_hash([ident, item['id']]),
                              {'session_id': ident, 'evidence_id': item['id'], 'record': item}, ident)
    runtime.store.audit('external_agent.session_created', 'Interactive source investigation opened', device['id'],
                        {'session_id': ident, 'finding_id': finding_id, 'source': 'codex_interactive', 'actor': principal['id']})
    return bundle


def _session(runtime, session_id, principal, require_open=True):
    _role(principal)
    session = runtime.store.get('external_agent_session', session_id)
    if not session:
        raise ExternalAgentError('Agent session not found', 404)
    if session['created_by'] != principal['id'] and principal['role'] != 'admin':
        raise ExternalAgentError('Session belongs to another operator', 403)
    if require_open:
        if session['status'] != 'open':
            raise ExternalAgentError('Session is already submitted or closed', 409)
        if datetime.fromisoformat(session['expires_at'].replace('Z', '+00:00')) <= datetime.now(timezone.utc):
            raise ExternalAgentError('Session expired; create a fresh context bundle', 410)
        finding = runtime.store.get('finding', session['finding_id'])
        if not finding:
            raise ExternalAgentError('Finding no longer exists', 409)
        snapshot, device = _snapshot(runtime, finding)
        if snapshot != session['snapshot'] or not _finding_current(finding, device, snapshot['build_evidence_policy']):
            raise ExternalAgentError('Finding, inventory, source, binding, advisory or runtime context changed; create a fresh session', 409)
    return session


def get_external_session(runtime, session_id, principal):
    session = _session(runtime, session_id, principal, require_open=False)
    result = {**session['bundle'], 'status': session['status'], 'tool_calls': session['tool_calls'],
              'response_chars': session['response_chars'], 'analysis_id': session.get('analysis_id')}
    result['evidence'] = [record['record'] for record in runtime.store.list('external_agent_evidence', owner=session_id)]
    return result


def project_external_analysis(runtime, finding):
    """Project the archived proposal on a finding read, without applying it.

    Re-scans replace finding payloads. The proposal registry remains independent;
    evidence appended by submission and new scan IDs do not alone stale a proposal.
    """
    if not finding:
        return finding
    pointer = runtime.store.get('external_agent_latest', finding['id'])
    proposal = runtime.store.get('external_agent_analysis', pointer['analysis_id']) if pointer else None
    if proposal is None:
        # Bounded compatibility path for proposals saved before the latest-pointer
        # index existed. New submissions always create that index.
        proposal = next((item for item in runtime.store.list('external_agent_analysis', owner=finding['device_id'], limit=200)
                         if item.get('finding_id') == finding['id']), None)
    if proposal is None:
        return finding
    reasons = []
    try:
        current, device = _snapshot(runtime, finding)
        ignored = {'finding_evidence_hash', 'assessment_revision'}
        if proposal['snapshot'].get('build_evidence_policy', 'required') != current['build_evidence_policy']:
            reasons.append('build_evidence_policy_changed')
        if proposal['snapshot'].get('assessment_policy_revision') != current['assessment_policy_revision']:
            reasons.append('assessment_policy_revision_changed')
        for key, value in proposal['snapshot'].items():
            if key not in ignored and current.get(key) != value:
                reasons.append(key + '_changed')
        if not _finding_current(finding, device, current['build_evidence_policy']):
            reasons.append('finding_not_current')
    except Exception:
        reasons.append('current_context_unavailable')
    keys = ('id', 'session_id', 'source', 'agent_name', 'proposed_applicability', 'rationale',
            'evidence_ids', 'unknowns', 'recommended_action', 'review_required', 'submitted_at')
    summary = {key: proposal.get(key) for key in keys}
    summary.update(stale=bool(reasons), stale_reasons=sorted(set(reasons)), promoted=False,
                   agent_identity_verified=False, agent_name_origin='self_reported')
    return {**finding, 'latest_external_analysis': summary}


class _PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0
    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style'}:self.skip += 1
        if tag in {'tr', 'p', 'h1', 'h2', 'li', 'br'}:self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in {'script', 'style'}:self.skip = max(0, self.skip - 1)
        if tag in {'td', 'th'}:self.parts.append(' | ')
    def handle_data(self, text):
        if not self.skip:self.parts.append(text)


def fetch_official_advisory(cve_id):
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve_id):
        raise ExternalAgentError('Only a specific CVE advisory can be fetched')
    url = 'https://security-tracker.debian.org/tracker/' + cve_id
    request = Request(url, headers={'Accept': 'text/html', 'User-Agent': 'SONiC-Smart-Patch-Interactive/1'})
    with build_opener(NoRedirects()).open(request, timeout=15) as response:
        raw = response.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ExternalAgentError('Official advisory exceeds size bound')
    parser = _PageText();parser.feed(raw.decode('utf-8', errors='replace'))
    text = re.sub(r'[ \t]+', ' ', ''.join(parser.parts)).strip()
    if cve_id not in text:
        raise ExternalAgentError('Fetched page does not identify the selected CVE')
    return {'id': 'advisory-' + stable_hash([url, hashlib.sha256(raw).hexdigest()])[:24],
            'type': 'official_advisory_fetch', 'source': url, 'cve_id': cve_id, 'fetched_at': now(),
            'content_sha256': hashlib.sha256(raw).hexdigest(), 'complete': len(text) <= 12000,
            'data': {'text': text[:12000], 'meaning': 'Distribution advisory evidence; exact shipped artifact and deployment applicability require separate verification'}}


def call_external_tool(runtime, session_id, name, arguments, principal):
    with runtime.store.lock:
        session = _session(runtime, session_id, principal)
        if session['tool_calls'] >= session['limits']['max_tool_calls']:
            raise ExternalAgentError('Session tool-call budget exhausted', 429)
        finding = runtime.store.get('finding', session['finding_id']);device = runtime.store.device(session['device_id'])
        tools = _make_tools(runtime, session, finding, device)
        definitions = {tool['function']['name']: tool['function']['parameters'] for tool in _tool_schemas(tools, finding['cve_id'])}
        if name not in definitions:
            raise ExternalAgentError('Tool is not permitted for this frozen context')
        try:jsonschema.Draft7Validator(definitions[name]).validate(arguments)
        except jsonschema.ValidationError as exc:raise ExternalAgentError('Tool arguments failed validation: ' + exc.message[:300]) from exc
        if name in {'get_source', 'search_symbol', 'check_commit'} and arguments.get('revision') != session['snapshot']['source_revision']:
            raise ExternalAgentError('Source reads must use the frozen build revision')
        path = str(arguments.get('path', ''))
        if path.rsplit('/', 1)[-1] in {'.env', '.npmrc', '.pypirc', 'id_rsa', 'id_ed25519'} or path.endswith(('.key', '.p12', '.pfx')):
            raise ExternalAgentError('Credential files are outside interactive source-tool scope')
        if arguments.get('scope_id') not in (None, session['snapshot']['scope_id']):
            raise ExternalAgentError('Tool scope differs from selected finding')
        if arguments.get('component_id') not in (None, finding['component_id']):
            raise ExternalAgentError('Tool component differs from selected finding')
        if arguments.get('cve_id') not in (None, finding['cve_id']):
            raise ExternalAgentError('Tool advisory differs from selected finding')
        session = {**session, 'tool_calls': session['tool_calls'] + 1}
        runtime.store.put('external_agent_session', session_id, session, session['device_id'])
    try:
        raw = fetch_official_advisory(arguments['cve_id']) if name == 'fetch_official_advisory' else tools.call(name, arguments)
    except Exception as exc:
        raise ExternalAgentError('Evidence tool failed: ' + str(exc)[:500]) from exc
    record = _evidence(raw)
    record['bound_source_revision'] = session['snapshot']['source_revision']
    if name == 'get_patch':record['source_role'] = 'reference_patch' if arguments.get('revision') != session['snapshot']['source_revision'] else 'build_revision'
    with runtime.store.lock:
        session = _session(runtime, session_id, principal)
        amount = len(json.dumps(record))
        if session['response_chars'] + amount > session['limits']['max_response_chars']:
            raise ExternalAgentError('Session evidence-output budget exhausted', 429)
        runtime.store.put('external_agent_evidence', stable_hash([session_id, record['id']]),
            {'session_id': session_id, 'evidence_id': record['id'], 'record': record, 'tool': name, 'arguments': arguments}, session_id)
        session = {**session, 'response_chars': session['response_chars'] + amount,
                   'evidence_ids': sorted(set(session['evidence_ids'] + [record['id']])), 'pending_requests': tools.requests}
        runtime.store.put('external_agent_session', session_id, session, session['device_id'])
        pending = runtime.queue_evidence_requests(session['device_id'], list(tools.requests.values())) if tools.requests else []
    runtime.store.audit('external_agent.tool_called', 'Interactive evidence tool executed', session['device_id'],
                        {'session_id': session_id, 'tool': name, 'evidence_id': record['id'], 'actor': principal['id']})
    return {'session_id': session_id, 'evidence': record, 'pending_requests': pending,
            'usage': {'tool_calls': session['tool_calls'], 'response_chars': session['response_chars']}}


def submit_external_analysis(runtime, session_id, body, principal):
    try:
        submission = body if isinstance(body, ExternalAnalysisSubmission) else ExternalAnalysisSubmission.model_validate(body)
    except ValidationError as exc:
        raise ExternalAgentError('Analysis schema validation failed: ' + str(exc)[:1000]) from exc
    with runtime.store.lock:
        session = _session(runtime, session_id, principal)
        if submission.snapshot_hash != session['snapshot_hash']:
            raise ExternalAgentError('Submitted snapshot does not match this session', 409)
        for key in ('cve_id', 'component_id', 'scope_id'):
            if getattr(submission, key) != session['snapshot'][key]:
                raise ExternalAgentError('Analysis identity differs from the frozen finding', 409)
        if len(set(submission.evidence_ids)) != len(submission.evidence_ids) or any(eid not in session['evidence_ids'] for eid in submission.evidence_ids):
            raise ExternalAgentError('Citations must identify distinct evidence actually recorded in this session')
        cited = []
        for eid in submission.evidence_ids:
            registered = runtime.store.get('external_agent_evidence', stable_hash([session_id, eid]))
            if not registered or registered['session_id'] != session_id:
                raise ExternalAgentError('Evidence citation is not bound to this session')
            cited.append(registered['record'])
        if submission.proposed_applicability != 'under_investigation' and all(record.get('data', {}).get('status') in {'pending', 'unknown'} for record in cited):
            raise ExternalAgentError('Pending or unknown observations cannot support a definitive proposal')
        ident = str(uuid.uuid4())
        proposal = {'id': ident, 'session_id': session_id, 'finding_id': session['finding_id'], 'device_id': session['device_id'],
            'source': 'codex_interactive', 'submitted_by': principal['id'], 'submitted_at': now(), 'snapshot': session['snapshot'],
            **submission.model_dump(), 'status': 'proposal', 'review_required': True, 'promoted': False,
            'agent_identity_verified': False, 'agent_name_origin': 'self_reported',
            'evidence': cited, 'provider_usage': None, 'service_tool_calls': session['tool_calls'],
            'external_references': [{'url': url, 'verification': 'reference_only; cite recorded fetch evidence for verified content'} for url in submission.external_references]}
        finding = runtime.store.get('finding', session['finding_id'])
        existing = {item['id']: item for item in finding.get('evidence', []) if isinstance(item, dict) and item.get('id')}
        existing.update({item['id']: item for item in cited})
        summary = {key: proposal[key] for key in ('id', 'session_id', 'source', 'agent_name', 'proposed_applicability', 'rationale',
                                                   'evidence_ids', 'unknowns', 'recommended_action', 'review_required', 'submitted_at',
                                                   'agent_identity_verified', 'agent_name_origin')}
        runtime.store.put('external_agent_analysis', ident, proposal, session['device_id'])
        runtime.store.put('external_agent_latest', finding['id'], {'finding_id': finding['id'], 'analysis_id': ident,
                          'submitted_at': proposal['submitted_at']}, session['device_id'])
        runtime.store.put('finding', finding['id'], {**finding, 'latest_external_analysis': summary,
            'external_agent_analysis_ids': (finding.get('external_agent_analysis_ids', []) + [ident])[-20:],
            'evidence': list(existing.values()), 'evidence_ids': sorted(set(finding.get('evidence_ids', []) + submission.evidence_ids))}, session['device_id'])
        for item in cited:runtime.store.put('evidence', item['id'], item)
        runtime.store.put('external_agent_session', session_id, {**session, 'status': 'submitted', 'analysis_id': ident}, session['device_id'])
    runtime.store.audit('external_agent.analysis_submitted', 'Interactive investigation saved as a proposal; applicability unchanged', session['device_id'],
                        {'session_id': session_id, 'analysis_id': ident, 'finding_id': session['finding_id'], 'actor': principal['id']})
    return proposal
