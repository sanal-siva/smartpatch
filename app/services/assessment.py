"""Evidence-based applicability; uncertainty never becomes a safety verdict."""
import copy
import re
from datetime import datetime, timezone, timedelta
from .source_tools import compare_versions, EvidenceToolError
from .applicability_context import applicability_facts


RULESET_VERSION = 'smart-patch-rules-v4-optional-build-evidence'


def distribution_advisory_matches(finding):
    """Require the scanner namespace to name this distribution and release."""
    distro = finding.get('distro') or {}
    name = str(distro.get('name', '')).lower()
    version = str(distro.get('version', ''))
    parts = str(finding.get('advisory_namespace', '')).lower().split(':')
    aliases = {'rhel': 'redhat', 'redhat': 'redhat'}
    if len(parts) != 4 or parts[1] != 'distro' or not name or not version:
        return False
    advisory_name, advisory_version = parts[2:]
    return (aliases.get(name, name) == aliases.get(advisory_name, advisory_name)
            and name in {'debian', 'ubuntu', 'alpine', 'redhat', 'rhel'}
            and bool(advisory_version)
            and (version == advisory_version or version.startswith(advisory_version + '.')))


def debian_release_lineage(finding):
    """A Debian revision suffix is a lineage hint, never evidence of a fix."""
    distro = finding.get('distro') or {}
    if str(distro.get('name', '')).lower() != 'debian':
        return None
    release = re.match(r'^(\d+)(?:\.|$)', str(distro.get('version', '')))
    if not release:
        return None
    major = release.group(1)
    component = finding.get('component') or {}
    signals = []
    for field, version in [('binary_version', finding.get('affected_version') or component.get('version')),
                           ('source_version', component.get('source_version'))]:
        if not isinstance(version, str):
            continue
        for hint in sorted(set(re.findall(r'[+~]deb(\d+)u\d+', version))):
            if hint != major:
                signals.append({'field': field, 'version': version, 'release_hint': hint})
    if not signals:
        return None
    return {'status': 'cross_release_candidate', 'scope_distribution': 'debian', 'scope_release': major,
            'signals': signals, 'meaning': 'Version suffix suggests a different Debian release lineage; it proves neither patch presence nor applicability'}


def now():
    return datetime.now(timezone.utc).isoformat()


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return parsed


def relevant_fact_deadlines(context):
    deadlines = []
    for fact in applicability_facts((context or {}).get('runtime_facts', [])):
        ttl = min(int(fact.get('ttl_seconds', 300)), 3600)
        if ttl <= 0:
            raise ValueError('Fact TTL must be positive')
        deadlines.append(_timestamp(fact['collected_at']) + timedelta(seconds=ttl))
    return deadlines


def finding_decision_fresh(finding, context=None, at=None):
    """Read/cache guard; expired exemptions or exposure cannot remain authoritative."""
    if finding.get('assessment_stale'):
        return False
    current = at or datetime.now(timezone.utc)
    for field in ('decision_valid_until', 'exposure_valid_until'):
        if finding.get(field):
            try:
                if _timestamp(finding[field]) <= current:
                    return False
            except (AttributeError, TypeError, ValueError):
                return False
    if finding.get('applicability') in {'fixed', 'not_affected'} and finding.get('decision_basis') == 'operator_review' and not finding.get('decision_valid_until'):
        return False  # legacy review cache entries must be reevaluated with a validity bound
    if finding.get('exposure') in {'reachable', 'constrained'} and not finding.get('exposure_valid_until'):
        return False
    if context is not None and finding.get('decision_basis') == 'operator_review':
        try:
            if any(deadline <= current for deadline in relevant_fact_deadlines(context)):
                return False
        except (KeyError, AttributeError, TypeError, ValueError):
            return False
    return True


def result_cache_fresh(result, context=None, at=None):
    if not isinstance(result, dict):
        return False
    if result.get('cache_valid_until'):
        try:
            if _timestamp(result['cache_valid_until']) <= (at or datetime.now(timezone.utc)):
                return False
        except (AttributeError, TypeError, ValueError):
            return False
    findings = result.get('findings', result.get('recommendations', []))
    return isinstance(findings, list) and all(finding_decision_fresh(finding, context, at) for finding in findings)


class AssessmentEngine:
    def __init__(self, trusted_assessments=None, build_evidence_policy='required'):
        if build_evidence_policy not in {'required', 'optional'}:
            raise ValueError('Build evidence policy must be required or optional')
        self.build_evidence_policy = build_evidence_policy
        self.ai_client = None
        # Only server-owned reviewed records may suppress a scanner finding.
        self.trusted_assessments = trusted_assessments or []

    def set_ai_client(self, client):
        self.ai_client = client

    def evaluate(self, finding, build_id=None, context=None):
        finding = copy.deepcopy(finding)
        context = context or {}
        for stale_field in ('decision_basis', 'review_record_id', 'vex_justification', 'vex_verdict', 'assessment_stale'):
            finding.pop(stale_field, None)
        finding.update(applicability='under_investigation', exposure='unknown', assessment_state='analyzed',
                       confidence=None, risk_score=finding.get('cvss_score'), action_type='defer',
                       expected_downtime_minutes=None, assessed_at=now(), decision_valid_until=None, exposure_valid_until=None,
                       ruleset_version=RULESET_VERSION, build_evidence_policy=self.build_evidence_policy,
                       remediation_eligible=False, review_required=False)
        rationale = 'Scanner identified a candidate; exact build and patch applicability need evidence.'
        component = finding.get('component', {})
        purl = component.get('purl', '')
        custom = bool(component.get('patches')) or '/sonic/' in purl or component.get('custom_build') is True
        lineage = debian_release_lineage(finding)
        finding.pop('release_lineage', None)
        if lineage:
            finding['release_lineage'] = lineage
        matches = finding.get('match_details', [])
        exact = any(m.get('type') == 'exact-direct-match' for m in matches)
        distro_match = distribution_advisory_matches(finding)
        finding['advisory_match_status'] = 'exact_distribution_match' if exact and distro_match else 'candidate'
        finding['artifact_binding'] = 'verified' if context.get('artifact_verified') is True else 'unverified'
        if exact and distro_match:
            rationale = 'Exact distribution advisory match is a candidate finding; shipped-artifact binding and patch applicability remain unverified.'
        if lineage:
            finding['advisory_match_status'] = 'cross_release_candidate'
            rationale = ('Package revision suggests a different Debian release lineage from the selected advisory feed. '
                         'Verify package-specific source/backport evidence; the suffix alone proves no fix, even when the image baseline is verified.')
        if exact and distro_match and not custom and not lineage and context.get('artifact_verified') is True:
            finding['applicability'] = 'affected'
            finding['action_type'] = 'maintenance_window'
            finding['decision_basis'] = 'verified_distribution_match'
            rationale = 'Exact distribution advisory match for this installed package; exposure is assessed separately.'
        elif exact and distro_match and not custom and not lineage and self.build_evidence_policy == 'optional':
            finding.update(applicability='affected', decision_basis='inventory_advisory_match', review_required=True)
            rationale = ('Affected based on the reported package/version and an exact distribution advisory match under '
                         'the optional build-evidence policy. Build provenance and installed binary contents remain '
                         'unverified; undisclosed custom patches may change applicability. Exposure is assessed '
                         'separately. A scoped operator review is required before remediation.')
        # A trusted record must match immutable artifact + occurrence + advisory, not CVE alone.
        records = sorted(self.trusted_assessments, key=lambda r: r.get('created_at', ''), reverse=True)
        for record in records:
            if record.get('build_evidence_policy', 'required') != self.build_evidence_policy:
                continue
            if not record.get('device_id') and (record.get('verification') != 'artifact_verified' or context.get('artifact_verified') is not True):
                continue
            if any(record.get(key) is not None and record.get(key) != context.get(key)
                   for key in ('device_id', 'inventory_digest', 'context_hash')):
                continue
            if record.get('context_hash'):
                fresh = True
                for fact in applicability_facts(context.get('runtime_facts', [])):
                    try:
                        age = (datetime.now(timezone.utc) - datetime.fromisoformat(fact['collected_at'].replace('Z', '+00:00'))).total_seconds()
                        fresh = fresh and 0 <= age <= min(int(fact.get('ttl_seconds', 300)), 3600)
                    except (KeyError, TypeError, ValueError):
                        fresh = False
                if not fresh:
                    continue
            if (not build_id or record.get('build_id') != build_id or record.get('scope_id') != finding['scope_id']
                    or record.get('component_id') != finding['component_id'] or record.get('cve_id') != finding['cve_id']
                    or record.get('version') != finding['affected_version'] or not record.get('evidence_ids')
                    or record.get('verification') not in {'reviewed', 'artifact_verified'}):
                continue
            expiry = record.get('expires_at')
            if expiry:
                try:
                    if datetime.fromisoformat(expiry.replace('Z', '+00:00')) <= datetime.now(timezone.utc):
                        continue
                except (ValueError, TypeError):
                    continue
            state = record.get('applicability')
            if state in {'affected', 'fixed', 'not_affected', 'under_investigation'} and record.get('justification'):
                finding['applicability'] = state
                finding['evidence_ids'] = sorted(set(finding.get('evidence_ids', []) + record['evidence_ids']))
                rationale = record['justification']
                finding['action_type'] = 'maintenance_window' if state == 'affected' else 'defer'
                finding['vex_justification'] = record.get('vex_justification')
                finding['decision_basis'] = 'operator_review' if record['verification'] == 'reviewed' else 'artifact_verified'
                deadlines = []
                if expiry:
                    deadlines.append(_timestamp(expiry))
                if record.get('context_hash'):
                    deadlines.extend(relevant_fact_deadlines(context))
                if deadlines:
                    finding['decision_valid_until'] = min(deadlines).astimezone(timezone.utc).isoformat()
                finding['review_record_id'] = record.get('id')
                if lineage:
                    finding['release_lineage']['resolution'] = 'reviewed_package_specific_decision'
                break
        # Runtime facts only affect exposure, never software applicability by themselves.
        for fact in applicability_facts(context.get('runtime_facts', [])):
            if fact.get('scope_id') != finding['scope_id'] or fact.get('component_id') != finding['component_id']:
                continue
            if fact.get('name') != 'exposure' or fact.get('status') != 'observed':
                continue
            if fact.get('inventory_digest') != context.get('inventory_digest') or not context.get('inventory_digest'):
                continue
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(fact['collected_at'].replace('Z', '+00:00'))).total_seconds()
                ttl = min(int(fact.get('ttl_seconds', 300)), 3600)
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= age <= ttl and fact.get('value') in {'reachable', 'constrained', 'unknown'}:
                finding['exposure'] = fact['value']
                finding['exposure_valid_until'] = (_timestamp(fact['collected_at']) + timedelta(seconds=ttl)).astimezone(timezone.utc).isoformat()
                if fact.get('id'):
                    finding['evidence_ids'] = sorted(set(finding['evidence_ids'] + [fact['id']]))
        # Version order validates candidate upgrade direction; it is not a standalone safe-update verdict.
        fixes = []
        ecosystem = component.get('ecosystem') or ('deb' if purl.startswith('pkg:deb/') else None)
        if ecosystem in {'deb', 'dpkg'}:
            for version in finding.get('fixed_versions', []):
                try:
                    if compare_versions('deb', component.get('source_version') or finding['affected_version'], version) < 0:
                        fixes.append(version)
                except (EvidenceToolError, OSError):
                    pass
        finding['candidate_fixed_versions'] = fixes
        finding['remediation_eligible'] = (finding['applicability'] == 'affected'
                                           and finding.get('decision_basis') != 'inventory_advisory_match')
        finding['rationale'] = finding['justification'] = rationale
        finding['vex_verdict'] = finding['applicability'] if finding['applicability'] in {'fixed', 'not_affected'} else None
        return finding

    def assess(self, vulnerabilities, sonic_version, device_context):
        recommendations = []
        for item in vulnerabilities:
            score = item.get('cvss_score')
            if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10):
                raise ValueError('cvss_score must be null or a number between 0 and 10')
            # This compatibility endpoint receives caller claims, not a trusted scanner report
            # or verified artifact binding. Never accept extra fields as match/patch evidence.
            finding = {key: item.get(key) for key in ('cve_id', 'package_name', 'affected_version', 'severity', 'cvss_score')}
            finding.update(scope_id='unbound', component_id=item.get('package_name', 'unknown'), evidence_ids=[], fixed_versions=[])
            recommendations.append(self.evaluate(finding, None, {}))
        return {'recommendations': recommendations, 'cached': False}
