"""Select scoped Debian maintenance candidates without equating version with safety.

Inputs are server-owned findings and signature-verified RepositoryCatalog rows.
No commands execute on switches. Every returned option still requires the agent's
signed APT, dependency, rollback and SONiC health preflight before application.
"""
from functools import cmp_to_key
import re

from .source_tools import compare_versions
from .sbom_parser import stable_id


class MaintenancePolicyError(ValueError):
    pass


PREFLIGHT = [
    'Confirm the authorized device and exact package target; apply the switch maintenance_checks_enabled policy',
    'Use configured APT repository trust; additional catalog and artifact hash enforcement follows the switch check policy',
    'Select exact authorized package/version artifacts and retain their identities',
    'Simulate the dependency transaction; enforce optional dependency restrictions only when checks are enabled',
    'Attempt to retain previous packages; missing rollback artifacts block staging only when checks are enabled',
    'Validate SONiC services, routing, interfaces and resource health when maintenance checks are enabled',
    'Enforce operating mode, maintenance approval and required restart/reboot policy',
]


def _identity(finding):
    component = finding.get('component') or {}
    return (finding.get('scope_id') or finding.get('scope') or 'host',
            finding.get('package_name') or component.get('name'), finding.get('affected_version') or component.get('version'))


def _floors(findings):
    result = []
    for finding in findings:
        component = finding.get('component') or {}
        ecosystem = component.get('ecosystem')
        if ecosystem and ecosystem not in {'deb', 'dpkg', 'debian'}:
            raise MaintenancePolicyError('This policy supports Debian APT packages only')
        package = _identity(finding)[1]
        versions = finding.get('candidate_fixed_versions') or finding.get('fixed_versions') or []
        if not isinstance(versions, list) or not versions:
            raise MaintenancePolicyError(f"No applicable advisory fix floor for {finding.get('cve_id')}")
        cleaned = sorted(set(versions), key=cmp_to_key(lambda a, b: compare_versions('deb', a, b)))
        source = component.get('source_name') or finding.get('source_name')
        result.append({'cve_id': finding['cve_id'], 'versions': cleaned, 'package_name': package,
                       'basis': 'source' if source else 'binary', 'source_name': source,
                       'installed_source_version': component.get('source_version') or finding.get('source_version'),
                       'namespace': finding.get('advisory_namespace')})
    return result


def _catalog_candidates(value):
    """Accept catalog package rows or explicitly verified server-normalized candidates."""
    if value is None:
        return [], 'unknown'
    if isinstance(value, dict):
        rows = value.get('packages', [value])
        globally_complete = value.get('coverage', {}).get('complete', True)
    elif isinstance(value, list):
        rows, globally_complete = value, True
    else:
        raise MaintenancePolicyError('Repository candidates must be catalog rows')
    accepted = []
    for row in rows:
        if not isinstance(row, dict):
            raise MaintenancePolicyError('Malformed repository candidate')
        candidate = row.get('candidate') or row
        verified = (row.get('verified') is True or
                    (row.get('status') == 'available' and row.get('availability_basis') == 'signature-verified configured APT indices'))
        evidence_ids = row.get('evidence_ids') or candidate.get('evidence_ids') or ([candidate['evidence_id']] if candidate.get('evidence_id') else [])
        # The catalog verifies these cryptographically. This helper checks that the
        # verified evidence and package checksum survived the internal handoff.
        if (not globally_complete or not verified or not isinstance(evidence_ids, list) or not evidence_ids
                or any(not isinstance(eid, str) or not eid or len(eid) > 256 for eid in evidence_ids)):
            continue
        if not re.fullmatch(r'[0-9a-fA-F]{64}', candidate.get('sha256', '')):
            continue
        accepted.append({**candidate, 'evidence_ids': list(evidence_ids), 'repository_availability': 'verified_index'})
    return accepted, 'verified_index' if accepted else 'unknown'


def _comparison_version(candidate, floor, package_name):
    if floor['basis'] == 'binary':
        return candidate['version']
    source_name = candidate.get('source_name')
    source_version = candidate.get('source_version')
    if not source_name and floor['source_name'] == package_name and not re.search(r'\+b\d+$', candidate['version']):
        source_name, source_version = package_name, candidate['version']
    if source_name != floor['source_name'] or not source_version:
        raise MaintenancePolicyError('Repository candidate lacks matching source-package/version evidence')
    return source_version


def _validate_recheck(validator, candidate, findings, scope):
    if validator is None:
        return {'status': 'not_run', 'reason': 'A current-database target recheck is required before final remediation approval'}
    try:
        result = validator(candidate, findings)
    except Exception as exc:
        raise MaintenancePolicyError('Target recheck failed: ' + str(exc)[:300]) from exc
    if not isinstance(result, dict):
        raise MaintenancePolicyError('Target validator must return structured scan evidence')
    target = result.get('target') or {}
    if target.get('package_name') != candidate['name'] or target.get('version') != candidate['version'] or target.get('scope_id') != scope:
        raise MaintenancePolicyError('Target recheck is not bound to the exact candidate and scope')
    if candidate.get('architecture') and target.get('architecture') != candidate['architecture']:
        raise MaintenancePolicyError('Target recheck architecture does not match candidate')
    for field in ('source_name', 'source_version'):
        if candidate.get(field) and target.get(field) != candidate[field]:
            raise MaintenancePolicyError('Target recheck source identity does not match repository metadata')
    scanner = result.get('scanner') or {}
    revision = scanner.get('db_revision')
    if (not result.get('coverage', {}).get('complete') or not revision
            or result.get('current_db_revision') != revision or scanner.get('status') not in {'complete', 'ready'}):
        raise MaintenancePolicyError('Target recheck is partial or its advisory database is not current')
    if not isinstance(result.get('findings'), list):
        raise MaintenancePolicyError('Target recheck has no findings array')
    selected = {finding['cve_id'] for finding in findings}
    remaining = set()
    other = set()
    for match in result['findings']:
        ids = {match.get('cve_id') or match.get('vulnerability', {}).get('id')}
        ids.update(v.get('id') for v in match.get('related_vulnerabilities', match.get('relatedVulnerabilities', [])))
        remaining.update(ids & selected)
        other.update(ids - selected - {None})
    if remaining:
        raise MaintenancePolicyError('Selected CVEs remain or were reintroduced: ' + ', '.join(sorted(remaining)))
    return {'status': 'passed', 'db_revision': revision, 'target': target,
            'evidence_ids': result.get('evidence_ids', []), 'result_digest': stable_id(result),
            'other_cves': sorted(other), 'meaning': 'Selected advisory matches absent; compatibility and deployment safety still require agent preflight'}


def resolve_maintenance_targets(findings, repository_candidates=None, requested_version=None, validator=None):
    """Return reviewed options, never an assertion that installing them is safe.

    A validator(candidate, findings) may return a central scan response plus
    ``target={package_name,version,scope_id,architecture}`` and
    ``current_db_revision``. Complete coverage, current DB identity and absence
    of every selected CVE are checked here. A malformed/negative check rejects
    the candidate. Without a validator, an available candidate remains pending.
    """
    if not isinstance(findings, list) or not findings or len(findings) > 100:
        raise MaintenancePolicyError('Select 1..100 findings for one package occurrence')
    identities = {_identity(finding) for finding in findings}
    if len(identities) != 1:
        raise MaintenancePolicyError('All findings must share the same scope, package and installed binary version')
    for field in ('device_id', 'inventory_digest'):
        if len({f[field] for f in findings if f.get(field)}) > 1:
            raise MaintenancePolicyError('Findings from different devices or inventories cannot share a maintenance target')
    scope, package_name, installed = next(iter(identities))
    if not package_name or not installed:
        raise MaintenancePolicyError('Package name and installed version are required')
    floors = _floors(findings)
    applicability_review_required = any(finding.get('decision_basis') == 'inventory_advisory_match' for finding in findings)
    catalog, availability = _catalog_candidates(repository_candidates)
    if len(catalog) > 64:
        raise MaintenancePolicyError('Pass at most 64 repository candidates for the selected package')
    options, rejected = [], []
    component = findings[0].get('component') or {}
    architecture = component.get('arch') or component.get('architecture')
    for candidate in catalog:
        candidate = {**candidate, 'name': candidate.get('name') or candidate.get('package_name')}
        version = candidate.get('version')
        try:
            if candidate['name'] != package_name:
                raise MaintenancePolicyError('Repository candidate is for a different binary package')
            if architecture and candidate.get('architecture') not in {architecture, 'all'}:
                raise MaintenancePolicyError('Repository candidate architecture is incompatible')
            if compare_versions('deb', installed, version) >= 0:
                raise MaintenancePolicyError('Candidate is not newer than installed binary version')
            for floor in floors:
                compared = _comparison_version(candidate, floor, package_name)
                # Multiple floors can represent different branches. Requiring every
                # applicable floor is conservative; a source-aware recheck is still needed.
                if any(compare_versions('deb', compared, threshold) < 0 for threshold in floor['versions']):
                    raise MaintenancePolicyError('Candidate is below a selected advisory fix floor')
            check = _validate_recheck(validator, candidate, findings, scope)
            options.append({**candidate, 'version': version, 'status': 'recheck_passed' if check['status'] == 'passed' else 'recheck_required',
                            'comparison_basis': floors, 'central_recheck': check, 'agent_preflight_required': True,
                            'execution_eligible': False})
        except (ValueError, OSError, TypeError, KeyError) as exc:
            rejected.append({'version': version, 'reason': str(exc)})
    if not catalog:
        # An exact shared advisory target can be staged explicitly when no catalog
        # is configured, but its presence in an advisory never proves availability.
        common = set(floors[0]['versions'])
        for floor in floors[1:]:
            common.intersection_update(floor['versions'])
        for version in common:
            if any(floor['basis'] == 'source' and floor['source_name'] != package_name for floor in floors):
                # Source fix versions cannot silently become binary install versions.
                continue
            if compare_versions('deb', installed, version) < 0:
                options.append({'name': package_name, 'version': version, 'status': 'candidate_only',
                    'repository_availability': 'unknown', 'evidence_ids': [], 'comparison_basis': floors,
                    'central_recheck': {'status': 'not_run'}, 'agent_preflight_required': True, 'execution_eligible': False})
    # Deduplicate identical binary targets and use Debian ordering, including epochs.
    unique = {}
    for option in options:
        unique.setdefault((option['version'], option.get('architecture'), option.get('sha256')), option)
    options = sorted(unique.values(), key=cmp_to_key(lambda a, b: compare_versions('deb', a['version'], b['version'])))
    if requested_version is not None and requested_version not in {option['version'] for option in options}:
        raise MaintenancePolicyError('Requested version is not an eligible verified repository option or exact common advisory candidate')
    if requested_version is not None and len({option.get('sha256') for option in options if option['version'] == requested_version}) > 1:
        raise MaintenancePolicyError('Requested version has multiple repository artifacts; resolve the exact package identity first')
    target = requested_version or (options[0]['version'] if len(options) == 1 else None)
    return {'target_version': target, 'target_options': options, 'repository_availability': availability,
            'evidence_basis': {'advisory_floors': floors, 'repository_evidence_ids': sorted({eid for option in options for eid in option['evidence_ids']})},
            'required_agent_preflight': list(PREFLIGHT), 'rejected_candidates': rejected,
            'applicability_review_required': applicability_review_required,
            'applicability_review_reason': ('Inventory/advisory matching without verified build evidence requires a scoped operator applicability review before approval'
                                            if applicability_review_required else None),
            'compatibility': 'unverified; no version comparison or scanner result establishes SONiC operational compatibility'}
