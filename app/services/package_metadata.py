"""Evidence-based projections for the literal legacy package database fields.

These fields describe recorded metadata and decisions. Names, available update
versions and an LLM's self-reported score never establish package type, a source
repository, calibrated probability, or that an installed version fixes a CVE.
"""
from datetime import datetime
from urllib.parse import urlsplit

from .assessment import finding_decision_fresh


def package_fields(component=None, finding=None, repository=None):
    component, finding, repository = component or {}, finding or {}, repository or {}
    reasons, evidence = {}, {}
    package_type = None
    props = component.get('properties') if isinstance(component.get('properties'),dict) else {}
    explicit = props.get('smart-patch:package_type') or props.get('sonic:package_type')
    if explicit in {'library','application','service','devel'}:
        package_type = explicit
        evidence['package_type'] = {'basis':'explicit component property','value':explicit}
    elif component.get('metadata_type_source') == 'cyclonedx.type' and component.get('type') in {'library','application'}:
        package_type = component['type']
        evidence['package_type'] = {'basis':'CycloneDX component type','value':package_type}
    else:
        reasons['package_type'] = 'No explicit supported package category; package names and ecosystem are not category evidence.'
    repository_path = None
    for reference in component.get('external_references',[]):
        if not isinstance(reference,dict) or reference.get('type') != 'vcs':continue
        url = reference.get('url')
        if not isinstance(url,str):continue
        try:parsed = urlsplit(url)
        except ValueError:continue
        if parsed.scheme not in {'https','http','git'} or not parsed.hostname or parsed.username or parsed.password:continue
        repository_path = url
        evidence['repository_path'] = {'basis':'SBOM VCS external reference','reference':reference,
                                       'verification':'observed metadata; source checkout not implied'}
        break
    if repository_path is None:
        reasons['repository_path'] = 'No package-specific source repository reference; an APT binary path is not a source-code repository.'
    timestamp = finding.get('assessed_at')
    try:
        if not isinstance(timestamp,str) or datetime.fromisoformat(timestamp.replace('Z','+00:00')).tzinfo is None:
            raise ValueError('timezone required')
    except (ValueError,TypeError):
        timestamp = None
        reasons['analysis_timestamp'] = 'No completed assessment timestamp is recorded.'
    if timestamp:evidence['analysis_timestamp'] = {'basis':'recorded assessment','assessment_revision':finding.get('assessment_revision')}
    rationale = finding.get('rationale') or finding.get('justification') or None
    if rationale:evidence['justification_text'] = {'basis':'assessment rationale','evidence_ids':finding.get('evidence_ids',[])}
    else:reasons['justification_text'] = 'No assessment justification is recorded.'
    # Current providers do not publish validated calibration evidence. Keeping
    # this null is deliberate even when an uncalibrated legacy score is present.
    reasons['applicability_confidence'] = 'No validated probability calibration is available; provider self-reported confidence is not a calibrated probability.'
    cves_fixed = []
    cited = set(finding.get('evidence_ids') or [])
    embedded = {item.get('id') for item in finding.get('evidence',[]) if isinstance(item,dict)}
    if (finding.get('status','current') == 'current' and finding.get('applicability') == 'fixed'
            and finding.get('decision_basis') in {'operator_review','artifact_verified'}
            and finding.get('cve_id') and cited.intersection(embedded) and finding_decision_fresh(finding)):
        cves_fixed = [finding['cve_id']]
        evidence['cves_fixed'] = {'basis':'current evidence-backed fixed verdict for the assessed package version',
                                  'version':finding.get('affected_version'),'evidence_ids':sorted(cited.intersection(embedded))}
    else:
        reasons['cves_fixed'] = 'No current evidence-backed fixed verdict for this package version; candidate update versions do not prove an installed fix.'
    return {'package_type':package_type,'repository_path':repository_path,'applicability_confidence':None,
            'analysis_timestamp':timestamp,'justification_text':rationale,'cves_fixed':cves_fixed,
            'applicability_verdict':finding.get('applicability') or None,
            'field_evidence':evidence,'field_unknown_reasons':reasons}
