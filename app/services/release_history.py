"""Atomic release projections and append-only assessment/evidence history."""
import copy
from contextlib import contextmanager

from sqlalchemy import select

from app.db.store import Record, now, stable_hash
from .assessment import RULESET_VERSION
from .package_metadata import package_fields


def release_assessment_identity(release):
    """Inputs whose replacement makes an in-flight release assessment stale."""
    return {key:copy.deepcopy(release.get(key)) for key in (
        'artifact_id','sbom_source','source_revision','resolved_commit','repositories','assessment_revision',
        'assessment_build_evidence_policy','assessment_policy_revision')}


def _append(session, kind, ident, payload, owner=None):
    existing = session.get(Record,(kind,ident))
    if existing is not None:
        if existing.payload != payload:raise ValueError('Immutable assessment history cannot be replaced')
        return
    instant = now()
    session.add(Record(kind=kind,id=ident,owner=owner,created_at=instant,updated_at=instant,payload=payload))


def _history(session, finding, result, kind, source_revision):
    digests = []
    for evidence in finding.get('evidence',[]):
        digest = stable_hash(evidence)
        _append(session,'evidence_snapshot',digest,evidence)
        digests.append(digest)
    ident = stable_hash(['release',finding['release_id'],finding['assessment_revision'],finding['id']])
    payload = {key:copy.deepcopy(value) for key,value in finding.items() if key != 'evidence'}
    payload.update(id=ident,finding_id=finding['id'],release_finding_id=finding['id'],recorded_at=finding['assessed_at'],
                   assessment_kind=kind,source_revision=source_revision,
                   scanner=copy.deepcopy(result.get('scanner',{})),evidence_digests=digests)
    _append(session,'release_assessment_history',ident,payload,finding['id'])


@contextmanager
def _guarded_session(store, identity_guard):
    # Call runtime/configuration guards before opening the write transaction:
    # their read sessions must not roll back a shared in-memory SQLite connection.
    with store.lock:
        if identity_guard is not None and not identity_guard():
            yield None
            return
        with store.sessions.begin() as session:yield session


def commit_release_assessment(store, release_id, result, revision, *, expected_identity, artifact_id,
                              source_revision=None, package_records=None, release_updates=None,
                              complete_scan=False, assessment_kind='scan', observed_at=None, identity_guard=None):
    """Commit only if release identity still matches, including prior revision.

Full scans may mark omissions no_longer_reported; AI retries never infer absence.
The latest projections, every assessed revision and exact evidence snapshots are
committed in one transaction. An existing immutable row is never overwritten.
"""
    instant = observed_at or now()
    with _guarded_session(store,identity_guard) as session:
        if session is None:return False
        release = session.get(Record,('release',release_id),with_for_update=True)
        if release is None or release_assessment_identity(release.payload) != expected_identity:return False
        policy_record = session.get(Record,('status','ruleset'))
        policy_revision = policy_record.payload.get('policy_revision') if policy_record else None
        packages = {row.payload.get('component_id'):copy.deepcopy(row.payload) for row in session.scalars(
            select(Record).where(Record.kind=='package',Record.owner==release_id))
            if row.payload.get('artifact_id') == artifact_id}
        if package_records is not None:
            packages = {}
            desired_packages = {package['id'] for package in package_records}
            replacements = {package['component_id']:package['id'] for package in package_records}
            for row in session.scalars(select(Record).where(Record.kind=='package',Record.owner==release_id)):
                if row.id not in desired_packages:
                    store._put(session,'package',row.id,{**row.payload,'status':'historical',
                        'replacement_package_id':replacements.get(row.payload.get('component_id'))
                        if row.payload.get('artifact_id')==artifact_id else None},release_id)
            for package in package_records:
                packages[package['component_id']] = copy.deepcopy(package)
                store._put(session,'package',package['id'],package,release_id)
        previous = {row.id:copy.deepcopy(row.payload) for row in session.scalars(
            select(Record).where(Record.kind=='release_finding',Record.owner==release_id))}
        legacy_by_occurrence = {}
        for ident,value in previous.items():
            if value.get('status')=='current':
                key=(value.get('artifact_id'),value.get('scope_id',value.get('scope')),value.get('component_id'),value.get('cve_id'))
                legacy_by_occurrence.setdefault(key,[]).append((ident,value))
        evidence_index = {item['id']:item for item in result.get('evidence',[]) if isinstance(item,dict) and item.get('id')}
        current, migrated = set(), set()

        def save(raw, ident, history_kind):
            old = previous.get(ident,{})
            embedded = {item.get('id'):item for item in raw.get('evidence',[]) if isinstance(item,dict)}
            evidence_ids = raw.get('evidence_ids') or list(embedded)
            proofs = []
            for evidence_id in evidence_ids:
                proof = evidence_index.get(evidence_id) or embedded.get(evidence_id)
                if proof is None:
                    stored = session.get(Record,('evidence',evidence_id))
                    proof = stored.payload if stored else None
                if proof is not None:proofs.append(copy.deepcopy(proof))
            finding = {**raw,'id':ident,'release_id':release_id,
                       'assessment_policy_revision':(raw.get('assessment_policy_revision')
                            if history_kind in ('disappearance','identity_migration') else policy_revision),
                       'artifact_id':raw.get('artifact_id',artifact_id) if history_kind in ('disappearance','identity_migration') else artifact_id,
                       'assessment_revision':revision,'assessed_at':instant,
                       'scan_revision':revision if history_kind=='scan' else old.get('scan_revision'),
                       'source_revision':source_revision,
                       'ruleset_version':raw.get('ruleset_version') or result.get('ruleset_version') or RULESET_VERSION,
                       'first_seen':old.get('first_seen',instant),'last_seen':instant,
                       'status':raw.get('status','current') if history_kind in ('disappearance','identity_migration') else 'current',
                       'evidence_ids':evidence_ids,'evidence':proofs}
            package = packages.get(finding.get('component_id'),finding.get('component') or {})
            availability = package.get('repository_availability') or {'status':'unknown'}
            finding.update(package_fields(package,finding,availability))
            _history(session,finding,result,history_kind,source_revision)
            store._put(session,'release_finding',ident,finding,release_id)
            old_catalog = session.get(Record,('package_cve',ident))
            catalog = {**(old_catalog.payload if old_catalog else {}),**finding,
                       'debian_release':finding.get('distro',{}).get('version'),
                       'installed_version':finding.get('affected_version'),
                       'available_fix_versions':finding.get('candidate_fixed_versions') or finding.get('fixed_versions',[]),
                       'latest_available_version':availability.get('latest_available_version'),
                       'repository_availability':availability,'latest_version_status':availability.get('status','unknown')}
            store._put(session,'package_cve',ident,catalog,release_id)
            return finding

        for raw in result.get('findings',[]):
            legacy = []
            if assessment_kind != 'scan':
                ident = raw.get('id')
                if ident not in previous:raise ValueError('Release retry finding is outside its committed release scope')
                if previous[ident].get('artifact_id') not in (None,artifact_id):
                    raise ValueError('Release retry finding belongs to a replaced artifact')
            else:
                ident = stable_hash([release_id,artifact_id,raw['scope_id'],raw['component_id'],raw['cve_id']])
                legacy = [(key,value) for key,value in legacy_by_occurrence.get(
                    (artifact_id,raw['scope_id'],raw['component_id'],raw['cve_id']),[]) if key!=ident]
                if legacy and ident not in previous:previous[ident]=legacy[0][1]
            current.add(ident)
            save(copy.deepcopy(raw),ident,assessment_kind)
            for old_id,old in legacy:
                save({**old,'status':'superseded_identity','replacement_finding_id':ident,
                      'resolution_basis':'Occurrence identifier migrated to include release scope; no fix is asserted.'},old_id,'identity_migration')
                migrated.add(old_id)
        if complete_scan:
            for ident,old in previous.items():
                if ident in current or ident in migrated or old.get('status') != 'current':continue
                missing = {**old,'status':'no_longer_reported','previous_applicability':old.get('applicability'),
                           'observed_artifact_id':artifact_id,
                           'applicability':'under_investigation','assessment_state':'analyzed',
                           'decision_basis':'scan_absence','decision_valid_until':None,
                           'resolution_basis':'Not reported by a complete release scan; absence does not establish a fix.',
                           'rationale':'Previously reported candidate is absent from this complete scan. No fix is asserted.'}
                save(missing,ident,'disappearance')
        # Aggregate only explicit per-version fixed verdicts for package rows;
        # available candidate versions are represented separately above.
        fixed_by_component = {}
        scan_revision = revision if assessment_kind=='scan' else release.payload.get('scan_revision')
        for row in session.scalars(select(Record).where(Record.kind=='package_cve',Record.owner==release_id)):
            value = row.payload
            if (scan_revision and value.get('scan_revision')==scan_revision
                    and value.get('artifact_id')==artifact_id and value.get('status')=='current'):
                # A partial scan leaves old rows available as last-known history;
                # they cannot advertise currently confirmed fixes in aggregates.
                fixed=package_fields(packages.get(value.get('component_id'),{}),value)['cves_fixed']
                fixed_by_component.setdefault(value.get('component_id'),set()).update(fixed)
        for component_id,package in packages.items():
            fixed = fixed_by_component.get(component_id,set())
            package['cves_fixed'] = sorted(fixed)
            if fixed:
                package.setdefault('field_unknown_reasons',{}).pop('cves_fixed',None)
                package.setdefault('field_evidence',{})['cves_fixed']={'basis':'current per-CVE fixed verdicts for this package version'}
            else:
                package.setdefault('field_evidence',{}).pop('cves_fixed',None)
                package.setdefault('field_unknown_reasons',{})['cves_fixed']=package_fields(package)['field_unknown_reasons']['cves_fixed']
            store._put(session,'package',package['id'],package,release_id)
        updates = copy.deepcopy(release_updates or {})
        updates.update(artifact_id=artifact_id,assessment_revision=revision,last_assessed_at=instant)
        if assessment_kind=='scan':updates['scan_revision']=revision
        store._put(session,'release',release_id,{**release.payload,**updates},release_id)
    return True
