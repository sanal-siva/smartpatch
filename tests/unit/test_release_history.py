"""Synthetic in-memory release history/metadata tests; no real CVE claims."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from app.db.store import Store, now, stable_hash
from app.services.package_metadata import package_fields
from app.services.release_history import commit_release_assessment, release_assessment_identity


@pytest.fixture
def store():
    value=Store('sqlite://')
    value.put('release','release',{'release_id':'release','artifact_id':'artifact','source_revision':'source-one'})
    yield value
    value.close()


def finding(**changes):
    return {'scope_id':'host','component_id':'component','cve_id':'SYNTHETIC-HISTORY-NOT-A-CVE',
            'package_name':'testprobe','affected_version':'1.0','applicability':'under_investigation',
            'fixed_versions':['1.1'],'assessment_state':'analyzed','rationale':'Synthetic candidate, no verified fix',
            'evidence_ids':['scanner-proof'],**changes}


def result(value=None, proof='one'):
    return {'findings':[value or finding()], 'evidence':[{'id':'scanner-proof','type':'synthetic_fixture','value':proof}],
            'scanner':{'db_revision':'db1'},'coverage':{'complete':True},'errors':[],'ai_usage':{}}


def commit(store,value,revision,release_id='release',**kwargs):
    release=store.get('release',release_id)
    return commit_release_assessment(store,release_id,value,revision,
        expected_identity=release_assessment_identity(release),artifact_id=release['artifact_id'],
        source_revision=release.get('source_revision'),**kwargs)


def test_same_verdict_new_evidence_keeps_two_immutable_revisions(store):
    assert commit(store,result(),'first')
    first=copy.deepcopy(store.list('release_assessment_history')[0])
    assert commit(store,result(proof='changed evidence'),'second')
    histories=store.list('release_assessment_history')
    assert len(histories)==2 and len(store.list('evidence_snapshot'))==2
    assert store.get('release_assessment_history',first['id'])==first
    assert {row['applicability'] for row in histories}=={'under_investigation'}
    assert {row['assessment_revision'] for row in histories}=={'first','second'}
    assert {row['source_revision'] for row in histories}=={'source-one'}
    assert store.list('release_finding')[0]['evidence'][0]['value']=='changed evidence'
    for history in histories:
        assert store.get('evidence_snapshot',history['evidence_digests'][0])


def test_duplicate_revision_cannot_replace_history_or_partially_update_current_rows(store):
    assert commit(store,result(),'same')
    current=store.list('release_finding')[0]
    with pytest.raises(ValueError,match='Immutable'):
        commit(store,result(proof='attempted replacement'),'same')
    assert store.list('release_finding')[0]==current
    assert len(store.list('release_assessment_history'))==1
    assert len(store.list('evidence_snapshot'))==1


@pytest.mark.parametrize('field,value',[('artifact_id','new-artifact'),('source_revision','new-source'),('assessment_revision','other-worker')])
def test_stale_identity_cannot_commit_assessment_or_history(store,field,value):
    expected=release_assessment_identity(store.get('release','release'))
    store.put('release','release',{**store.get('release','release'),field:value})
    assert not commit_release_assessment(store,'release',result(),'stale',expected_identity=expected,artifact_id='artifact')
    assert store.list('release_finding')==[] and store.list('release_assessment_history')==[]


def test_runtime_policy_guard_is_checked_before_any_write(store):
    assert not commit(store,result(),'denied',identity_guard=lambda:False)
    assert store.list('release_assessment_history')==[] and store.list('evidence_snapshot')==[]


def test_same_artifact_in_two_releases_has_separate_findings_and_history(store):
    store.put('release','other',{'release_id':'other','artifact_id':'artifact'})
    assert commit(store,result(),'one')
    assert commit(store,result(),'two',release_id='other')
    first=store.list('release_finding',owner='release')[0]
    second=store.list('release_finding',owner='other')[0]
    assert first['id']!=second['id']
    assert len(store.list('release_assessment_history',owner=first['id']))==1
    assert len(store.list('release_assessment_history',owner=second['id']))==1


def test_partial_omission_stays_unresolved_and_complete_disappearance_never_claims_fixed(store):
    assert commit(store,result(finding(applicability='affected')),'initial')
    empty={'findings':[],'evidence':[],'coverage':{'complete':False}}
    assert commit(store,empty,'partial')
    assert store.list('release_finding')[0]['status']=='current'
    assert len(store.list('release_assessment_history'))==1
    assert commit(store,{**empty,'coverage':{'complete':True}},'complete',complete_scan=True)
    current=store.list('release_finding')[0]
    assert current['status']=='no_longer_reported'
    assert current['applicability']=='under_investigation' and current['previous_applicability']=='affected'
    assert current['cves_fixed']==[] and 'No fix' in current['rationale']
    assert store.list('package_cve')[0]['status']=='no_longer_reported'
    assert any(row['assessment_kind']=='disappearance' for row in store.list('release_assessment_history'))


def test_retry_refreshes_exact_evidence_and_history_without_cross_scope_insert(store):
    assert commit(store,result(),'scan')
    current=store.list('release_finding')[0]
    assert commit(store,result(current,proof='retry proof'),'retry',assessment_kind='ai_retry')
    assert store.list('release_finding')[0]['evidence'][0]['value']=='retry proof'
    assert {row['assessment_kind'] for row in store.list('release_assessment_history')}=={'scan','ai_retry'}
    with pytest.raises(ValueError,match='outside'):
        commit(store,result({**current,'id':'different-release-finding'}),'bad',assessment_kind='ai_retry')
    assert len(store.list('release_assessment_history'))==2


def test_fixed_projection_clears_when_later_evidence_no_longer_supports_fix(store):
    package={'id':'package','component_id':'component','artifact_id':'artifact','release_id':'release',
             'name':'testprobe','version':'1.0','type':'library','metadata_type_source':'cyclonedx.type','status':'current'}
    trusted=finding(applicability='fixed',decision_basis='artifact_verified')
    assert commit(store,result(trusted),'fixed',package_records=[package])
    assert store.get('package','package')['cves_fixed']==[trusted['cve_id']]
    assert commit(store,result(),'unknown')
    package=store.get('package','package')
    assert package['cves_fixed']==[]
    assert 'cves_fixed' not in package['field_evidence']
    assert package['field_unknown_reasons']['cves_fixed']


def test_legacy_ids_migrate_observed_occurrences_without_hiding_partial_omissions(store):
    legacy={**finding(),'id':'legacy-finding','artifact_id':'artifact','release_id':'release','status':'current',
            'first_seen':'2020-01-01T00:00:00Z'}
    store.put('release_finding','legacy-finding',legacy,'release')
    store.put('release_finding','unobserved',{**legacy,'id':'unobserved','component_id':'another'},'release')
    old_package={'id':'legacy-package','component_id':'component','artifact_id':'artifact','release_id':'release','status':'current'}
    store.put('package','legacy-package',old_package,'release')
    new_package={**old_package,'id':'scoped-package'}
    partial=result();partial['coverage']['complete']=False
    assert commit(store,partial,'migration',package_records=[new_package])
    assert store.get('package','legacy-package')['status']=='historical'
    assert store.get('package','legacy-package')['replacement_package_id']=='scoped-package'
    retired=store.get('release_finding','legacy-finding')
    assert retired['status']=='superseded_identity' and retired['cves_fixed']==[]
    current=store.get('release_finding',retired['replacement_finding_id'])
    assert current['status']=='current' and current['first_seen']=='2020-01-01T00:00:00Z'
    assert store.get('release_finding','unobserved')['status']=='current'


def test_package_metadata_uses_explicit_type_and_source_references_only():
    unknown=package_fields({'name':'lib-looks-like-library','type':'library'},repository={'candidate':{'filename':'pool/test.deb'}})
    assert unknown['package_type'] is None and unknown['repository_path'] is None
    assert unknown['field_unknown_reasons']['package_type']
    component={'type':'library','metadata_type_source':'cyclonedx.type',
               'external_references':[{'type':'vcs','url':'https://example.invalid/source'}]}
    known=package_fields(component)
    assert known['package_type']=='library' and known['repository_path']=='https://example.invalid/source'
    assert known['field_evidence']['repository_path']['verification'].startswith('observed')


def test_confidence_and_candidate_fix_versions_do_not_fabricate_probabilities_or_installed_fixes():
    unverified=finding(confidence=0.999,assessed_at=now(),applicability='fixed')
    fields=package_fields({},unverified)
    assert fields['applicability_confidence'] is None and fields['cves_fixed']==[]
    assert fields['analysis_timestamp']==unverified['assessed_at']
    assert fields['justification_text']==unverified['rationale']
    assert 'calibrat' in fields['field_unknown_reasons']['applicability_confidence']
    reviewed={**unverified,'decision_basis':'operator_review','decision_valid_until':'2000-01-01T00:00:00Z',
              'evidence':[{'id':'scanner-proof'}]}
    assert package_fields({},reviewed)['cves_fixed']==[]
    reviewed['decision_valid_until']=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
    assert package_fields({},reviewed)['cves_fixed']==[reviewed['cve_id']]


def test_subset_ai_revision_preserves_shared_scan_revision_and_unselected_finding(store):
    initial=result()
    initial['findings'].append(finding(component_id='second-component',package_name='second-testprobe'))
    assert commit(store,initial,'scan-one')
    rows=store.list('release_finding')
    selected,untouched=rows
    assert commit(store,result(selected,proof='additional AI evidence'),'ai-two',assessment_kind='ai_backlog')
    release=store.get('release','release')
    assert release['assessment_revision']=='ai-two' and release['scan_revision']=='scan-one'
    current=store.get('release_finding',selected['id'])
    assert current['assessment_revision']=='ai-two' and current['scan_revision']=='scan-one'
    assert store.get('release_finding',untouched['id'])==untouched
    assert untouched['scan_revision']==release['scan_revision']
    # A partial new scan advances scanner freshness only for reported rows.
    partial=result(finding(component_id=selected['component_id'],package_name=selected['package_name']))
    partial['coverage']['complete']=False
    assert commit(store,partial,'scan-three')
    assert store.get('release','release')['scan_revision']=='scan-three'
    assert store.get('release_finding',untouched['id'])['scan_revision']=='scan-one'
    assert store.get('release_finding',untouched['id'])['status']=='current'
