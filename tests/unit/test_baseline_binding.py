import copy
from app.services.baseline import bind_inventory


def fixtures():
    observed={'build_id':'build','scopes':[
        {'id':'host','kind':'host','components':[{'id':'host-lib','name':'libexample','version':'1.0','arch':'amd64'}]},
        {'id':'container:bgp','kind':'container','image_digest':'sha256:image',
         'components':[{'id':'container-lib','name':'libexample','version':'1.0','arch':'amd64'}]}]}
    baseline={'scopes':[
        {'id':'host','kind':'host','components':[{'id':'host-pkg','name':'libexample','version':'1.0','arch':'amd64',
         'purl':'pkg:deb/sonic/libexample@1.0','patches':[{'type':'unofficial','diff':{'url':'https://example.test/host-patch'}}]}]},
        {'id':'image-frr','kind':'container','name':'docker-fpm-frr','components':[{'id':'container-pkg','name':'libexample',
         'version':'1.0','arch':'amd64','purl':'pkg:deb/debian/libexample@1.0','patches':[]}]}]}
    manifest={'container_identities':[{'name':'docker-fpm-frr.gz','image_digest':'sha256:image','references':['docker-fpm-frr:latest']}]}
    return observed,baseline,manifest


def test_patch_pedigree_stays_in_its_exact_host_or_container_scope():
    observed,baseline,manifest=fixtures();original=copy.deepcopy(observed)
    result=bind_inventory(observed,baseline,manifest,'artifact')
    host=result['scopes'][0]['components'][0];container=result['scopes'][1]['components'][0]
    assert host['patches'] and host['custom_build'] is True
    assert container['patches']==[] and container['custom_build'] is False
    assert host['id']=='host-lib' and container['id']=='container-lib'
    assert observed==original
    assert result['provenance_coverage']['components_matched']==2


def test_changed_container_digest_cannot_inherit_same_named_build_evidence():
    observed,baseline,manifest=fixtures()
    observed['scopes'][1]['image_digest']='sha256:different-image'
    result=bind_inventory(observed,baseline,manifest,'artifact')
    component=result['scopes'][1]['components'][0]
    assert component['custom_build'] is True
    assert component['baseline_match_status']=='unverified_drift'
    assert 'baseline_provenance' not in component


def test_changed_package_or_ambiguous_baseline_abstains():
    observed,baseline,manifest=fixtures()
    observed['scopes'][0]['components'][0]['version']='2.0'
    baseline['scopes'][1]['components'].append(copy.deepcopy(baseline['scopes'][1]['components'][0]))
    result=bind_inventory(observed,baseline,manifest,'artifact')
    assert result['scopes'][0]['components'][0]['baseline_match_status']=='unverified_drift'
    assert result['scopes'][1]['components'][0]['baseline_match_status']=='ambiguous'
    assert result['provenance_coverage']['components_matched']==0
