"""Associate runtime occurrences with a verified release's scoped SBOM pedigree.

Version identity alone never transfers custom-build patch claims between scopes.
Unmatched drift remains explicitly unverified and cannot receive a stock-package
applicability verdict merely because the containing release is signed.
"""
import copy


def _image_name(value):
    return str(value).rsplit('/',1)[-1].split(':',1)[0].replace('.gz','').replace('-dbg','')


def bind_inventory(observed,baseline,manifest,artifact_id):
    result=copy.deepcopy(observed)
    matched=0;total=0;unresolved=[]
    for scope in result['scopes']:
        if scope['id']=='host':
            choices=[s for s in baseline['scopes'] if s['id']=='host']
        else:
            image=scope.get('image_digest')
            identities=[i for i in manifest.get('container_identities',[]) if image and i.get('image_digest')==image]
            names={_image_name(i.get('name')) for i in identities}
            names.update(_image_name(reference) for i in identities for reference in i.get('references',[]))
            choices=[s for s in baseline['scopes'] if s.get('kind')=='container' and
                     ((image and s.get('image_digest')==image) or _image_name(s.get('name')) in names)]
        baseline_scope=choices[0] if len(choices)==1 else None
        if baseline_scope is None:unresolved.append(scope['id'])
        for component in scope['components']:
            total+=1
            candidates=[]
            if baseline_scope:
                for package in baseline_scope['components']:
                    props=package.get('properties') or {}
                    arch=package.get('arch') or props.get('sonic:arch')
                    if (package.get('name')==component['name'] and package.get('version')==component['version']
                            and (not arch or arch==component.get('arch',component.get('architecture')))):
                        candidates.append(package)
            if len(candidates)!=1:
                component['custom_build']=True
                component['baseline_match_status']='ambiguous' if candidates else 'unverified_drift'
                continue
            package=candidates[0]
            component['purl']=package.get('purl') or component.get('purl','')
            component['patches']=copy.deepcopy(package.get('patches',[]))
            component['properties']={**package.get('properties',{}),**component.get('properties',{})}
            component['baseline_match_status']='matched'
            component['baseline_provenance']={'artifact_id':artifact_id,'scope_id':baseline_scope['id'],
                                              'component_ref':package.get('bom_ref') or package['id']}
            component['custom_build']=bool(component['patches']) or '/sonic/' in component['purl']
            matched+=1
    result['provenance_coverage']={'components_matched':matched,'components_total':total,'unresolved_scopes':unresolved}
    return result
