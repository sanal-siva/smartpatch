"""Central target rechecks; final installation remains gated by agent preflight."""
import copy
from urllib.parse import quote
from app.db.store import now, stable_hash
from .maintenance_policy import resolve_maintenance_targets


def repository_candidates(store,device,package_name):
    binding=store.get('build_binding',device.get('build_id',''))
    if not binding or binding.get('verification')!='signature_verified':return None
    release=store.get('release',binding['release_id'])
    if not release or release.get('artifact_id')!=binding.get('artifact_id'):return None
    records=store.list('package',owner=binding['release_id'])
    return [r['repository_availability'] for r in records if r.get('name')==package_name
            and r.get('artifact_id')==binding.get('artifact_id') and r.get('status')=='current' and r.get('repository_availability')]


def validate_plan_target(runtime,operation):
    plan_id=operation['arguments']['plan_id'];plan=runtime.store.get('plan',plan_id)
    if not plan:raise ValueError('Maintenance plan no longer exists')
    device=runtime.store.device(plan['device_id'])
    if (not device or device['inventory_digest']!=plan['inventory_digest'] or device['epoch']!=plan.get('inventory_epoch')
            or device.get('build_id')!=plan.get('build_id')):
        raise ValueError('Maintenance plan inventory or build changed')
    policy = runtime.configuration()
    if ((plan.get('build_evidence_policy') or 'required') != policy.get('build_evidence_policy', 'required')
            or plan.get('assessment_policy_revision') != policy.get('assessment_policy_revision')):
        raise ValueError('Maintenance assessment policy changed; create a new plan')
    original_plan_digest = stable_hash(plan)
    device_fields = ('inventory_digest', 'epoch', 'build_id', 'artifact_id', 'artifact_verified',
                     'binding_revision', 'review_revision', 'assessment_revision')
    captured_device = {key: device.get(key) for key in device_fields}

    def inputs_current():
        current_policy = runtime.configuration()
        current_device = runtime.store.device(plan['device_id']) or {}
        return (current_policy.get('build_evidence_policy', 'required') == policy.get('build_evidence_policy', 'required')
                and current_policy.get('assessment_policy_revision') == policy.get('assessment_policy_revision')
                and {key: current_device.get(key) for key in device_fields} == captured_device
                and stable_hash(runtime.store.get('plan', plan_id)) == original_plan_digest)
    findings=[runtime.store.get('finding',fid) for fid in plan['finding_ids']]
    if any(not finding for finding in findings):raise ValueError('A selected finding no longer exists')
    inventory=runtime.to_inventory(device)
    scope=next(s for s in inventory['scopes'] if s['id']==plan['scope'])
    observed=next(c for c in scope['components'] if c['name']==plan['package_name'])
    candidates=repository_candidates(runtime.store,device,plan['package_name'])
    requested=operation['arguments'].get('target_version') or plan.get('target_version')
    if candidates and requested:
        candidates=[c for c in candidates if (c.get('candidate') or c).get('version')==requested]
    if candidates and len(candidates)>5:
        raise ValueError('Choose one exact target version before the bounded central recheck')

    def validator(candidate,_findings):
        target=copy.deepcopy(observed)
        target.update(version=candidate['version'],source_name=candidate.get('source_name',candidate['name']),
                      source_version=candidate.get('source_version',candidate['version']),patches=[],custom_build=False)
        target['purl']='pkg:deb/debian/'+quote(candidate['name'],safe='')+'@'+quote(candidate['version'],safe='')
        target_scope={**scope,'components':[target]}
        before=runtime.pipeline.scanner.status()
        scanned=runtime.pipeline.scanner.scan_scope(target_scope)
        after=runtime.pipeline.scanner.status()
        database=scanned.get('scanner',{}).get('database',{})
        database=database.get('status',database) if isinstance(database,dict) else {}
        revision=database.get('checksum') or database.get('built') or database.get('schemaVersion')
        complete=bool(not scanned.get('missing_versions') and revision==before.get('db_revision')==after.get('db_revision'))
        identity={'package_name':candidate['name'],'version':candidate['version'],'scope_id':scope['id'],
                  'architecture':candidate.get('architecture'),'source_name':candidate.get('source_name'),
                  'source_version':candidate.get('source_version')}
        return {'target':identity,'coverage':{'complete':complete},'scanner':{'status':'complete' if complete else 'partial','db_revision':revision},
                'current_db_revision':after.get('db_revision'),'findings':scanned['findings'],
                'evidence_ids':[e['id'] for e in scanned.get('evidence',[])]}

    try:
        resolution=resolve_maintenance_targets(findings,candidates,requested,validator=validator)
        version=resolution['target_version']
        option=next((o for o in resolution['target_options'] if o['version']==version),None)
        eligible=bool(option and option['status'] in ('candidate_only','recheck_passed') and not plan['maintenance_required']
                      and not resolution.get('applicability_review_required')
                      and all(f.get('applicability')=='affected' for f in findings))
        plan={**plan,'target_version':version,'target_resolution':resolution,'staging_eligible':eligible,
              'execution_eligible':False,'approved':False,'status':'draft','updated_at':now(),
              'target_package_sha256':option.get('sha256') if option else None}
        if option and option['status']=='recheck_passed':
            plan['finding']={**plan['finding'],'fixed_versions':sorted(set(plan['finding'].get('fixed_versions',[])+[version])),
                             'target_validation':option['central_recheck']}
        with runtime.store.lock:
            if not inputs_current():
                raise ValueError('Maintenance plan or assessment policy changed during target validation')
            runtime.store.put('plan',plan_id,plan,plan['device_id'])
        runtime.store.audit('plan.target_checked','Maintenance target recheck completed',plan['device_id'],{'plan_id':plan_id,'target_version':version})
        return {'plan_id':plan_id,'target_resolution':resolution,'staging_eligible':eligible}
    except Exception as exc:
        with runtime.store.lock:
            if inputs_current():
                runtime.store.put('plan',plan_id,{**plan,'status':'validation_failed','execution_eligible':False,
                                  'staging_eligible':False,'validation_error':str(exc)[:1000]},plan['device_id'])
        raise
