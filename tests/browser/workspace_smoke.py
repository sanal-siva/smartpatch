"""Browser smoke tests. Mock mode never binds a port; live mode is read-only.

Run with the browser-capable test environment:
  python tests/browser/workspace_smoke.py --mock --output /tmp/smart-patch-ui-test
  python tests/browser/workspace_smoke.py --base-url https://100.104.17.32:8000 \
    --token-file .state/bootstrap-token --output /tmp/smart-patch-live-ui
Screenshots contain test fixtures in mock mode; never represent deployed scan results.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
NOW = '2026-09-30T06:30:00Z'
TEST_TOKEN = 'synthetic-browser-test-token'
ATTACK_TEXT = '<img src=x onerror="window.smartPatchXss=1">'


def fixtures():
    device = dict(id='test-switch',hostname='SYNTHETIC TEST SWITCH',ip_address='192.0.2.1',sonic_version='test-build',
                  build_id='test-build-identity',platform='test-platform',last_seen=NOW,inventory_digest='test-digest',
                  components_count=2,scopes_count=1,status='online',scan_status='completed',
                  resources={'collector_rss_bytes':123456},findings_counts={'affected':1,'under_investigation':1},
                  coverage={'complete':True},components=[{'name':'test-package','version':'1.0','scope':'host'}],facts=[],events=[])
    finding = dict(id='finding-test',device_id=device['id'],hostname=device['hostname'],cve_id='CVE-TEST-0001',
                   component_id='test-component',scope='host',package_name=ATTACK_TEXT,affected_version='1.0',
                   severity='HIGH',cvss_score=7.5,fixed_versions=['1.1'],applicability='affected',exposure='unknown',
                   build_evidence_policy='optional',decision_basis='inventory_advisory_match',artifact_binding='unverified',
                   remediation_eligible=False,action_type='defer',
                   rationale='Synthetic browser fixture; no real vulnerability assertion.',evidence=[{'id':'evidence-test',
                   'type':'test_observation','data':{'text':ATTACK_TEXT},'source':'browser test'}],assessed_at=NOW,source='fixture')
    return device,finding


def mock_routes(context, captured):
    device,finding = fixtures()
    settings = dict(ai_provider='openai',ai_model='test-model',ai_api_url='https://example.test/v1',ai_enabled=False,
                    ai_api_key_set=False,build_evidence_policy='required',source_roots=[],source_revision='',scan_interval_seconds=3600,
                    scanner_binary='/tools/grype',auth_required=True,alerts_enabled=True,alert_min_samples=20,alert_latency_p95_seconds=2,alert_cache_hit_rate_percent=70,alert_error_rate_percent=5,alert_queue_depth=100)
    tokens = []
    approval_control = {}
    plan_read_control = {}
    bulk_batch = {}
    bulk_control = {}
    maintenance_plan = {'id':'plan-staged-test','title':'Synthetic staged maintenance','device_id':device['id'],
        'hostname':device['hostname'],'scope':'host','package_name':'test-package','from_version':'1.0',
        'target_version':'1.1','finding_ids':['finding-test'],'inventory_digest':'test-digest',
        'created_at':NOW,'expires_at':'2099-01-01T00:00:00Z','status':'draft','approved':False,
        'staging_eligible':True,'execution_eligible':False,
        'target_resolution':{'repository_availability':'verified_index',
            'required_agent_preflight':['Verify signed package metadata','Stage exact rollback artifacts','Validate SONiC routing and service health'],
            'target_options':[{'version':'1.1','status':'candidate_only','repository_availability':'unknown','evidence_ids':[]},
                              {'version':'1.2','status':'recheck_required','repository_availability':'verified_index','evidence_ids':['repository-test']}]} }
    finding_records = [finding] + [{**finding,'id':f'finding-extra-{index}','cve_id':f'CVE-TEST-{index+1:04d}'} for index in range(1,51)]
    finding_records[1]['applicability']='under_investigation'
    finding_records[2].update(decision_basis='artifact_verified',artifact_binding='verified')
    finding_records += [{**finding, 'id': f'finding-no-fix-{index}', 'cve_id': f'CVE-NOFIX-{index:04d}',
                         'package_name': 'no-fix-package', 'fixed_versions': versions,
                         'candidate_fixed_versions': ['withheld-2.0'], 'applicability': 'under_investigation'}
                        for index, versions in enumerate(([], None, []))]
    finding_records[-1].pop('fixed_versions')
    payloads = {
      '/overview': {'summary':{'devices_total':1,'devices_online':1,'findings_affected':50,'findings_total':54,'findings_exposed':0,
             'findings_unknown':4,'findings_fixed':0,'coverage_pct':100,'scans_running':0,'queue_depth':0},
             'severity_counts':{'HIGH':54},'applicability_counts':{'affected':50,'under_investigation':4},
             'recent_events':[{'id':'event-test','type':'inventory.checkpoint','severity':'info','message':'Synthetic inventory received','created_at':NOW}],
             'scanner':{'status':'ready','version':'test','db_revision':'test-revision'},'ai':{'enabled':False,'requests':0,'tokens':0}},
      '/analytics':{'window_days':30,'package_trends':[{'date':'2026-09-30','components':2,'unique_packages':2,'devices':1}],'cve_trends':[{'date':'2026-09-30','affected':1,'under_investigation':1,'fixed':0,'not_affected':0,'unique_cves':1}],'severity_package_grid':[{'package_name':'test-package','critical':0,'high':1,'medium':0,'low':0,'unknown':0,'affected_devices':1,'occurrences':1}],'request_metrics':{'total_requests':0,'completed':0,'failed':0,'pending':0,'p95_duration_ms':None,'average_duration_ms':None,'cache_hit_rate':None,'cache_hits':0,'cache_misses':0},'current_inventory':{'components':2,'unique_packages':2,'devices':1},'package_type_breakdown':[{'package_type':'standard','components':2,'unique_packages':2,'devices':1}],'top_updated_packages':[{'package_name':'test-package','updates':2,'devices':1,'scopes':1,'last_updated':NOW,'latest_observed_version':'1.2'}],'package_change_coverage':{'complete':True,'first_recorded_change_at':NOW},'requests':[],'notes':['Synthetic test snapshots; no historical backfill.']},
      '/devices':{'devices':[device]},'/devices/test-switch':device,'/findings':{'findings':[finding]},
      '/findings/finding-test':finding,'/events':{'events':[]},'/changes':{'changes':[]},
      '/operations':{'operations':[]},'/plans':{'plans':[maintenance_plan]},'/releases':{'releases':[{'release_id':'custom:browser-fixture','artifact_id':'fixture-artifact','status':'imported'}]},'/settings':settings,
      '/tools':{'tools':[{'name':'compare_versions','description':'Compare Debian versions deterministically.',
          'input_schema':{'type':'object','properties':{'ecosystem':{'type':'string'},'installed':{'type':'string'},'other':{'type':'string'}},
                          'required':['ecosystem','installed','other']}}]},
    }
    payloads['/analytics'].update(cve_discovery_trends=[
        {'date':'2026-09-29','snapshot_time':'2026-09-29T00:00:00Z','first_seen_cves':2,'granularity':'day'},
        {'date':'2026-09-30','snapshot_time':'2026-09-30T00:00:00Z','first_seen_cves':1,'granularity':'day'}],
        cve_discovery_summary={'distinct_cves_in_window':3,'total_distinct_cves':8,
            'earliest_recorded_first_seen':'2026-09-20T00:00:00Z',
            'coverage':{'ledger_started_at':NOW,'history_complete':False}})
    def handler(route):
        request=route.request; path=urlparse(request.url).path
        if path.startswith('/api/v1/'):
            endpoint=path.removeprefix('/api/v1')
            body=request.post_data_json if request.method in ('POST','PUT','PATCH') and 'application/json' in request.headers.get('content-type','') else None
            captured.append({'path':endpoint,'query':parse_qs(urlparse(request.url).query),'method':request.method,'body':body,'authorization':request.headers.get('authorization')})
            if request.headers.get('authorization') != 'Bearer '+TEST_TOKEN:
                route.fulfill(status=401,json={'message':'Invalid test token'});return
            if endpoint == '/remediation-batches' and request.method == 'GET':
                route.fulfill(json={'batches': [bulk_batch] if bulk_batch else []});return
            if endpoint.startswith('/plans/bulk-plan-') and request.method=='GET':
                route.fulfill(json=next(entry['plan'] for entry in bulk_batch['entries'] if entry['plan_id']==endpoint.rsplit('/',1)[-1]));return
            if endpoint == '/remediation-batches' and request.method == 'POST':
                if bulk_control.get('create_error'):
                    route.fulfill(status=503,json={'detail':'Batch preview temporarily unavailable'});return
                entries=[]
                dispositions=['eligible','eligible','manual','review_required','no_fix','stale','offline']
                reasons=['Eligible host package','Eligible host package','Container packages require manual maintenance','Scoped finding review required','No fix recorded','Inventory changed; refresh the finding','Switch is offline']
                for index, (eligibility, reason) in enumerate(zip(dispositions,reasons)):
                    plan=dict(maintenance_plan, id=f'bulk-plan-{index}', device_id=f'bulk-switch-{index}', hostname=f'BULK SWITCH {index+1}', package_name='bulk-probe', status='draft', approved=False, staging_eligible=eligibility=='eligible', execution_eligible=False, scope='container:pmon' if index==2 else 'host', target_version='1.1', from_version='1.0')
                    plan.pop('execution_result',None);plan.pop('staging_result',None);plan.pop('reassessment',None)
                    plan['batch_id']='bulk-test'
                    plan['expires_at']='2099-01-01T00:00:00Z'
                    entries.append(dict(id=f'bulk-entry-{index}', plan_id=plan['id'] if eligibility!='no_fix' else None, device_id=plan['device_id'], hostname=plan['hostname'],finding_ids=[f'bulk-finding-{index}'],cve_ids=[f'CVE-BULK-{index:04d}'],package_name=plan['package_name'],scope=plan['scope'],from_version='1.0',target_version='1.1' if eligibility!='no_fix' else None,target_options=[{'version':'1.1','status':'candidate_only'},{'version':'1.2','status':'candidate_only'}],eligibility=eligibility,reason=reason,status='draft' if eligibility=='eligible' else 'blocked',plan=plan))
                bulk_batch.update(id='bulk-test',revision=1,status='draft',name='',created_at=NOW,entries=entries,max_concurrent_switches=body['max_concurrent_switches'],pause_on_failure=body['pause_on_failure'])
                route.fulfill(status=201,json=bulk_batch);return
            if endpoint.startswith('/remediation-batches/bulk-test'):
                operation=endpoint.rsplit('/',1)[-1]
                if request.method=='GET':route.fulfill(json=bulk_batch);return
                if bulk_control.get('error'):
                    code,message=bulk_control['error'];route.fulfill(status=code,json={'detail':message});return
                if body.get('expected_revision')!=bulk_batch['revision']:
                    route.fulfill(status=409,json={'detail':'Batch review is out of date. Refresh the batch.'});return
                bulk_batch['revision']+=1
                if request.method=='PATCH':
                    for key in ('name','max_concurrent_switches','pause_on_failure'):
                        if key in body:bulk_batch[key]=body[key]
                    for entry in bulk_batch['entries']:
                        if entry['id'] in body.get('target_versions',{}):
                            entry['target_version']=body['target_versions'][entry['id']];entry['plan']['target_version']=entry['target_version']
                elif operation=='refresh':pass
                elif operation=='approve-and-stage':
                    bulk_batch['status']='staging'
                    for entry in bulk_batch['entries']:
                        if entry['plan_id'] in body['confirmed_plan_ids']:
                            entry['status']='staging_queued';entry['plan'].update(status='staging_queued',approved=True)
                        elif entry['eligibility']=='eligible':entry['status']='excluded'
                elif operation=='execute':
                    expected=sorted(entry['device_id'] for entry in bulk_batch['entries'] if entry['plan_id'] in body['confirmed_plan_ids'])
                    assert sorted(body['confirmed_device_ids'])==expected
                    bulk_batch['status']='executing'
                    for entry in bulk_batch['entries']:
                        if entry['plan_id'] in body['confirmed_plan_ids']:entry['status']='queued';entry['plan']['status']='queued'
                elif operation=='pause':bulk_batch.update(status='paused',reason='Paused by an administrator. New dispatch is stopped; queued work may finish.')
                elif operation=='resume':bulk_batch.update(status='executing',reason='')
                elif operation=='stop':bulk_batch.update(status='stopped',reason='Remaining dispatch stopped; queued work may finish.')
                route.fulfill(json=bulk_batch);return
            if endpoint=='/analytics':
                days=int(parse_qs(urlparse(request.url).query).get('days',['30'])[0])
                resolution='hour' if days<=7 else 'day'
                response=json.loads(json.dumps(payloads['/analytics']))
                response.update(history_resolution=resolution,history_points=1,history_observations=1)
                for key in ('package_trends','cve_trends'):
                    for row in response[key]:row.update(granularity=resolution,snapshot_time=(NOW[:13]+':00:00Z') if resolution=='hour' else NOW[:10]+'T00:00:00Z',measured_at=NOW,observation_count=1,peak_affected=1)
                route.fulfill(json=response);return
            if endpoint=='/findings':
                query=parse_qs(urlparse(request.url).query)
                records=finding_records
                for key in ('applicability','severity','device_id'):
                    if query.get(key):records=[record for record in records if str(record.get(key,'')).lower()==query[key][0].lower()]
                if query.get('fix_available'):
                    wanted=query['fix_available'][0]=='true'
                    records=[record for record in records if bool(record.get('fixed_versions'))==wanted]
                if query.get('search'):records=[record for record in records if query['search'][0].lower() in json.dumps(record).lower()]
                offset=int(query.get('offset',['0'])[0]);limit=int(query.get('limit',['1000'])[0])
                route.fulfill(json={'findings':records[offset:offset+limit],'total':len(records)});return
            if endpoint=='/findings/finding-test/agent-session' and request.method=='POST':
                route.fulfill(json={'session_id':'agent-session-test','source':'codex_interactive','status':'open','created_at':NOW,
                    'expires_at':'2099-01-01T00:00:00Z','snapshot_hash':'synthetic-snapshot',
                    'snapshot':{'device_id':device['id'],'inventory_digest':'test-digest','epoch':'test-epoch','build_id':'test-build','source_revision':'a'*40,'artifact_verified':False},
                    'finding':dict(finding),'evidence':finding['evidence'],'tools':[],
                    'limits':{'max_tool_calls':12,'max_context_chars':16000,'max_response_chars':48000},
                    'submission_schema':{'required':['snapshot_hash','cve_id','component_id','scope_id','proposed_applicability','rationale','evidence_ids']}});return
            if endpoint=='/agent-sessions/agent-session-test/analysis' and request.method=='POST':
                finding['latest_external_analysis']={'id':'proposal-test','session_id':'agent-session-test','source':'codex_interactive',
                    'proposed_applicability':body['proposed_applicability'],'rationale':body['rationale'],
                    'evidence_ids':body['evidence_ids'],'review_required':True,'agent_identity_verified':False,'agent_name_origin':'self_reported','agent_name':'Synthetic agent','submitted_at':NOW}
                route.fulfill(json=finding['latest_external_analysis']);return
            if endpoint=='/findings/finding-test/review' and request.method=='POST':
                finding.update(applicability=body['applicability'],rationale=body['justification']);route.fulfill(json=finding);return
            if endpoint=='/releases' and request.method=='POST':
                payloads['/releases']['releases'].append({**body,'status':'configured'});route.fulfill(status=201,json=body);return
            if endpoint=='/artifacts/verify' and request.method=='POST':
                route.fulfill(json={'build_id':'sha256:fixture','verification':'signature_verified','binding_scope':'signed_release_baseline'});return
            if endpoint=='/tokens' and request.method=='POST':
                token={'id':'token-test','description':body['description'],'role':body['role'],'device_id':body.get('device_id'),'revoked':False}
                tokens.append(token);route.fulfill(status=201,json={'token':'synthetic-created-token','token_id':token['id']});return
            if endpoint=='/tokens':route.fulfill(json={'tokens':tokens});return
            if endpoint=='/settings' and request.method=='PUT':
                if 'build_evidence_policy' not in settings and 'build_evidence_policy' in body:
                    route.fulfill(status=422,json={'detail':'Unsupported configuration fields: build_evidence_policy'});return
                settings.update({k:v for k,v in body.items() if k!='ai_api_key'});settings['ai_api_key_set']=bool(body.get('ai_api_key'));route.fulfill(json=settings);return
            if endpoint.startswith('/tools/'):
                route.fulfill(json={'result':{'id':'test-evidence','data':{'comparison':1},'complete':True}});return
            if endpoint.endswith('/scan') or endpoint.endswith('/investigate'):
                route.fulfill(status=202,json={'operation_id':'test-operation','status':'queued'});return
            if endpoint=='/plans/plan-staged-test':
                if plan_read_control.get('hold'):
                    plan_read_control['held_route']=route;return
                route.fulfill(json=maintenance_plan);return
            if endpoint=='/plans/plan-staged-test/validate-target':
                maintenance_plan.update(status='validating_target',approved=False,staging_eligible=False,execution_eligible=False)
                route.fulfill(status=202,json={'operation_id':'target-recheck-test','status':'queued'});return
            if endpoint=='/plans/plan-staged-test/approve':
                if approval_control.get('error'):
                    status,message=approval_control['error']
                    route.fulfill(status=status,json={'detail':message});return
                if approval_control.get('hold'):
                    approval_control['held_route']=route;return
                maintenance_plan.update(status='approved',approved=True);route.fulfill(json=maintenance_plan);return
            if endpoint=='/plans/plan-staged-test/stage':
                maintenance_plan.update(status='staging_queued',stage_request_id='stage-test',execution_eligible=False)
                route.fulfill(status=202,json=maintenance_plan);return
            if endpoint=='/plans/plan-staged-test/execute':
                maintenance_plan.update(status='queued',action_request_id='apply-test')
                route.fulfill(status=202,json=maintenance_plan);return
            if endpoint=='/plans' and request.method=='POST':
                route.fulfill(status=201,json={'id':'plan-test','device_id':device['id'],'status':'draft','finding_ids':body['finding_ids'],'execution_eligible':False});return
            if endpoint in payloads:route.fulfill(json=payloads[endpoint]);return
            route.fulfill(status=404,json={'message':'No mock for '+endpoint});return
        if path.startswith('/ui/static/'):
            file=ROOT/'app/ui/static'/path.removeprefix('/ui/static/')
            route.fulfill(path=file,content_type='text/javascript' if file.suffix=='.js' else 'text/css');return
        if path.startswith('/ui'):
            page=path.removeprefix('/ui').strip('/') or 'overview'
            content=(ROOT/'app/ui/templates/workspace.html').read_text().replace('{{ page }}',page).replace('{{ asset_version }}','synthetic-test')
            route.fulfill(body=content,content_type='text/html',headers={'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"});return
        route.fulfill(status=404,body='Not found')
    context.route('**/*',handler)
    return {'overview':payloads['/overview'],'findings':finding_records,'maintenance_plan':maintenance_plan,'settings':settings,'approval_control':approval_control,'plan_read_control':plan_read_control,'bulk_batch':bulk_batch,'bulk_control':bulk_control}


def ready(page):
    page.locator('#page-content[aria-busy="false"]').wait_for()
    expect(page.locator("#last-updated")).to_contain_text("Updated")


def assert_modal_feedback_visible(page, message):
    """A CSS-visible body toast can still be hidden by a native modal's top layer."""
    alert=page.locator('#detail-dialog .dialog-feedback [role="alert"]')
    expect(alert).to_contain_text(message)
    expect(alert).to_be_visible()
    assert alert.evaluate('''node => {
        const box = node.getBoundingClientRect();
        const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
        return Boolean(hit && (node === hit || node.contains(hit)));
    }'''), 'The modal error is obscured or outside the visible viewport'


def exercise_bulk_workflow(page, mock_state, captured, output, screens):
    """Only synthetic routes: no real switch action or approval is submitted."""
    base_finding=mock_state['findings'][0]
    mock_state['findings'].extend(dict(base_finding,id=f'bulk-finding-{index}',device_id=f'bulk-switch-{index}',hostname=f'BULK SWITCH {index+1}',package_name='bulk-probe',cve_id=f'CVE-BULK-{index:04d}',fixed_versions=[] if index==4 else ['1.1']) for index in range(7))
    page.locator('a[data-nav="findings"]').click();ready(page)
    page.get_by_role('combobox',name='Fix availability').select_option('')
    page.get_by_placeholder('Search CVE, package, switch, or scope').fill('CVE-BULK')
    page.get_by_text('Showing 1–7 of 7',exact=True).wait_for()
    for checkbox in page.locator('.row-select').all():checkbox.check()
    mock_state['bulk_control']['create_error']=True
    page.get_by_role('button',name='Remediate selected switches',exact=True).click()
    expect(page.get_by_role('alert')).to_contain_text('Batch preview temporarily unavailable')
    mock_state['bulk_control'].clear()
    page.get_by_role('button',name='Remediate selected switches',exact=True).click()
    creation_requests=[item for item in captured if item['method']=='POST' and item['path']=='/remediation-batches']
    assert len(creation_requests)==2
    assert creation_requests[0]['body']['idempotency_key']==creation_requests[1]['body']['idempotency_key']
    expect(page.locator('.batch-detail')).to_contain_text('Container packages require manual maintenance')
    expect(page.locator('.batch-detail')).to_contain_text('Scoped finding review required')
    expect(page.locator('.batch-detail')).to_contain_text('No fix recorded')
    expect(page.locator('.batch-detail')).to_contain_text('Inventory changed; refresh the finding')
    expect(page.locator('.batch-detail')).to_contain_text('Switch is offline')
    expect(page.get_by_label('Switches at a time',exact=True)).to_have_value('1')
    expect(page.get_by_label('Pause new dispatch after a failure',exact=True)).to_be_checked()
    assert page.locator('.batch-detail input[type=checkbox]:disabled').count()==5
    assert not any(item['method']=='POST' and item['path'].endswith('/approve-and-stage') for item in captured)
    page.get_by_label('Target version for BULK SWITCH 1 bulk-probe',exact=True).select_option('1.2')
    expect(page.get_by_role('button',name='Approve and stage selected switches',exact=True)).to_be_disabled()
    page.get_by_role('button',name='Save target selections',exact=True).click()
    expect(page.get_by_label('Target version for BULK SWITCH 1 bulk-probe',exact=True)).to_have_value('1.2')
    page.get_by_label('Batch name',exact=True).fill('Synthetic multi-switch remediation')
    page.get_by_label('Switches at a time',exact=True).fill('2')
    page.get_by_role('button',name='Save batch settings',exact=True).click()
    expect(page.get_by_role('heading',name='Synthetic multi-switch remediation',exact=True)).to_be_visible()
    page.locator('#detail-dialog').evaluate('(dialog) => { dialog.scrollTop = 0; }')
    page.screenshot(path=str(output/'batch-preview.png'),full_page=True);screens.append('batch-preview.png')
    page.locator('.batch-entry-details').first.locator('summary').click()
    page.get_by_role('button',name='View plan',exact=True).first.click()
    expect(page.get_by_role('button',name='Back to batch',exact=True)).to_be_visible()
    expect(page.get_by_role('button',name='2 · Approve review',exact=True)).to_have_count(0)
    expect(page.get_by_role('button',name='3 · Stage packages',exact=True)).to_have_count(0)
    expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_have_count(0)
    page.get_by_role('button',name='Back to batch',exact=True).click()
    batch=mock_state['bulk_batch'];control=mock_state['bulk_control']
    def bulk_mutations():return [item for item in captured if item['method'] in ('POST','PATCH') and item['path'].startswith('/remediation-batches/')]
    control['error']=(403,'Administrator access is required to approve this batch.')
    page.get_by_role('button',name='Approve and stage selected switches',exact=True).click()
    assert_modal_feedback_visible(page,'Administrator access is required')
    control.clear()
    page.get_by_role('button',name='Approve and stage selected switches',exact=True).click()
    expect(page.locator('.batch-detail')).to_contain_text('Staging Queued')
    expect(page.get_by_role('button',name='Review execution for selected switches',exact=True)).to_be_disabled()
    stage=[item for item in captured if item['path'].endswith('/approve-and-stage')][-1]
    assert stage['body']['confirmed_plan_ids']==['bulk-plan-0','bulk-plan-1']
    batch['status']='ready'
    for entry in batch['entries'][:2]:
        entry['status']='staged';entry['plan'].update(status='staged',execution_eligible=True,
            staging_result={'value':{'status':'staged','details':{'maintenance_checks_enabled':False,'rollback_available':False,'checks_skipped':['pre_install_health'],'rollback_missing':[{'package':'bulk-probe','version':'1.0','reason':'Old package unavailable'}]}}})
    expect(page.locator('.batch-detail')).to_contain_text('Automatic rollback unavailable',timeout=8000)
    # Polling discovers readiness but never selects newly staged switches or executes them.
    expect(page.get_by_role('button',name='Review execution for selected switches',exact=True)).to_be_disabled()
    for index in range(2):page.get_by_label(f'Select BULK SWITCH {index+1} bulk-probe for execution',exact=True).check()
    page.get_by_role('button',name='Review execution for selected switches',exact=True).click()
    expect(page.locator('#detail-dialog')).to_contain_text('Maintenance checks disabled')
    expect(page.locator('#detail-dialog')).to_contain_text('Automatic rollback unavailable')
    page.get_by_label('Confirm selected switch execution',exact=True).fill('EXECUTE 1 SWITCHES')
    page.get_by_role('button',name='Request execution on selected switches',exact=True).click()
    assert_modal_feedback_visible(page,'Type EXECUTE 2 SWITCHES exactly')
    assert not any(item['path'].endswith('/bulk-test/execute') for item in captured)
    page.get_by_label('Confirm selected switch execution',exact=True).fill('EXECUTE 2 SWITCHES')
    control['error']=(409,'Batch review is out of date. Refresh the batch.')
    page.get_by_role('button',name='Request execution on selected switches',exact=True).click()
    assert_modal_feedback_visible(page,'Batch review is out of date')
    control.clear()
    page.get_by_role('button',name='Back to batch',exact=True).click()
    page.get_by_role('button',name='Review execution for selected switches',exact=True).click()
    page.get_by_label('Confirm selected switch execution',exact=True).fill('EXECUTE 2 SWITCHES')
    page.get_by_role('button',name='Request execution on selected switches',exact=True).click()
    expect(page.locator('.batch-detail')).to_contain_text('Executing')
    execution=[item for item in captured if item['path'].endswith('/bulk-test/execute')][-1]
    assert execution['body']['confirmed_plan_ids']==['bulk-plan-0','bulk-plan-1']
    assert execution['body']['confirmed_device_ids']==['bulk-switch-0','bulk-switch-1']
    # Restarting the browser view recovers the saved batch; it never replays commands.
    page.get_by_role('button',name='Close details').click()
    mutations=len(bulk_mutations())
    page.locator('a[data-nav="plans"]').click();ready(page)
    page.reload();ready(page)
    page.get_by_role('button',name='Review batch',exact=True).click()
    expect(page.locator('.batch-detail')).to_contain_text('Executing')
    assert len(bulk_mutations())==mutations
    page.get_by_role('button',name='Pause new dispatch',exact=True).click()
    expect(page.locator('#detail-dialog')).to_contain_text('does not interrupt an installation')
    page.get_by_role('button',name='Confirm pause',exact=True).click()
    expect(page.get_by_role('button',name='Resume new dispatch',exact=True)).to_be_visible()
    # Collector failure stays explicit and is not replayed by polling or resume.
    batch['entries'][0].update(status='failed',reason='Inspect the collector result and current inventory')
    batch['entries'][0]['plan'].update(status='failed',execution_eligible=False,execution_result={'value':{'status':'failed','details':{'error':'Package manager failed; inspect the switch'}}})
    batch['entries'][1].update(status='pending_reassessment')
    batch['entries'][1]['plan'].update(status='pending_reassessment',execution_eligible=False,
        execution_result={'value':{'status':'pending_reassessment','details':{'maintenance_checks_enabled':False,'rollback_available':False,'post_validation':{'status':'SKIPPED'}}}})
    expect(page.locator('.batch-detail')).to_contain_text('Package manager failed; inspect the switch',timeout=8000)
    expect(page.locator('.batch-detail')).to_contain_text('Pending Reassessment')
    page.screenshot(path=str(output/'batch-paused-progress.png'),full_page=True);screens.append('batch-paused-progress.png')
    execute_count=sum(item['path'].endswith('/bulk-test/execute') for item in captured)
    page.get_by_role('button',name='Resume new dispatch',exact=True).click()
    expect(page.locator('#detail-dialog')).to_contain_text('Failed or denied execution will not be retried')
    page.get_by_role('button',name='Confirm resume',exact=True).click()
    expect(page.get_by_role('button',name='Pause new dispatch',exact=True)).to_be_visible()
    assert sum(item['path'].endswith('/bulk-test/execute') for item in captured)==execute_count
    page.get_by_role('button',name='Stop remaining dispatch',exact=True).click()
    expect(page.locator('#detail-dialog')).to_contain_text('cannot cancel actions already queued')
    page.get_by_role('button',name='Confirm stop',exact=True).click()
    expect(page.locator('.batch-detail .badge').first).to_have_text('Stopped')
    expect(page.get_by_role('button',name='Review execution for selected switches',exact=True)).to_have_count(0)
    terminal_reads=sum(item['method']=='GET' and item['path']=='/remediation-batches/bulk-test' for item in captured)
    page.wait_for_timeout(5300)
    assert sum(item['method']=='GET' and item['path']=='/remediation-batches/bulk-test' for item in captured)==terminal_reads
    page.get_by_role('button',name='Close details').click()


def run(args):
    output=Path(args.output);output.mkdir(parents=True,exist_ok=True)
    errors=[];captured=[];screens=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
        context=browser.new_context(viewport={'width':1440,'height':1060},ignore_https_errors=args.mock or args.allow_untrusted_test_tls)
        mock_state=mock_routes(context,captured) if args.mock else None
        page=context.new_page();page.on('pageerror',lambda error:errors.append(str(error)))
        base='https://smart-patch.test' if args.mock else args.base_url.rstrip('/')
        page.goto(base+'/ui/')
        page.get_by_role('button',name='Connect securely').click()
        token=TEST_TOKEN if args.mock else Path(args.token_file).read_text().strip()
        page.get_by_label('Smart Patch service token').fill(token)
        page.get_by_role('button',name='Connect to workspace').click();ready(page)
        assert page.locator('#connection-state').get_attribute('class').endswith('connected')
        assert page.evaluate("localStorage.getItem('smart_patch_admin_token')") is None
        assert page.evaluate("sessionStorage.getItem('smart_patch_admin_token')") == token
        page.screenshot(path=str(output/'overview-light.png'),full_page=True);screens.append('overview-light.png')
        page.get_by_role('button',name='Switch to dark theme').click()
        assert page.locator('html').get_attribute('data-theme')=='dark'
        page.screenshot(path=str(output/'overview-dark.png'),full_page=True);screens.append('overview-dark.png')
        page.get_by_role('button',name='Switch to light theme').click()
        for view in ['fleet','findings','coverage','changes','plans','jobs','tools','releases','settings','tokens','packages-trends','cve-trends','request-status']:
            page.locator(f'a[data-nav="{view}"]').click();ready(page)
            assert not page.get_by_role('heading',name='This view is unavailable').count(),view
            if args.mock and view=='fleet':
                page.get_by_role('button',name='Inspect',exact=False).first.click()
                page.get_by_role('button',name='Queue central scan').click()
                page.get_by_role('button',name='Close details').click()
            if args.mock and view=='findings':
                expect(page.get_by_role('combobox',name='Fix availability')).to_have_value('true')
                expect(page.get_by_role('row').filter(has_text='CVE-NOFIX-')).to_have_count(0)
                assert page.get_by_text(ATTACK_TEXT,exact=True).count()>0
                inventory_row=page.get_by_role('row').filter(has=page.get_by_text('CVE-TEST-0001',exact=True))
                expect(inventory_row).to_contain_text('Affected')
                expect(inventory_row).to_contain_text('Inventory advisory match · build unverified')
                verified_row=page.get_by_role('row').filter(has=page.get_by_text('CVE-TEST-0003',exact=True))
                expect(verified_row).not_to_contain_text('Inventory advisory match')
                page.get_by_role('button',name='Next',exact=True).click()
                page.get_by_text('Showing 51–51 of 51',exact=True).wait_for()
                page.get_by_role('combobox',name='Fix availability').select_option('false')
                page.get_by_text('Showing 1–3 of 3',exact=True).wait_for()
                expect(page.get_by_role('row').filter(has_text='CVE-NOFIX-')).to_have_count(3)
                expect(page.get_by_role('cell',name='No fix recorded',exact=False)).to_have_count(3)
                expect(page.get_by_role('button',name='Previous',exact=True)).to_be_disabled()
                page.get_by_role('combobox',name='All applicability').select_option('affected')
                page.get_by_text('0 records',exact=True).wait_for()
                page.get_by_role('combobox',name='All applicability').select_option('')
                page.get_by_text('Showing 1–3 of 3',exact=True).wait_for()
                page.get_by_role('combobox',name='Fix availability').select_option('')
                page.get_by_text('Showing 1–50 of 54',exact=True).wait_for()
                page.get_by_role('button',name='Next',exact=True).click()
                page.get_by_text('Showing 51–54 of 54',exact=True).wait_for()
                expect(page.get_by_role('row').filter(has_text='CVE-NOFIX-')).to_have_count(3)
                page.get_by_role('combobox',name='Fix availability').select_option('true')
                page.get_by_text('Showing 1–50 of 51',exact=True).wait_for()
                finding_queries=[item['query'] for item in captured if item['path']=='/findings' and item['query'].get('limit')==['50']]
                assert finding_queries[0]['fix_available']==['true']
                assert any(query.get('fix_available')==['false'] and query.get('offset')==['0'] for query in finding_queries)
                assert any('fix_available' not in query for query in finding_queries)
                page.get_by_role('button',name='Inspect CVE-TEST-0001').click()
                assert page.locator('#detail-content img').count()==0
                assert page.evaluate('window.smartPatchXss') is None
                expect(page.locator('.detail-field').filter(has_text='Assessment basis')).to_contain_text('Inventory Advisory Match')
                expect(page.locator('.detail-field').filter(has_text='Build provenance')).to_contain_text('Unverified')
                expect(page.locator('.detail-field').filter(has_text='Build evidence policy')).to_contain_text('Optional')
                expect(page.locator('#detail-content')).to_contain_text('does not authorize automatic installation')
                page.screenshot(path=str(output/'finding-evidence.png'),full_page=True);screens.append('finding-evidence.png')
                page.get_by_role('button',name='External agent review',exact=True).click()
                page.get_by_role('heading',name='Use your signed-in agent',exact=True).wait_for()
                expect(page.locator('#detail-content')).to_contain_text('creating a session does not run a model or change the finding')
                assert page.get_by_role('button',name='Sign in with OpenAI',exact=True).count()==0
                with page.expect_download() as download_info:
                    page.get_by_role('button',name='Download case bundle',exact=True).click()
                download=download_info.value;download.save_as(output/'external-agent-case.json')
                bundle=json.loads((output/'external-agent-case.json').read_text())
                assert bundle['session_id']=='agent-session-test' and bundle['snapshot_hash']=='synthetic-snapshot'
                assert TEST_TOKEN not in json.dumps(bundle)
                proposal={'proposed_applicability':'not_affected','rationale':'Synthetic external-agent UI fixture; this is not a real analysis.','evidence_ids':['evidence-test']}
                page.get_by_label('Agent result JSON file · optional',exact=True).set_input_files({'name':'agent-result.json','mimeType':'application/json','buffer':json.dumps(proposal).encode()})
                expect(page.get_by_label('Agent proposal JSON',exact=True)).to_have_value(json.dumps(proposal))
                page.get_by_role('button',name='Submit agent proposal',exact=True).click()
                page.get_by_role('heading',name='External agent proposal',exact=True).wait_for()
                expect(page.locator('.external-proposal')).to_contain_text('The current recorded applicability is Affected.')
                expect(page.locator('.external-proposal')).to_contain_text('Self-reported; not provider-verified')
                assert mock_state['findings'][0]['applicability']=='affected'
                page.screenshot(path=str(output/'external-agent-proposal.png'),full_page=True);screens.append('external-agent-proposal.png')
                page.get_by_role('button',name='Record reviewed verdict').click()
                page.get_by_label('Reviewed applicability').select_option('fixed')
                page.get_by_label('Evidence-based justification').fill('Synthetic test review of an exact build-specific fix with recorded evidence.')
                page.get_by_label('Supporting reference').fill('https://example.test/reviewed-build')
                page.locator('input[name=evidence_id]').first.check()
                page.get_by_role('button',name='Save scoped review').click()
                page.get_by_text('Scoped applicability review recorded.',exact=True).wait_for()
                page.get_by_role('button',name='Close details').click()
                page.get_by_role('checkbox').first.check()
                page.get_by_role('button',name='Create plan (1)').click()
                page.get_by_role('heading',name='Component remediation plan').wait_for()
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                page.get_by_role('button',name='Close details').click()
            if args.mock and view=='plans':
                page.get_by_role('button',name='Review',exact=True).click()
                expect(page.get_by_role('button',name='3 · Stage packages',exact=True)).to_be_disabled()
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                plan=mock_state['maintenance_plan']
                plan.update(maintenance_required=True,scope='container:pmon',staging_eligible=False,
                    steps=['Obtain a signed SONiC service image containing the verified fix.',
                           'Retain the previous image and configuration for rollback.',
                           'Collect fresh scoped inventory and reassess the selected CVEs.'],
                    limitations=['Automatic image activation and reboots are not executed by this package plan.'],
                    finding={'id':'finding-test','decision_basis':'inventory_advisory_match','remediation_eligible':False})
                plan['target_resolution'].update(applicability_review_required=True,applicability_review_reason='Inventory/advisory matching requires a scoped operator review before approval')
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.get_by_role('button',name='2 · Approve review',exact=True)).to_be_disabled()
                expect(page.locator('.approval-prerequisite')).to_contain_text('create a new plan')
                assert not any(item['path'].endswith('/approve') for item in captured)
                page.get_by_role('button',name='Inspect finding for scoped review',exact=True).click()
                expect(page.get_by_role('button',name='Record reviewed verdict',exact=True)).to_be_visible()
                page.get_by_role('button',name='Close details').click()
                plan.pop('finding')
                plan['target_resolution'].update(applicability_review_required=False)
                page.get_by_role('button',name='Review',exact=True).click()
                # Image/container maintenance itself must not block recording a review.
                expect(page.get_by_role('button',name='2 · Approve review',exact=True)).to_be_enabled()
                expect(page.locator('#detail-content')).to_contain_text('does not queue a download or installation')
                # A recorded review is not an active collector job. Render the manual
                # runbook without offering or silently requesting stage/execute actions.
                maintenance_posts_before=sum(item['method']=='POST' and item['path'].startswith('/plans/plan-staged-test/') for item in captured)
                plan.update(status='approved',approved=True)
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.get_by_role('heading',name='Review approved — manual maintenance required',exact=True)).to_be_visible()
                expect(page.get_by_role('heading',name='Manual maintenance runbook',exact=True)).to_be_visible()
                expect(page.locator('.manual-maintenance-runbook')).to_contain_text(plan['steps'][0])
                expect(page.locator('.manual-maintenance-runbook')).to_contain_text(plan['limitations'][0])
                expect(page.locator('.manual-maintenance-flow .maintenance-step.done')).to_have_count(2)
                expect(page.locator('.manual-maintenance-flow .maintenance-step.current')).to_have_count(0)
                expect(page.locator('.manual-maintenance-flow')).not_to_contain_text('Stage & check')
                expect(page.get_by_role('button',name='3 · Stage packages',exact=True)).to_have_count(0)
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_have_count(0)
                expect(page.locator('#detail-content')).to_contain_text('Waiting or rechecking a target will not start deployment')
                assert sum(item['method']=='POST' and item['path'].startswith('/plans/plan-staged-test/') for item in captured)==maintenance_posts_before
                page.locator('#detail-dialog').evaluate('(dialog) => { dialog.scrollTop = 0; }')
                expect(page.get_by_text('MANUAL MAINTENANCE RUNBOOK',exact=True)).to_be_visible()
                page.screenshot(path=str(output/'approved-manual-maintenance.png'),full_page=True);screens.append('approved-manual-maintenance.png')
                page.get_by_role('combobox',name='Target version for central recheck').select_option('1.2')
                page.get_by_role('button',name='Recheck selected target',exact=True).click()
                expect(page.locator('#detail-content')).to_contain_text('A central worker is checking')
                expect(page.get_by_role('button',name='2 · Approve review',exact=True)).to_be_disabled()
                plan=mock_state['maintenance_plan']
                plan.update(status='draft',target_version='1.2',maintenance_required=False,scope='host',staging_eligible=True,approved=False,execution_eligible=False)
                plan.pop('steps')
                plan.pop('limitations')
                plan['target_resolution']['target_options'][1]['status']='recheck_passed'
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.get_by_role('button',name='2 · Approve review',exact=True)).to_be_enabled()
                for status,message in ((409,'Record a scoped operator review before approving inventory-only findings for remediation'),(403,'Administrator access required')):
                    mock_state['approval_control']['error']=(status,message)
                    page.get_by_role('button',name='2 · Approve review',exact=True).click()
                    assert_modal_feedback_visible(page,message)
                    assert plan['status']=='draft' and plan['approved'] is False
                    expect(page.get_by_role('button',name='3 · Stage packages',exact=True)).to_be_disabled()
                    page.screenshot(path=str(output/f'approval-error-{status}.png'),full_page=True);screens.append(f'approval-error-{status}.png')
                    if status==409:
                        page.wait_for_timeout(7600)
                        assert_modal_feedback_visible(page,message)
                    page.locator('#detail-dialog').get_by_role('button',name='Dismiss notification',exact=True).click()
                mock_state['approval_control'].clear()
                mock_state['approval_control']['hold']=True
                before_approval=sum(item['path'].endswith('/approve') for item in captured)
                page.get_by_role('button',name='2 · Approve review',exact=True).click()
                expect(page.get_by_text('Submitting review approval…',exact=True)).to_be_visible()
                expect(page.get_by_role('button',name='2 · Approve review',exact=True)).to_be_disabled()
                # Also exercise the request guard if an event is dispatched directly.
                page.get_by_role('button',name='2 · Approve review',exact=True).dispatch_event('click')
                assert sum(item['path'].endswith('/approve') for item in captured)==before_approval+1
                plan.update(status='approved',approved=True)
                mock_state['approval_control'].pop('held_route').fulfill(json=plan)
                mock_state['approval_control'].clear()
                expect(page.get_by_role('button',name='3 · Stage packages',exact=True)).to_be_enabled()
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                expect(page.locator('.maintenance-step.current')).to_contain_text('Ready to stage')
                expect(page.locator('#detail-content')).to_contain_text('No staging request has been queued')
                page.get_by_role('button',name='3 · Stage packages',exact=True).click()
                expect(page.locator('#detail-content')).to_contain_text('Staging is queued for the collector')
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                page.locator('#detail-dialog .dialog-feedback').get_by_role('button',name='Dismiss notification',exact=True).click()
                # Open active plans update using GET only. An unchanged response
                # must not replace DOM nodes, close evidence, move focus or scroll.
                def plan_gets():
                    return sum(item['method']=='GET' and item['path']=='/plans/plan-staged-test' for item in captured)
                def plan_posts():
                    return sum(item['method']=='POST' and item['path'].startswith('/plans/plan-staged-test/') for item in captured)
                post_count=plan_posts()
                page.locator('#detail-dialog').evaluate('''dialog => {
                    dialog.querySelector('#detail-content').firstElementChild.pollProbe = true;
                    dialog.querySelector('details').open = true;
                    [...dialog.querySelectorAll('button')].find(node => node.textContent === 'Refresh plan').focus({preventScroll:true});
                    dialog.scrollTop = 120;
                }''')
                before_poll=plan_gets()
                page.wait_for_timeout(5300)
                assert plan_gets()==before_poll+1
                assert page.locator('#detail-dialog').evaluate('''dialog =>
                    dialog.querySelector('#detail-content').firstElementChild.pollProbe === true &&
                    dialog.querySelector('details').open && document.activeElement.textContent === 'Refresh plan' &&
                    Math.abs(dialog.scrollTop - 120) < 2''')
                reason='At least 500 MiB of staging free space is required'
                plan.update(status='denied',execution_eligible=False,
                    staging_result={'status':'denied','value':{'status':'denied','details':reason}})
                expect(page.locator('.collector-outcome .notice')).to_have_text(reason,timeout=8000)
                expect(page.locator('#detail-content')).to_contain_text('The collector denied this request')
                expect(page.locator('.maintenance-step.current')).to_have_count(0)
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                updated_view=page.locator('#detail-dialog').evaluate('''dialog => ({
                    evidenceOpen: dialog.querySelector('details').open,
                    focus: document.activeElement.textContent, scroll: dialog.scrollTop})''')
                assert updated_view['evidenceOpen'] and updated_view['focus']=='Refresh plan' and abs(updated_view['scroll']-120)<2, updated_view
                page.locator('.collector-outcome').scroll_into_view_if_needed()
                expect(page.locator('.collector-outcome .notice')).to_be_visible()
                page.screenshot(path=str(output/'collector-staging-denied.png'),full_page=True);screens.append('collector-staging-denied.png')
                # A terminal result stops polling; closing the active plan also
                # stops polling and must never reopen the dialog on a late timer.
                terminal_gets=plan_gets()
                page.wait_for_timeout(5300)
                assert plan_gets()==terminal_gets and plan_posts()==post_count
                plan.update(status='staging_queued')
                plan.pop('staging_result')
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                page.get_by_role('button',name='Close details').click()
                closed_gets=plan_gets()
                page.wait_for_timeout(5300)
                assert plan_gets()==closed_gets and plan_posts()==post_count
                expect(page.locator('#detail-dialog')).not_to_be_visible()
                # Replacing the plan with a finding dialog cancels its polling.
                plan['finding']={'id':'finding-test','decision_basis':'inventory_advisory_match','remediation_eligible':False}
                page.get_by_role('button',name='Review',exact=True).click()
                page.get_by_role('button',name='Inspect finding for scoped review',exact=True).click()
                expect(page.get_by_role('button',name='Record reviewed verdict',exact=True)).to_be_visible()
                switched_gets=plan_gets()
                page.wait_for_timeout(5300)
                assert plan_gets()==switched_gets and plan_posts()==post_count
                expect(page.get_by_role('button',name='Record reviewed verdict',exact=True)).to_be_visible()
                page.get_by_role('button',name='Close details').click()
                plan.pop('finding')
                page.get_by_role('button',name='Review',exact=True).click()
                # Wait for the initial read before holding the next poll response.
                expect(page.locator('#detail-dialog .maintenance-controls')).to_be_visible()
                # A slow GET must not overlap the next interval; closing cancels
                # that request and a late response cannot reopen the plan.
                before_slow_poll=plan_gets()
                mock_state['plan_read_control']['hold']=True
                page.wait_for_timeout(5300)
                assert 'held_route' in mock_state['plan_read_control']
                assert plan_gets()==before_slow_poll+1
                page.wait_for_timeout(5300)
                assert plan_gets()==before_slow_poll+1
                page.get_by_role('button',name='Close details').click()
                mock_state['plan_read_control'].pop('held_route').fulfill(json=plan)
                mock_state['plan_read_control'].clear()
                page.wait_for_timeout(200)
                expect(page.locator('#detail-dialog')).not_to_be_visible()
                assert plan_posts()==post_count
                page.get_by_role('button',name='Review',exact=True).click()
                for status in ('staging_failed','unknown'):
                    plan.update(status=status,execution_eligible=True,execution_result={'status':'complete','value':{'status':status}})
                    page.get_by_role('button',name='Refresh plan',exact=True).click()
                    expect(page.locator('#detail-content')).to_contain_text('The recorded outcome is failed or unknown')
                    expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                plan.update(status='denied',staging_result={'status':'complete','value':{'status':'staged','details':'Old staging result'}},
                    execution_result={'status':'denied','value':{'status':'denied','details':'Current execution prerequisite failed'}})
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.locator('.collector-outcome .notice')).to_have_text('Current execution prerequisite failed')
                expect(page.locator('.maintenance-step.current')).to_have_count(0)
                plan.pop('staging_result')
                plan.update(status='staged',execution_eligible=False,execution_result={'status':'complete','value':{'status':'staged','checks':['Synthetic preflight passed']}})
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                plan['execution_eligible']=True
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_enabled()
                # Older agents did not report this policy: absence must not be
                # represented as disabled checks or unavailable rollback.
                expect(page.locator('.maintenance-check-summary')).to_have_count(0)
                plan['execution_result']['value']['details']={
                    'maintenance_checks_enabled':True,'rollback_available':True,'checks_skipped':[]}
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Maintenance checks enabled for this request')
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Rollback packages staged for an attempted recovery')
                plan['execution_result']['value']['details']={
                    'maintenance_checks_enabled':False,'rollback_available':False,
                    'rollback_missing':[{'package':'test-package','version':'1.0','reason':'Exact old version unavailable from repository'}],
                    'checks_skipped':['free_space','dependency_policy','health_baseline']}
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Maintenance checks disabled for this request')
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Automatic rollback unavailable')
                expect(page.locator('.rollback-missing')).to_contain_text('test-package 1.0: Exact old version unavailable from repository')
                expect(page.locator('.checks-skipped')).to_contain_text('Free Space')
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_enabled()
                assert not any(item['path']=='/plans/plan-staged-test/execute' for item in captured)
                page.screenshot(path=str(output/'staged-maintenance.png'),full_page=True);screens.append('staged-maintenance.png')
                plan['staging_result']=json.loads(json.dumps(plan['execution_result']))
                page.get_by_role('button',name='4 · Review execution',exact=True).click()
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Maintenance checks disabled for this request')
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Automatic rollback unavailable')
                expect(page.locator('.rollback-missing')).to_contain_text('test-package 1.0')
                assert not any(item['path']=='/plans/plan-staged-test/execute' for item in captured)
                page.get_by_role('textbox',name='Confirm target switch identity').fill('wrong-switch')
                page.get_by_role('button',name='Request plan execution',exact=True).click()
                expect(page.get_by_text('The switch identity does not match the plan target.',exact=True)).to_be_visible()
                assert not any(item['path']=='/plans/plan-staged-test/execute' for item in captured)
                page.get_by_role('textbox',name='Confirm target switch identity').fill('test-switch')
                page.get_by_role('button',name='Request plan execution',exact=True).click()
                expect(page.locator('#detail-content')).to_contain_text('The explicit execution request is queued or running')
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                plan.update(status='pending_reassessment',execution_eligible=False,execution_result={'status':'complete','value':{
                    'status':'completed','details':{'maintenance_checks_enabled':False,'rollback_available':False,
                    'checks_skipped':['health_baseline','post_install_health'], 'post_validation':{'status':'SKIPPED'}}}},
                    reassessment={'status':'waiting','reason_code':'awaiting_scan',
                        'reason':'Waiting for an accepted scan of the new inventory.',
                        'observed_version':'1.2','target_version':'1.2','inventory_digest':'post-install-test-digest',
                        'assessment_revision':None,'checked_at':NOW,'scope':'host','package_name':'test-package',
                        'selected_cves':['CVE-TEST-0001'],'remaining_cves':[],
                        'scanner_db_revision':None,'scan_completed_at':None})
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.locator('#detail-content')).to_contain_text('A new inventory and central assessment must establish')
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Post-installation health checks skipped')
                expect(page.locator('.reassessment-summary')).to_contain_text('Waiting for an accepted scan of the new inventory.')
                expect(page.locator('.reassessment-summary')).to_contain_text('Not yet established')
                expect(page.locator('.maintenance-step.current')).to_contain_text('Reassess')
                execution_post_count=plan_posts()
                plan['reassessment'].update(reason_code='incomplete_scan',reason='The last scan did not cover the target scope completely.')
                expect(page.locator('.reassessment-summary')).to_contain_text('The last scan did not cover the target scope completely.',timeout=8000)
                plan.update(status='completed',staging_eligible=False,execution_eligible=False)
                plan['reassessment'].update(status='completed',reason_code='selected_cves_absent',
                    reason='The accepted scan no longer reports the selected CVEs for test-package in host.',
                    assessment_revision='post-install-test-assessment',scanner_db_revision='post-install-test-db',
                    scan_completed_at=NOW)
                expect(page.get_by_role('heading',name='Selected CVEs no longer reported',exact=True)).to_be_visible(timeout=8000)
                expect(page.locator('.maintenance-step.done')).to_have_count(5)
                expect(page.locator('.maintenance-step.current')).to_have_count(0)
                expect(page.locator('.reassessment-summary')).to_contain_text('Observed version1.2')
                expect(page.locator('.reassessment-summary')).to_contain_text('post-install-test-assessment')
                expect(page.locator('.reassessment-summary')).to_contain_text('post-install-test-digest')
                expect(page.locator('.reassessment-summary')).to_contain_text('None in the accepted scan')
                expect(page.locator('.maintenance-check-summary')).to_contain_text('Post-installation health checks skipped')
                expect(page.get_by_role('button',name='3 · Stage packages',exact=True)).to_be_disabled()
                expect(page.get_by_role('button',name='4 · Review execution',exact=True)).to_be_disabled()
                completed_gets=plan_gets()
                page.wait_for_timeout(5300)
                assert plan_gets()==completed_gets and plan_posts()==execution_post_count
                # A completed result remains historical evidence after its
                # execution authorization expires; it must not show active work.
                plan['expires_at']='2000-01-01T00:00:00Z'
                page.get_by_role('button',name='Refresh plan',exact=True).click()
                expect(page.locator('#detail-content')).not_to_contain_text('This plan has expired. Create a new plan')
                expect(page.locator('.maintenance-step.done')).to_have_count(5)
                page.locator('.reassessment-summary').scroll_into_view_if_needed()
                page.screenshot(path=str(output/'completed-scoped-reassessment.png'),full_page=True);screens.append('completed-scoped-reassessment.png')
                page.get_by_role('button',name='Close details').click()
                page.locator('#refresh-button').click();ready(page)
                completed_row=page.get_by_role('row').filter(has_text='Synthetic staged maintenance')
                expect(completed_row).to_contain_text('Observed 1.2 · Before 1.0')
                expect(completed_row).not_to_contain_text('Installed 1.0')
                expect(completed_row.get_by_role('cell').nth(3)).to_have_text('Staged')
                expect(completed_row.get_by_role('cell').nth(4)).to_have_text('Completed')
            if args.mock and view=='tools':
                page.locator('#tool-select').select_option('compare_versions')
                page.locator('#tool-arguments').fill(json.dumps({'ecosystem':'deb','installed':'1:1.0','other':'2.0'}))
                page.get_by_role('button',name='Run evidence tool').click()
                expect(page.locator("#tool-output")).to_contain_text("comparison")
            if args.mock and view=='releases':
                page.get_by_role('button',name='Verify binding',exact=True).click()
                page.get_by_label('Approved public-key ID').fill('test-builder')
                page.get_by_label('Embedded manifest · original JSON file').set_input_files({'name':'manifest.json','mimeType':'application/json','buffer':b'{"fixture":"raw manifest"}\n'})
                page.get_by_label('Signed external release index · original JSON file').set_input_files({'name':'index.json','mimeType':'application/json','buffer':b'{"fixture":"raw index"}\n'})
                page.get_by_label('Detached signature · binary .sig file').set_input_files({'name':'index.sig','mimeType':'application/octet-stream','buffer':b'fixture-signature'})
                page.get_by_role('button',name='Verify signed binding',exact=True).click()
                page.get_by_role('heading',name='Builder signature verified',exact=True).wait_for()
                page.get_by_role('button',name='Close details').click()
                page.get_by_label('Release / build ID',exact=True).first.fill('custom:browser-repository')
                page.get_by_label('Source URL',exact=True).fill('https://github.com/sonic-net/sonic-buildimage')
                page.get_by_label('Pinned source revision',exact=True).fill('a'*40)
                repositories=[{'base_url':'https://deb.debian.org/debian','suite':'bookworm','components':['main'],'architectures':['amd64'],'keyring':'/usr/share/keyrings/debian-archive-keyring.gpg'}]
                page.get_by_label('Signed APT repositories · JSON',exact=True).fill(json.dumps(repositories))
                page.get_by_role('button',name='Register release',exact=True).click()
                page.get_by_text('Release registered.',exact=True).wait_for()
            if args.mock and view=='packages-trends':
                expect(page.get_by_role('heading',name='Current package families',exact=True)).to_be_visible()
                expect(page.get_by_role('heading',name='Most updated packages',exact=True)).to_be_visible()
                expect(page.get_by_text('test-package',exact=True).first).to_be_visible()
                expect(page.get_by_text('Daily · last observed value',exact=True)).to_be_visible()
                page.get_by_role('combobox',name='Observation window').select_option('7')
                expect(page.get_by_text('Hourly observations',exact=True)).to_be_visible()
                page.get_by_role('combobox',name='Observation window').select_option('366')
                expect(page.get_by_text('Daily · last observed value',exact=True)).to_be_visible()
            if args.mock and view=='cve-trends':
                expect(page.get_by_role('heading',name='CVE discovery',exact=True)).to_be_visible()
                chart=page.get_by_role('img',name='Distinct CVEs first observed by Smart Patch',exact=True)
                expect(chart.locator('rect')).to_have_count(2)
                expect(page.get_by_text('First observed in this window',exact=True)).to_be_visible()
                expect(page.get_by_text('Historical discovery coverage is partial.',exact=False)).to_be_visible()
                expect(page.get_by_text('Daily observations · discovery counts per day',exact=True)).to_be_visible()
                page.screenshot(path=str(output/'cve-discovery-mock.png'),full_page=True);screens.append('cve-discovery-mock.png')
                page.get_by_role('combobox',name='Observation window').select_option('7')
                expect(page.get_by_text('Hourly observations · discovery counts per hour',exact=True)).to_be_visible()
                page.get_by_role('combobox',name='Observation window').select_option('366')
                expect(page.get_by_text('Daily observations · discovery counts per day',exact=True)).to_be_visible()
            if args.mock and view=='settings':
                expect(page.get_by_label('Build evidence for applicability',exact=True)).to_have_value('required')
                page.get_by_label('Build evidence for applicability',exact=True).select_option('optional')
                page.get_by_label('Provider API key').fill('synthetic-provider-secret')
                page.get_by_label('Queue depth alert threshold',exact=True).fill('75')
                page.get_by_role('button',name='Save configuration').click()
                page.get_by_text('Configuration saved.',exact=True).wait_for()
                assert page.get_by_label('Provider API key').input_value()==''
                expect(page.get_by_label('Build evidence for applicability',exact=True)).to_have_value('optional')
                expect(page.locator('#page-content')).to_contain_text('marks existing assessments stale')
                page.get_by_label('Build evidence for applicability',exact=True).select_option('required')
                with page.expect_response(lambda response: response.url.endswith('/api/v1/settings') and response.request.method=='GET'):
                    page.get_by_role('button',name='Save configuration').click()
                ready(page)
                expect(page.get_by_label('Build evidence for applicability',exact=True)).to_have_value('required')
                # Static assets may update before the service restarts. An older
                # backend must continue accepting unrelated settings edits.
                mock_state['settings'].pop('build_evidence_policy')
                page.reload();ready(page)
                expect(page.get_by_label('Build evidence for applicability',exact=True)).to_have_count(0)
                page.get_by_label('Model',exact=True).fill('legacy-compatible-model')
                page.get_by_label('Queue depth alert threshold',exact=True).fill('76')
                with page.expect_response(lambda response: response.url.endswith('/api/v1/settings') and response.request.method=='GET'):
                    page.get_by_role('button',name='Save configuration').click()
                ready(page)
                expect(page.get_by_label('Model',exact=True)).to_have_value('legacy-compatible-model')
                expect(page.get_by_label('Queue depth alert threshold',exact=True)).to_have_value('76')
                expect(page.get_by_label('Build evidence for applicability',exact=True)).to_have_count(0)
            if args.mock and view=='tokens':
                page.get_by_label('Description',exact=True).fill('Synthetic browser collector')
                page.get_by_label('Device ID',exact=True).fill('test-switch')
                page.get_by_role('button',name='Create token',exact=True).click()
                page.get_by_text('Copy this token now',exact=True).wait_for()
                page.get_by_role('button',name='Dismiss token',exact=True).click()
        if args.mock:
            exercise_bulk_workflow(page, mock_state, captured, output, screens)
            mock_state['overview']['summary'].update(findings_affected=0,findings_unknown=51,findings_total=51)
            mock_state['overview']['applicability_counts']={'affected':0,'under_investigation':51}
            for finding in mock_state['findings']:finding['applicability']='under_investigation'
            page.locator('a[data-nav="overview"]').click();ready(page)
            expect(page.locator('#nav-findings-count')).to_have_text('51')
            expect(page.get_by_role('button',name='Needs evidence (51)',exact=True)).to_have_attribute('aria-pressed','true')
            expect(page.get_by_role('heading',name='51 candidates need applicability evidence.')).to_be_visible()
            expect(page.get_by_role('button',name='Inspect CVE-TEST-0001')).to_be_visible()
            page.screenshot(path=str(output/'overview-needs-evidence.png'),full_page=True);screens.append('overview-needs-evidence.png')
            page.locator('a[data-nav="request-status"]').click();ready(page)
        page.set_viewport_size({'width':390,'height':844})
        page.wait_for_timeout(300)  # Allow the responsive sidebar transition to finish.
        page.screenshot(path=str(output/'mobile-request-performance.png'),full_page=True);screens.append('mobile-request-performance.png')
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile page overflows horizontally'
        page.get_by_role('button',name='Toggle navigation').click()
        page.locator('a[data-nav="overview"]').click();ready(page)
        if args.mock:
            token_request=next(item for item in captured if item['path']=='/tokens' and item['method']=='POST')
            assert token_request['body']['role']=='agent'
            settings_request=next(item for item in captured if item['path']=='/settings' and item['method']=='PUT')
            assert 'scanner_binary' not in settings_request['body']
            assert settings_request['body']['alert_queue_depth']==75
            assert settings_request['body']['alerts_enabled'] is True
            settings_requests=[item for item in captured if item['path']=='/settings' and item['method']=='PUT']
            assert [item['body'].get('build_evidence_policy') for item in settings_requests]==['optional','required',None]
            assert 'build_evidence_policy' not in settings_requests[-1]['body']
            assert settings_requests[-1]['body']['ai_model']=='legacy-compatible-model'
            assert settings_requests[-1]['body']['alert_queue_depth']==76
            proposal_request=next(item for item in captured if item['path']=='/agent-sessions/agent-session-test/analysis')
            assert proposal_request['body']['snapshot_hash']=='synthetic-snapshot'
            assert proposal_request['body']['component_id']=='test-component'
            assert proposal_request['body']['scope_id']=='host'
            maintenance_posts=[item for item in captured if item['method']=='POST' and item['path'].startswith('/plans/plan-staged-test/')]
            assert [item['path'].rsplit('/',1)[-1] for item in maintenance_posts]==['validate-target','approve','approve','approve','stage','execute']
            assert maintenance_posts[0]['body']=={'target_version':'1.2'}
            assert maintenance_posts[-1]['body']=={'confirmed_device_id':'test-switch'}
            release_request=next(item for item in captured if item['path']=='/releases' and item['method']=='POST')
            assert release_request['body']['source_revision']=='a'*40
            assert release_request['body']['repositories'][0]['base_url']=='https://deb.debian.org/debian'
            binding_request=next(item for item in captured if item['path']=='/artifacts/verify')
            assert binding_request['body']['manifest_text'].endswith('\n')
            assert binding_request['body']['release_index_text'].endswith('\n')
            assert set(binding_request['body'])=={'release_id','manifest_text','release_index_text','signature_base64','key_id'}
            review_request=next(item for item in captured if item['path']=='/findings/finding-test/review')
            assert review_request['body']['evidence_ids']==['evidence-test']
            assert review_request['body']['review_reference'].startswith('https://')
            assert all(item['authorization']=='Bearer '+TEST_TOKEN for item in captured)
        assert not errors,errors
        browser.close()
    result={'mode':'synthetic mock' if args.mock else 'live read-only','pages_checked':14,'javascript_errors':errors,'screenshots':screens}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--mock',action='store_true')
    parser.add_argument('--base-url',default='https://100.104.17.32:8000')
    parser.add_argument('--token-file',default='.state/bootstrap-token')
    parser.add_argument('--allow-untrusted-test-tls',action='store_true',help='Browser smoke only; does not alter service or collector TLS policy.')
    parser.add_argument('--output',default='/tmp/smart-patch-ui-smoke')
    run(parser.parse_args())
