"""Capture generic documentation screens from the code-native web UI.

Uses a private token file. Empty connection dialog is captured before login.
Only GETs and the read-only Debian version tool may reach the server.
Form examples are typed locally and are never submitted.
Deployment details are replaced in rendered DOM text before each new capture;
the service data and configuration are not changed. No existing pixels are edited.
"""
import argparse
import importlib.util
import json
import re
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright,expect

ROOT=Path(__file__).resolve().parents[2]
DEST=Path(__file__).with_name('images')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    destination=parser.add_mutually_exclusive_group(required=True)
    destination.add_argument('--base-url',help='Actual HTTPS Smart Patch origin used only during capture')
    destination.add_argument('--mock',action='store_true',help='Render local UI using labelled synthetic fixtures; no network')
    parser.add_argument('--token-file',type=Path,default=ROOT/'.state/bootstrap-token')
    args=parser.parse_args();base='https://smart-patch.test' if args.mock else args.base_url.rstrip('/')
    if urlsplit(base).scheme!='https' or '<' in base:parser.error('Provide the actual HTTPS service origin')
    DEST.mkdir(exist_ok=True)
    manifest={'captured_at':datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(),'base_url':'https://<server-ip>:8000',
              'presentation':('Local UI with labelled synthetic example data; no live scan results' if args.mock else
                              'Real UI with deployment addresses, paths and identifiers replaced before capture'),
              'synthetic_data':args.mock,
              'configuration_changes':False,'switch_actions':False,'screens':[],'javascript_errors':[]}
    replacements=[(str(ROOT),'<path-to-intelligence-service>'),
                  (str(ROOT.parent/'sonic-buildimage'),'<path-to-sonic-buildimage>'),
                  (urlsplit(base).hostname,'<server-ip>')]
    def safe_text(value):
        for original,replacement in replacements:value=value.replace(original,replacement)
        value=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<ip-address>',value)
        return value
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
        context=browser.new_context(viewport={'width':1360,'height':980},ignore_https_errors=True,
                                   timezone_id='Asia/Kolkata',device_scale_factor=1)
        if args.mock:
            spec=importlib.util.spec_from_file_location('workspace_smoke',ROOT/'tests/browser/workspace_smoke.py')
            smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
            original_fixtures=smoke.fixtures
            smoke.ATTACK_TEXT='example-lldpd'
            def documentation_fixtures():
                device,finding=original_fixtures()
                device['hostname']='EXAMPLE SONiC SWITCH'
                finding.update(hostname=device['hostname'],cve_id='CVE-2099-10001',package_name='example-lldpd',
                               applicability='under_investigation',rationale='Synthetic example. Gather package and build evidence before recording a verdict.')
                return device,finding
            smoke.fixtures=documentation_fixtures
            mock_state=smoke.mock_routes(context,[])
            mock_state['overview']['summary'].update(findings_affected=0,findings_unknown=54)
            mock_state['overview']['applicability_counts']={'under_investigation':54}
            context.route('**/api/v1/tools/compare_versions',lambda route:route.fulfill(json={
                'result':{'id':'example-version-comparison','data':{'comparison':0},'complete':True}}))
            token=smoke.TEST_TOKEN
        else:
            token=args.token_file.read_text().strip()
        def guard(route):
            req=route.request;url=urlsplit(req.url)
            if url.netloc!=urlsplit(base).netloc:route.abort();return
            if req.method not in ('GET','HEAD') and not (req.method=='POST' and url.path=='/api/v1/tools/compare_versions'):
                raise AssertionError('Documentation capture blocked mutation: '+req.method+' '+url.path)
            route.fallback() if args.mock else route.continue_()
        context.route('**/*',guard)
        page=context.new_page();page.on('pageerror',lambda e:manifest['javascript_errors'].append(str(e)))
        def ready():
            expect(page.locator('#last-updated')).to_contain_text('Updated',timeout=30000)
            page.locator('#page-content[aria-busy="false"]').wait_for()
        def shot(name,description,selector=None,mode='live'):
            if args.mock:
                page.evaluate('''() => {
                  document.querySelectorAll('[data-documentation-example]').forEach(node=>node.remove());
                  const container=document.querySelector('dialog[open]') || document.querySelector('#page-content');
                  const label=document.createElement('p');
                  label.dataset.documentationExample='true';label.textContent='ILLUSTRATIVE DATA · synthetic documentation example';
                  label.style.cssText='font:600 11px Arial;color:#6455cb;letter-spacing:.05em;margin:0 0 18px';
                  container.prepend(label);
                }''')
            page.evaluate(r'''pairs => {
              const rewrite = value => {
                for (const [source,target] of pairs) value=value.split(source).join(target);
                return value.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,'<ip-address>')
                  .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,'<record-id>')
                  .replace(/\b[0-9a-f]{64}\b/gi,'<digest>')
                  .replace(/\b[0-9a-f]{40}\b/gi,'<source-commit>')
                  .replace(/\b[0-9a-f]{24,39}\b/gi,'<record-id>')
                  .replace(/master\.0-[0-9a-f]+/gi,'<sonic-build>');
              };
              const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
              const nodes=[];while(walker.nextNode()) nodes.push(walker.currentNode);
              for (const node of nodes) {
                if (!['SCRIPT','STYLE'].includes(node.parentElement?.tagName)) node.nodeValue=rewrite(node.nodeValue);
              }
              document.querySelectorAll('input,textarea').forEach(input=>{
                if(input.type!=='password') input.value=rewrite(input.value);
              });
            }''',replacements)
            visible=page.evaluate("document.body.innerText + Array.from(document.querySelectorAll('input,textarea')).map(n=>n.value).join(' ')")
            assert not re.search(r'/home/[^/\s]+/|\b(?:\d{1,3}\.){3}\d{1,3}\b',visible),'Unreplaced deployment detail in capture'
            page.screenshot(path=str(DEST/name),full_page=False) if selector is None else page.locator(selector).screenshot(path=str(DEST/name))
            manifest['screens'].append({'file':name,'description':safe_text(description.replace('Live ', 'Example ').replace('live ', 'example ').replace('Actual ', 'Example ').replace('Actual ', 'Example ') if args.mock else description),
                'mode':('synthetic example; ' if args.mock else 'deployment-details-replaced; ')+mode,'url':safe_text(page.url)})
            (DEST.parent/'screenshot-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        def visit(view):
            page.goto(base+'/ui/'+view);ready()
        page.goto(base+'/ui/')
        page.get_by_role('button',name='Connect securely').click()
        shot('01-connect.png','Empty connection dialog; enter a Smart Patch service token, not an AI key.','#auth-dialog')
        page.get_by_label('Smart Patch service token').fill(token)
        page.get_by_role('button',name='Connect to workspace').click();ready()
        page.locator('#auth-token').evaluate('(input) => { input.value = ""; }')
        devices=page.evaluate("""async()=>{const response=await fetch('/api/v1/devices',
          {headers:{Authorization:'Bearer '+sessionStorage.getItem('smart_patch_admin_token')}});
          if(!response.ok) throw new Error('Could not read device identities for anonymization');
          return (await response.json()).devices;}""")
        for index,device in enumerate(devices):
            for key,replacement in [('id','<device-id>' if index==0 else '<second-device-id>'),
                    ('ip_address','<sonic-vm-ip>' if index==0 else '<second-sonic-vm-ip>'),
                    ('hostname','SONiC VM '+str(index+1)),('sonic_version','<sonic-build>')]:
                if device.get(key):replacements.append((device[key],replacement))
        shot('02-overview.png','Live fleet overview; candidate counts do not establish confirmed affected systems.')
        visit('tokens')
        page.locator('input[name=description]').fill('Smart Patch collector — SONiC VM')
        page.locator('select[name=role]').select_option('agent')
        page.locator('input[name=device_id]').fill('<device-id>')
        shot('03-token-example.png','Example device-token form; values typed locally, Create token not clicked.',
             '#page-content .two-column',mode='unsaved form example on live UI')
        visit('settings')
        shot('04-settings.png','Live provider/source settings. No provider API key is configured.')
        visit('fleet')
        shot('05-fleet.png','Live enrolled switches; online is a heartbeat state.')
        page.get_by_role('button',name='Inspect',exact=False).first.click()
        page.locator('#detail-dialog[open]').wait_for()
        shot('06-device-detail.png','Live device detail with scan and evidence controls. No actions submitted.','#detail-dialog')
        page.get_by_role('button',name='Close details').click()
        cve='CVE-2099-10001' if args.mock else 'CVE-2023-41910'
        visit('findings?search='+cve)
        shot('07-findings.png','Finding search; inspect the package and scope on each switch.')
        page.get_by_role('button',name='Inspect '+cve,exact=True).first.click()
        page.locator('#detail-dialog[open]').wait_for()
        shot('08-finding-detail.png','Live LLDP finding detail. Under investigation remains distinct from fixed/not affected.','#detail-dialog')
        page.get_by_role('button',name='Record reviewed verdict',exact=True).click()
        page.locator('#review-rationale').fill('The shipped artifact is not verified. Keep this occurrence under investigation until package and patch provenance is available.')
        shot('09-review-example.png','Administrator review form with example rationale; no review submitted.','#detail-dialog',mode='unsaved form example on live UI')
        page.get_by_role('button',name='Close details').click()
        visit('tools')
        page.locator('#tool-select').select_option('compare_versions')
        page.locator('#tool-arguments').fill(json.dumps({'ecosystem':'deb','installed':'1.0.16-1+deb12u1','other':'1.0.16-1+deb12u1'},indent=2))
        page.get_by_role('button',name='Run evidence tool',exact=True).click()
        expect(page.locator('#tool-output')).to_contain_text('comparison',timeout=30000)
        shot('10-version-tool.png','Actual read-only Debian version comparison; result zero means the versions compare equal.')
        visit('releases')
        page.locator('input[name=release_id]').first.fill('<release-id>')
        page.locator('input[name=source_url]').fill('https://github.com/sonic-net/sonic-buildimage')
        page.locator('input[name=source_revision]').fill('<source-commit>')
        page.locator('textarea[name=repositories]').fill(json.dumps([{'base_url':'https://deb.debian.org/debian',
            'suite':'trixie','components':['main'],'architectures':['amd64'],
            'keyring':'/usr/share/keyrings/debian-archive-keyring.gpg'}],indent=2))
        page.locator('textarea[name=repositories]').evaluate('(input) => { input.scrollTop = 0; input.scrollLeft = 0; }')
        shot('11-release-example.png','Release example; public keyring path is a prerequisite placeholder. Registration/upload not submitted.',
             '#page-content .two-column',mode='unsaved form example on live UI')
        visit('coverage');shot('12-coverage.png','Live coverage and freshness; signed baseline and scanner coverage are separate.')
        visit('cve-trends');shot('13-discovery.png','Live first-observed CVE chart; retained historical coverage is partial.')
        visit('jobs');shot('14-jobs.png','Live background jobs; queued/completed processing does not prove vulnerability resolution.')
        assert not manifest['javascript_errors'],manifest['javascript_errors']
        browser.close()
    (DEST.parent/'screenshot-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'screenshots':len(manifest['screens']),'javascript_errors':manifest['javascript_errors'],
                      'configuration_changes':False,'switch_actions':False}))


if __name__=='__main__':main()
