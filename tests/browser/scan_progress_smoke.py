"""Synthetic read-only job progress rendering and polling; no live service."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright

from workspace_smoke import NOW, TEST_TOKEN, mock_routes, ready


def run(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    errors, requests, reads = [], [], []
    job = {'id': 'progress-fixture', 'operation_type': 'scan', 'status': 'in_progress',
           'progress_percentage': 62, 'created_at': NOW, 'started_at': NOW,
           'progress_data': {'progress_kind': 'workflow', 'phase': 'assessing',
               'detail': 'Evaluating findings and saving evidence', 'scopes_completed': 15, 'scopes_total': 15,
               'packages_matched': 1, 'packages_reused': 3999, 'findings_completed': 500, 'findings_total': 2000}}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=['--no-sandbox'])
        context = browser.new_context(viewport={'width': 1550, 'height': 1060})
        mock_routes(context, requests)

        def handler(route):
            request = route.request
            assert request.method == 'GET'
            assert request.headers.get('authorization') == 'Bearer ' + TEST_TOKEN
            endpoint = urlparse(request.url).path
            reads.append(endpoint)
            if endpoint.endswith('/operations'):
                route.fulfill(json={'operations': [job]})
            elif endpoint.endswith('/logs'):
                route.fulfill(json={'logs': [{'message': 'Synthetic progress fixture'}]})
            else:
                route.fulfill(json=job)

        context.route('**/api/v1/operations**', handler)
        context.route('**/api/v1/operations/**', handler)
        context.add_init_script("sessionStorage.setItem('smart_patch_admin_token', '" + TEST_TOKEN + "')")
        page = context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto('https://smart-patch.test/ui/jobs')
        ready(page)
        expect(page.get_by_text('Assessing findings', exact=True)).to_be_visible()
        expect(page.get_by_text('62% workflow progress', exact=True)).to_be_visible()
        expect(page.get_by_text('Packages checked now: 1 · Package results reused: 3,999', exact=True)).to_be_visible()
        expect(page.get_by_text('500 / 2,000 findings assessed', exact=True)).to_be_visible()
        page.screenshot(path=str(output / 'jobs-progress.png'), full_page=True)
        page.get_by_role('button', name='Inspect', exact=True).click()
        dialog = page.locator('#detail-dialog')
        expect(dialog.get_by_text('500 / 2,000 findings assessed', exact=True)).to_be_visible()
        job['progress_data']['findings_completed'] = 900
        job['progress_percentage'] = 66
        # The dialog stays current while open, without a page refresh or write.
        expect(dialog.get_by_text('900 / 2,000 findings assessed', exact=True)).to_be_visible(timeout=9000)
        page.screenshot(path=str(output / 'job-detail-progress.png'), full_page=True)
        job.update(status='failed', error_message='Synthetic scanner failure', progress_percentage=66)
        job['progress_data'].update(phase='failed', stopped_phase='assessing')
        dialog.get_by_role('button', name='Refresh progress').click()
        expect(dialog.get_by_text('Processing failed', exact=True)).to_be_visible()
        expect(dialog.get_by_text('66% workflow progress', exact=True)).to_be_visible()
        expect(dialog.get_by_text('Stopped during Assessing findings', exact=True)).to_be_visible()
        individual = '/api/v1/operations/progress-fixture'
        stopped = reads.count(individual)
        page.wait_for_timeout(5500)
        assert reads.count(individual) == stopped, 'Terminal jobs should stop polling'
        job.update(status='completed', progress_percentage=100, result={'accepted': False}, error_message=None)
        job['progress_data']['phase'] = 'superseded'
        dialog.get_by_role('button', name='Refresh progress').click()
        expect(dialog.get_by_text('Superseded · inventory changed', exact=True)).to_be_visible()
        expect(dialog.get_by_text('Finished processing an older inventory; this result is not current.', exact=True)).to_be_visible()
        job.update(status='in_progress', result=None, progress_percentage=70)
        job['progress_data']['phase'] = 'assessing'
        dialog.get_by_role('button', name='Refresh progress').click()
        expect(dialog.get_by_text('Assessing findings', exact=True)).to_be_visible()
        dialog.get_by_role('button', name='Close details', exact=True).click()
        stopped = reads.count(individual)
        page.wait_for_timeout(5500)
        assert reads.count(individual) == stopped, 'Closed dialogs must cancel polling'
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        assert not errors, errors
        browser.close()
    result = {'mode': 'synthetic read-only', 'javascript_errors': errors, 'operation_reads': len(reads),
              'screenshots': [path.name for path in output.glob('*.png')]}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='/tmp/smart-patch-scan-progress-ui')
    run(parser.parse_args().output)
