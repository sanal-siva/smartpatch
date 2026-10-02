"""Export the source-rendered user guide and design to portable PDFs.

Run after render_guide.py and render_design.py in a documentation environment
containing Playwright/Chromium and PyMuPDF. No network or application API is used.
"""
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

import fitz
from playwright.sync_api import sync_playwright


def main():
    docs = Path(__file__).resolve().parent
    results = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 1060})
        page.route('http://**', lambda route: route.abort())
        page.route('https://**', lambda route: route.abort())
        for name, report_dir in [('USER_GUIDE', docs / 'user-guide/verification'),
                                 ('DETAILED_DESIGN', docs / 'design')]:
            page.goto((docs / (name + '.html')).as_uri(), wait_until='load')
            page.evaluate('document.fonts.ready')
            title = page.title()
            page.pdf(path=str(docs / (name + '.pdf')), print_background=True,
                     prefer_css_page_size=True, outline=True, tagged=True,
                     display_header_footer=True, header_template='<span></span>',
                     footer_template='<div style="font:8px Arial;width:100%;text-align:center;color:#647089">'
                                     + title + ' · <span class="pageNumber"></span> / '
                                     '<span class="totalPages"></span></div>')
            if name == 'USER_GUIDE':
                page.screenshot(path=str(docs / 'user-guide/preview.png'))
            # Chromium resolves local hyperlinks to the build machine's absolute
            # checkout path. Keep source links portable in the shared PDF.
            target = docs / (name + '.pdf')
            with fitz.open(target) as portable:
                for sheet in portable:
                    for link in sheet.get_links():
                        uri = urlsplit(link.get('uri', ''))
                        if uri.scheme == 'file':
                            link['uri'] = os.path.relpath(unquote(uri.path), docs)
                            if uri.fragment:
                                link['uri'] += '#' + uri.fragment
                            sheet.update_link(link)
                portable.save(docs / (name + '.portable.pdf'), garbage=4, deflate=True)
            (docs / (name + '.portable.pdf')).replace(target)
            with fitz.open(docs / (name + '.pdf')) as pdf:
                outside = []
                for index, sheet in enumerate(pdf):
                    for block in sheet.get_text('blocks'):
                        if len(block) > 6 and block[6] == 0 and not sheet.rect.contains(fitz.Rect(block[:4])):
                            outside.append({'page': index + 1, 'text': block[4][:80]})
                report = {'pdf_pages': len(pdf), 'text_outside_page': outside,
                          'bookmarks': len(pdf.get_toc()),
                          'contents_links_resolve': all(link.get('page', 0) >= 0
                              for sheet in pdf for link in sheet.get_links() if link['kind'] == fitz.LINK_GOTO)}
                assert not outside, report
                assert report['contents_links_resolve'], report
            (report_dir / 'layout-check.json').write_text(json.dumps(report, indent=2) + '\n')
            results[name] = report
        browser.close()
    print(json.dumps(results))


if __name__ == '__main__':
    main()
