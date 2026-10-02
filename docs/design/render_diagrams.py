"""Render local Mermaid design sources to self-contained SVG and review PNGs.

Run with a Playwright environment and --mermaid-js pointing to Mermaid11.6.0.
No network or application API is used during rendering.
"""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from playwright.sync_api import sync_playwright


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mermaid-js',type=Path,required=True)
    args=parser.parse_args();folder=Path(__file__).with_name('diagrams');results=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1800,'height':1200},device_scale_factor=1)
        page.set_content('<html><body style="margin:0;background:white"></body></html>')
        page.add_script_tag(path=str(args.mermaid_js))
        page.evaluate('''mermaid.initialize({startOnLoad:false,securityLevel:'strict',theme:'base',htmlLabels:false,
          themeVariables:{fontFamily:'Arial',fontSize:'18px',primaryColor:'#f1edff',primaryTextColor:'#202b3d',
            primaryBorderColor:'#80739d',lineColor:'#62728b',secondaryColor:'#eaf2ff',tertiaryColor:'#eef6ef',
            clusterBkg:'#f8f9fc',clusterBorder:'#c8cfdb',edgeLabelBackground:'#ffffff',actorBkg:'#edf2fb',actorTextColor:'#20304c',
            actorBorder:'#7a8aa6',signalColor:'#52637c',signalTextColor:'#22304b',noteBkgColor:'#f5f3fb',noteTextColor:'#332c4a'},
          flowchart:{htmlLabels:false,useMaxWidth:false,curve:'linear',nodeSpacing:30,rankSpacing:38,subGraphTitleMargin:{top:10,bottom:18}},
          sequence:{useMaxWidth:false,actorFontSize:17,messageFontSize:16,noteFontSize:15,diagramMarginX:20,diagramMarginY:16}})''')
        for index,source in enumerate(sorted(folder.glob('*.mmd'))):
            text=source.read_text();rendered=page.evaluate('(async ([id,source])=> (await mermaid.render(id,source)).svg)',[f'design{index}',text])
            assert '<foreignObject' not in rendered,'Diagram must use portable SVG text'
            viewbox=re.search(r'viewBox="([^"]+)"',rendered)
            assert viewbox,source
            _,_,width,height=map(float,viewbox.group(1).split());width=math.ceil(width);height=math.ceil(height)
            rendered=re.sub(r'<svg\b([^>]*)>',lambda m:'<svg'+re.sub(r'\s(?:width|height)="[^"]*"','',m.group(1))+f' width="{width}" height="{height}">',rendered,count=1)
            target=source.with_suffix('.svg');target.write_text(rendered)
            preview=browser.new_page(viewport={'width':max(800,min(width+32,2200)),'height':max(600,min(height+32,1800))},device_scale_factor=1)
            preview.set_content('<html><body style="margin:0;background:white">'+rendered+'</body></html>')
            preview.locator('svg').screenshot(path=str(source.with_suffix('.png')))
            labels=preview.locator('svg text').count();assert labels>0,source
            preview.close()
            results.append({'file':source.name,'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                            'width':width,'height':height,'svg_text_elements':labels})
        browser.close()
    report={'mermaid_version':'11.6.0','renderer_sha256':hashlib.sha256(args.mermaid_js.read_bytes()).hexdigest(),'diagrams':results}
    (folder.parent/'diagram-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
