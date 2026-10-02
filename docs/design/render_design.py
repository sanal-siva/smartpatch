"""Render the canonical detailed design with inline vector diagrams.

Uses Markdown3.8.2 and the project's documentation style. No network requests.
"""
import ast
import json
import re
from pathlib import Path
import markdown

DOCS=Path(__file__).resolve().parent.parent
source=DOCS/'DETAILED_DESIGN.md'
converter=markdown.Markdown(extensions=['extra','toc','sane_lists'],extension_configs={'toc':{'toc_depth':'2'}})
body=converter.convert(source.read_text())
body=re.sub(r'<h1[^>]*>.*?</h1>','',body,count=1,flags=re.S)
style_source=ast.parse((DOCS/'user-guide/render_guide.py').read_text())
css=next(ast.literal_eval(n.value) for n in style_source.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='css' for t in n.targets))
figures=[]

def figure(match):
    alt,path,caption=match.groups();svg=(DOCS/path).read_text()
    values=list(map(float,re.search(r'viewBox="([^"]+)"',svg).group(1).split()))
    width,height=values[2:];orientation='landscape' if width>height*1.15 else 'portrait'
    figures.append({'source':path,'width':width,'height':height,'print_orientation':orientation})
    return f'<figure class="diagram diagram-{orientation}"><div class="diagram-title">{alt}</div><div class="diagram-vector">{svg}</div><figcaption>{caption} <a href="{path}" target="_blank">Open full-size SVG</a>.</figcaption></figure>'

body=re.sub(r'<p><img alt="([^"]*)" src="([^"]*)"\s*/></p>\s*<p><em>(.*?)</em></p>',figure,body,flags=re.S)
front,sections=body.split('<h2',1);sections='<h2'+sections
css+='''
.diagram{background:white}.diagram-title{font-size:17px;font-weight:bold;text-align:left;margin:12px 0;color:#382970}.diagram-vector{display:flex;justify-content:center}.diagram-vector>svg{max-width:100%;height:auto}.diagram figcaption a{white-space:nowrap}
@media print{
 @page design-landscape{size:A3 landscape;margin:13mm 13mm 17mm}
 @page design-portrait{size:A3 portrait;margin:13mm 13mm 17mm}
 .diagram{break-before:page;break-after:page;break-inside:avoid;margin:0;padding:0;border:0}
 .diagram-landscape{page:design-landscape;width:394mm}
 .diagram-portrait{page:design-portrait;width:271mm}
 .diagram-title{font-size:15pt;margin:0 0 10mm}
 .diagram-landscape .diagram-vector>svg{max-width:390mm;max-height:220mm;width:auto;height:auto}
 .diagram-portrait .diagram-vector>svg{max-width:267mm;max-height:337mm;width:auto;height:auto}
 .diagram figcaption{font-size:10pt;margin-top:6mm;line-height:1.4}
}
'''
javascript='''document.querySelectorAll('pre').forEach(pre=>{const button=document.createElement('button');button.className='copy';button.textContent='Copy';button.onclick=async()=>{try{await navigator.clipboard.writeText(pre.querySelector('code').textContent);button.textContent='Copied';setTimeout(()=>button.textContent='Copy',1600)}catch{button.textContent='Select to copy'}};pre.append(button)});'''
page='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>SONiC Smart Patch Detailed Design</title><style>'+css+'</style></head><body>'
page+='<aside><div class="title">SONiC Smart Patch<br>Detailed Design</div>'+converter.toc+'</aside><header><div class="eyebrow">COMMUNITY SONIC · ENGINEERING DESIGN</div><h1 class="hero-title">SONiC Smart Patch<br>Detailed Design</h1><div class="front">'+front+'</div><div class="toolbar"><a href="DETAILED_DESIGN.pdf">Open PDF</a><button onclick="window.print()">Print design</button><a href="DETAILED_DESIGN.md" download>Markdown source</a></div><nav class="print-toc"><strong>Contents</strong>'+converter.toc+'</nav></header><main>'+sections+'<p class="end">Diagrams use inline vectors and larger PDF pages for legibility. All application behavior is described from the recorded source snapshot; no runtime or deployment action is implied.</p></main><script>'+javascript+'</script></body></html>'
(DOCS/'DETAILED_DESIGN.html').write_text(page)
(DOCS/'design/render-manifest.json').write_text(json.dumps({'figures':figures,'html_bytes':len(page.encode())},indent=2)+'\n')
print(json.dumps({'html':str(DOCS/'DETAILED_DESIGN.html'),'figures':len(figures),'bytes':len(page.encode())}))
