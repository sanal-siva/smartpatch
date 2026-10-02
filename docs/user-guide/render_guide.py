"""Render USER_GUIDE.md as portable HTML with embedded screenshots.

Requires Markdown 3.8.2 in a documentation environment, not the service.
Print the HTML with Chromium to create the companion PDF.
"""
import base64
import html
import json
import re
from pathlib import Path
import markdown

DOCS=Path(__file__).resolve().parent.parent
source=DOCS/'USER_GUIDE.md'
converter=markdown.Markdown(extensions=['extra','toc','sane_lists'],extension_configs={'toc':{'toc_depth':'2'}})
body=converter.convert(source.read_text())
body=re.sub(r'<h1[^>]*>.*?</h1>','',body,count=1,flags=re.S)

def figure(match):
    alt,path,caption=match.groups()
    raw=(DOCS/path).read_bytes()
    data='data:image/png;base64,'+base64.b64encode(raw).decode()
    return '<figure><a href="'+data+'" target="_blank" title="Open full-resolution screenshot"><img alt="'+alt+'" src="'+data+'"></a><figcaption>'+caption+'</figcaption></figure>'

body=re.sub(r'<p><img alt="([^"]*)" src="([^"]*)"\s*/></p>\s*<p><em>(.*?)</em></p>',figure,body,flags=re.S)
front,sections=body.split('<h2',1);sections='<h2'+sections
toc=converter.toc
css='''
:root{color-scheme:light;--ink:#1d2637;--muted:#58667b;--accent:#5e4ed8;--line:#dce1ed;--paper:#fff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#f3f5fa;color:var(--ink);font:16px/1.65 Arial,Helvetica,sans-serif}
a{color:#4534b8;text-decoration:none}a:hover{text-decoration:underline}header{margin-left:248px;padding:50px 58px 30px;background:linear-gradient(120deg,#f0edff,#fff);border-bottom:1px solid var(--line)}
.eyebrow{font-size:12px;letter-spacing:.15em;color:var(--accent);font-weight:bold}.hero-title{font-size:40px;line-height:1.12;letter-spacing:-.035em;margin:16px 0 24px;max-width:780px}
.front{max-width:950px}.front p{margin:12px 0}.front p:last-child{font-size:14px;color:var(--muted);border-left:3px solid #bbb2ee;padding-left:14px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}.toolbar a,.toolbar button{border:1px solid #c9c4e8;background:white;color:#4434a1;padding:9px 15px;border-radius:7px;font:600 13px Arial;cursor:pointer}
aside{position:fixed;left:0;top:0;bottom:0;width:248px;background:#151b2e;color:#eef0ff;padding:25px 20px;overflow:auto}aside .title{font-weight:bold;line-height:1.3;margin-bottom:24px}aside a{color:#ccd1e7;font-size:12px;display:block;padding:6px 0;line-height:1.45}aside a:hover{color:white}aside ul{list-style:none;padding-left:0}aside ul ul{padding-left:0}aside>.toc>ul>li>a{display:none}
main{margin-left:248px;padding:14px 58px 70px;max-width:1420px;background:var(--paper)}h2{font-size:27px;line-height:1.25;margin:56px 0 20px;padding-top:15px;border-top:2px solid #ebe7fd;scroll-margin-top:16px}h3{font-size:19px;line-height:1.4;margin:28px 0 12px;color:#3a326c}p{margin:12px 0}ul,ol{padding-left:26px}li{margin:8px 0}strong{font-weight:700}
table{border-collapse:collapse;width:100%;margin:18px 0 24px;table-layout:fixed;font-size:14px;line-height:1.55}th{background:#f0eefb;text-align:left;color:#342a6b}th,td{padding:10px 12px;border:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}td:first-child{font-weight:500}code{font: .9em/1.5 'DejaVu Sans Mono',Consolas,monospace;background:#f1f2f7;border-radius:3px;padding:1px 3px;overflow-wrap:anywhere}
pre{position:relative;border:1px solid #d7ddea;border-left:3px solid var(--accent);border-radius:5px;background:#f7f8fc;padding:16px 18px;margin:16px 0 22px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.6}pre code{padding:0;background:none;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}pre .copy{position:absolute;top:5px;right:6px;border:1px solid #d8d5ea;border-radius:4px;background:#fff;color:#5848bd;font-size:10px;padding:3px 7px;cursor:pointer}
blockquote{margin:20px 0;border-left:4px solid #a49aec;background:#f6f4ff;padding:10px 18px;color:#3d3659}figure{margin:25px 0 28px;text-align:center}figure img{max-width:100%;height:auto;border:1px solid #d7ddea;border-radius:7px;box-shadow:0 8px 22px #1a244511}figcaption{font-size:13px;color:var(--muted);line-height:1.5;margin:9px 0;text-align:left}.print-toc{display:none}.end{font-size:12px;color:var(--muted);margin-top:40px}
@media(max-width:1000px){aside{position:static;width:auto}aside .toc{columns:2}aside .title{margin-bottom:8px}header,main{margin-left:0;padding-left:24px;padding-right:24px}h2{font-size:24px}.hero-title{font-size:34px}}
@media print{@page{size:A4;margin:15mm 14mm 17mm}body{font-size:10pt;line-height:1.5;background:white;color:#192234}aside,.toolbar,.copy{display:none!important}header,main{margin:0;padding:0;max-width:none;background:white;border:0}.eyebrow{font-size:9pt}.hero-title{font-size:31pt;max-width:none}.front p:last-child{font-size:9pt}.print-toc{display:block;margin-top:20px}.print-toc .toc>ul>li>a{display:none}.print-toc ul{list-style:none;padding:0}.print-toc li{margin:3px 0}.print-toc a{font-size:10pt;color:#292142}h2{break-before:page;font-size:22pt;line-height:1.2;margin:0 0 16px;padding-top:10px;break-after:avoid}h3{font-size:13pt;margin:20px 0 9px;break-after:avoid}p{orphans:3;widows:3;margin:8px 0}table{font-size:8.7pt;line-height:1.45;margin:12px 0 17px}thead{display:table-header-group}tr{break-inside:avoid}th,td{padding:7px 8px}pre{break-inside:avoid;padding:11px 12px;margin:10px 0 16px}pre code{font-size:8.1pt;line-height:1.5}figure{break-inside:avoid;margin:16px 0 20px}figure img{max-height:148mm;max-width:100%;width:auto;box-shadow:none;border-radius:4px}figcaption{font-size:8.5pt}a{color:#392c8c}blockquote{break-inside:avoid}li{margin:5px 0}.end{font-size:8pt}}
'''
javascript='''document.querySelectorAll('pre').forEach(pre=>{const button=document.createElement('button');button.className='copy';button.textContent='Copy';button.onclick=async()=>{try{await navigator.clipboard.writeText(pre.querySelector('code').textContent);button.textContent='Copied';setTimeout(()=>button.textContent='Copy',1600)}catch{button.textContent='Select to copy'}};pre.append(button)});'''
result='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>SONiC Smart Patch User Guide</title><style>'+css+'</style></head><body>'
result+='<aside><div class="title">SONiC Smart Patch<br>User Guide</div>'+toc+'</aside><header><div class="eyebrow">COMMUNITY SONIC · OPERATOR GUIDE</div><h1 class="hero-title">SONiC Smart Patch<br>User Guide</h1><div class="front">'+front+'</div><div class="toolbar"><a href="USER_GUIDE.pdf">Open PDF</a><button onclick="window.print()">Print guide</button><a href="USER_GUIDE.md" download>Markdown source</a></div><nav class="print-toc"><strong>Contents</strong>'+toc+'</nav></header><main>'+sections+'<p class="end">Local project documentation. Screenshots are embedded in this HTML; no external assets or analytics are loaded.</p></main><script>'+javascript+'</script></body></html>'
(DOCS/'USER_GUIDE.html').write_text(result)
print(json.dumps({'html':str(DOCS/'USER_GUIDE.html'),'embedded_screenshots':result.count('data:image/png;base64,')//2,'bytes':len(result.encode())}))
