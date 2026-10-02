"""Small documentation client: verified TLS and file-based Smart Patch credentials.

Example: python smart_patch_api.py GET /api/v1/readiness
POST/PUT execute the requested API action; this is not a dry-run client.
"""
import argparse
import json
import os
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request,HTTPSHandler,HTTPRedirectHandler,build_opener


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise HTTPError(req.full_url,code,'Redirect rejected; use the final Smart Patch address',headers,fp)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('method',choices=['GET','POST','PUT'])
    parser.add_argument('path',help='Smart Patch API path, for example /api/v1/readiness')
    parser.add_argument('--json-file',type=Path)
    args=parser.parse_args()
    if not args.path.startswith('/api/v1/') or '://' in args.path:
        parser.error('Use a /api/v1/ path, not a URL')
    base=os.environ.get('SMART_PATCH_URL','').rstrip('/')
    if not base or '<' in base or '>' in base:
        parser.error('Set SMART_PATCH_URL to your actual HTTPS service origin, replacing any placeholder')
    parts=urlsplit(base)
    if parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path:
        parser.error('SMART_PATCH_URL must be an HTTPS origin without credentials or a path')
    try:
        token=Path(os.environ['SMART_PATCH_TOKEN_FILE']).read_text().strip()
        context=ssl.create_default_context(cafile=os.environ['SMART_PATCH_CA_FILE'])
        if not token or any(c.isspace() for c in token):raise ValueError('Token file does not contain one bearer token')
        payload=json.loads(args.json_file.read_text()) if args.json_file else None
        if args.method=='GET' and payload is not None:raise ValueError('GET does not take a JSON body')
        body=json.dumps(payload).encode() if payload is not None else None
        headers={'Authorization':'Bearer '+token,'Accept':'application/json'}
        if body is not None:headers['Content-Type']='application/json'
        request=Request(base+args.path,data=body,headers=headers,method=args.method)
        with build_opener(NoRedirects(),HTTPSHandler(context=context)).open(request,timeout=30) as response:
            raw=response.read(16*1024*1024+1)
            if len(raw)>16*1024*1024:raise ValueError('Response exceeds documentation client limit')
        print(json.dumps(json.loads(raw),indent=2))
    except HTTPError as exc:
        print('Smart Patch HTTP '+str(exc.code)+': '+exc.read(4096).decode('utf-8',errors='replace'),file=sys.stderr)
        return 1
    except (OSError,ValueError,KeyError) as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
