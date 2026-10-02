"""Opt-in central release workflow acceptance with real Grype and signed Debian metadata.

The input is a saved, reported inventory sample. This does not register a release
in the live service, enable AI, install packages, or contact a switch.
"""
import argparse
import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
from datetime import datetime,timezone
from pathlib import Path

import requests

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from app.config import Settings
from app.runtime import Runtime
from app.services.sbom_parser import normalize_inventory,scope_to_sbom

# Published by Debian FTP masters: https://ftp-master.debian.org/keys.html.
# These are isolated test trust anchors; no host/system/live-service trust changes.
KEYS={
    'archive-key-12.asc':'B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8',
    'archive-key-13.asc':'04B54C3CDCA79751B16BC6B5225629DF75B188BD',
    'release-13.asc':'41587F7DB8C774BCCF131416762F67A0B2C39DE4',
}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    started=time.monotonic();report={'started_at':datetime.now(timezone.utc).isoformat(),
        'mode':'isolated deterministic release workflow; AI disabled',
        'success':False,'live_state_modified':False,'switches_contacted':False,
        'limitations':['Reported inventory sample is not a complete signed SONiC release SBOM.',
            'No API-provider analysis, vulnerability ground-truth accuracy, installation or remediation is measured.',
            'Runtime and scanner child peak RSS are separate process maxima, not a concurrent total.']}
    runtime=None
    try:
        fixture=json.loads(args.input.read_text())
        components=[{**c,'id':c['component_id'],'arch':c.get('architecture','amd64'),'ecosystem':'deb'} for c in fixture['components']]
        assert len({c['name'] for c in components})>=200
        report['input']={key:fixture.get(key) for key in ('label','device_id','inventory_digest','sonic_version','collected_at')}
        report['input'].update(unique_package_names=len({c['name'] for c in components}),
                               source_sha256=hashlib.sha256(args.input.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory(prefix='smart-patch-real-release-') as directory:
            temporary=Path(directory);key_home=temporary/'gnupg';key_home.mkdir(mode=0o700)
            session=requests.Session();session.trust_env=False;keyring=temporary/'debian-test-keys.gpg';keys=[]
            for filename,fingerprint in KEYS.items():
                url='https://ftp-master.debian.org/keys/'+filename
                response=session.get(url,timeout=30);response.raise_for_status()
                assert len(response.content)<256*1024
                key=temporary/filename;key.write_bytes(response.content)
                base=['gpg','--no-options','--homedir',str(key_home),'--batch']
                shown=subprocess.run(base+['--with-colons','--import-options','show-only','--import',str(key)],
                    capture_output=True,text=True,check=True,timeout=15).stdout
                observed=[line.split(':')[9] for line in shown.splitlines() if line.startswith('fpr:')]
                assert observed and observed[0]==fingerprint,(filename,observed)
                binary=subprocess.run(base+['--dearmor',str(key)],capture_output=True,check=True,timeout=15)
                with keyring.open('ab') as out:out.write(key.with_suffix('.asc.gpg').read_bytes())
                keys.append({'source_url':url,'expected_primary_fingerprint':fingerprint,
                             'observed_fingerprints':observed,'sha256':hashlib.sha256(response.content).hexdigest()})
            report['key_provenance']=keys
            scope=normalize_inventory({'scopes':[{'id':'host','kind':'host','distro':{'name':'debian','version':'13'},
                                                'components':components}]})['scopes'][0]
            sbom=scope_to_sbom(scope);sbom_path=args.output/'sample-sbom.json'
            # scope_to_sbom is an internal scanner input. A standalone import
            # also needs explicit distro and rooted sample-containment metadata.
            sbom['metadata']={'component':{'type':'application','name':'Reported host inventory sample',
                                           'bom-ref':'smart-patch-acceptance-sample-root'}}
            sbom['dependencies']=[{'ref':'smart-patch-acceptance-sample-root',
                                   'dependsOn':[c['bom-ref'] for c in sbom['components']]}]
            for item in sbom['components']:
                item['properties'].extend([{'name':'smart-patch:distro:name','value':'debian'},
                                           {'name':'smart-patch:distro:version','value':'13'}])
            sbom_path.write_text(json.dumps(sbom,indent=2)+'\n')
            settings=Settings(_env_file=None,state_dir=temporary/'state',database_url='sqlite:///'+str(temporary/'state.db'),
                jobs_enabled=False,ai_enabled=False,ai_api_key='',source_roots=[str(ROOT.parent/'sonic-buildimage')],
                scanner_binary=str(ROOT/'.tools/grype-0.112.0/grype'),scanner_db_dir=str(ROOT/'.state/grype-db'))
            runtime=Runtime(settings);runtime.scanner_info=runtime.pipeline.scanner.status()
            assert runtime.scanner_info['status']=='ready',runtime.scanner_info
            release_id='acceptance:reported-host-250'
            runtime.store.put('release',release_id,{'release_id':release_id,'sbom_source':str(sbom_path.resolve()),
                'source_revision':'b7f8ed799a94244427817dfe91716e208326d705',
                'repositories':[{'base_url':'https://deb.debian.org/debian','suite':'trixie',
                    'components':['main'],'architectures':['amd64'],'keyring':str(keyring)}]})
            operation=runtime.enqueue('release_sync',{'release_id':release_id});operation=runtime.store.claim()
            sync_started=time.monotonic();result=runtime._job_release_sync(operation)
            runtime.store.update_operation(operation['id'],'completed',result=result)
            duration=time.monotonic()-sync_started
            findings=runtime.store.list('release_finding',owner=release_id)
            packages=runtime.store.list('package',owner=release_id)
            history=runtime.store.list('release_assessment_history')
            report.update(release_duration_seconds=round(duration,3),result=result,scanner=runtime.scanner_info,
                committed_packages=len(packages),committed_findings=len(findings),history_rows=len(history),
                repository_packages_available=sum(p.get('repository_availability',{}).get('status')=='available' for p in packages),
                package_fields_complete=all(all(k in p for k in ('package_type','repository_path','cves_fixed','field_unknown_reasons')) for p in packages),
                operation_logs=runtime.store.operation(operation['id']).get('logs',[]),
                under_15_minutes=duration<900,
                signed_repository_evidence=[e for e in runtime.store.list('evidence') if e.get('type')=='signed_repository_release'])
            assert result.get('accepted',True) and result['coverage']['complete'],result
            assert result['repository_coverage']['complete'],result['repository_errors']
            assert len(packages)>=200 and len(history)==len(findings)
            assert report['package_fields_complete'] and report['under_15_minutes']
            report['success']=True
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)[:1500]}
    finally:
        if runtime:runtime.stop()
        report.update(completed_at=datetime.now(timezone.utc).isoformat(),overall_seconds=round(time.monotonic()-started,3),
            parent_max_rss_mib=round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,3),
            child_max_rss_mib=round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss/1024,3))
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:report.get(k) for k in ('success','release_duration_seconds','overall_seconds','committed_packages',
            'committed_findings','repository_packages_available','parent_max_rss_mib','child_max_rss_mib','error')}))
    return 0 if report['success'] else 1


if __name__=='__main__':raise SystemExit(main())
