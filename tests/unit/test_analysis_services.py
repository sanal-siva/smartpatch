import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.services.ai_client import AIClient
from app.services.assessment import AssessmentEngine
from app.services.pipeline import AnalysisPipeline
from app.services.process import ProcessError, run_bounded
from app.services.scanner import GrypeScanner, ScanError
from app.services.sbom_parser import SBOMParser, SBOMValidationError, normalize_inventory, scope_to_sbom
from app.services.source_tools import SourceTools, EvidenceToolError, compare_versions
from app.services.github_sync import parse_sonic_release


def inventory():
    return {'build_id': 'build-a', 'scopes': [{'id': 'host', 'distro': {'name': 'debian', 'version': '12'},
            'components': [{'id': 'openssl-host', 'name': 'openssl', 'version': '3.0.1-1', 'ecosystem': 'deb',
                            'arch': 'amd64', 'source_name': 'openssl', 'source_version': '3.0.1-1'}]}]}


def finding():
    return {'id': 'f1', 'cve_id': 'CVE-2026-1234', 'scope_id': 'host', 'component_id': 'openssl-host',
            'package_name': 'openssl', 'affected_version': '3.0.1-1', 'cvss_score': None,
            'fixed_versions': ['3.0.2-1'], 'advisory_namespace': 'debian:distro:debian:12',
            'component': inventory()['scopes'][0]['components'][0], 'distro': {'name': 'debian', 'version': '12'},
            'match_details': [{'type': 'exact-direct-match'}], 'evidence_ids': ['scan-1']}


class ParserTests(unittest.TestCase):
    def test_missing_or_invalid_source_never_becomes_sample(self):
        with self.assertRaises(FileNotFoundError):
            SBOMParser().load_sbom('/a/nonexistent/smart-patch-sbom.json')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.json'
            path.write_text('{\n "broken": }')
            with self.assertRaises(SBOMValidationError) as error:
                SBOMParser().load_sbom(path)
            self.assertEqual(error.exception.line, 2)

    def test_dangling_cyclonedx_reference_rejected(self):
        doc = scope_to_sbom(normalize_inventory(inventory())['scopes'][0])
        doc['dependencies'] = [{'ref': 'openssl-host', 'dependsOn': ['absent']}]
        with self.assertRaises(SBOMValidationError):
            SBOMParser().validate(doc)

    def test_spdx_packages_are_preserved(self):
        doc = {'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT', 'documentNamespace': 'https://example.test/bom/1',
               'name': 'test-sbom', 'dataLicense': 'CC0-1.0',
               'creationInfo': {'creators': ['Tool: Smart Patch-test'], 'created': '2026-01-01T00:00:00Z'},
               'packages': [{'SPDXID': 'SPDXRef-pkg', 'name': 'curl', 'versionInfo': '1:7.0-2',
                             'downloadLocation': 'NOASSERTION',
                             'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': 'pkg:deb/debian/curl@1%3A7.0-2?arch=arm64'}]}]}
        package = SBOMParser().parse_packages(doc)[0]
        self.assertEqual((package['version'], package['arch'], package['id']), ('1:7.0-2', 'arm64', 'SPDXRef-pkg'))

    def test_normalization_immutable_and_source_version_preserved(self):
        source = inventory()
        original = copy.deepcopy(source)
        normalized = normalize_inventory(source)
        sbom = scope_to_sbom(normalized['scopes'][0])
        self.assertEqual(source, original)
        self.assertEqual(sbom['components'][0]['bom-ref'], 'openssl-host')
        props = {p['name']: p['value'] for p in sbom['components'][0]['properties']}
        self.assertEqual(props['syft:metadata:sourceVersion'], '3.0.1-1')

    def test_containment_scopes_are_separate(self):
        doc = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [
            {'type': 'container', 'name': 'bgp', 'bom-ref': 'bgp'},
            {'type': 'library', 'name': 'openssl', 'version': '1', 'bom-ref': 'lib'}],
            'dependencies': [{'ref': 'bgp', 'dependsOn': ['lib']}]}
        result = SBOMParser().to_inventory(doc)
        self.assertEqual(result['scopes'][0]['components'], [])
        self.assertEqual(result['scopes'][1]['components'][0]['id'], 'lib')

    def test_rooted_shared_component_keeps_both_host_and_container_occurrences(self):
        document = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
            'metadata': {'component': {'type': 'application', 'name': 'sonic-image', 'bom-ref': 'root'}},
            'components': [
                {'type': 'operating-system', 'name': 'host-image', 'bom-ref': 'hostfs', 'properties': [{'name': 'sonic:scope', 'value': 'host-image'}]},
                {'type': 'container', 'name': 'docker-frr', 'bom-ref': 'bgp', 'properties': [{'name': 'sonic:scope', 'value': 'dockers/docker-frr'}],
                 'hashes': [{'alg': 'SHA-256', 'content': 'a' * 64}]},
                {'type': 'library', 'name': 'shared', 'version': '1', 'bom-ref': 'shared'}],
            'dependencies': [{'ref': 'root', 'dependsOn': ['hostfs', 'bgp']}, {'ref': 'hostfs', 'dependsOn': ['shared']},
                             {'ref': 'bgp', 'dependsOn': ['shared']}]}
        result = SBOMParser().to_inventory(document)
        host, container = result['scopes']
        self.assertEqual([p['id'] for p in host['components']], ['shared'])
        self.assertEqual([p['id'] for p in container['components']], ['shared'])
        self.assertEqual(host['scope_assignment'], 'explicit_root_containment')
        self.assertEqual(container['properties']['sonic:scope'], 'dockers/docker-frr')
        self.assertEqual(container['hashes'][0]['content'], 'a' * 64)
        self.assertIsNone(container['image_digest'])  # archive hash is not a runtime image digest
        self.assertEqual(result['coverage_warnings'], [])

    def test_raw_sbom_hash_is_exact_and_dict_import_does_not_invent_it(self):
        import hashlib
        document = scope_to_sbom(normalize_inventory(inventory())['scopes'][0])
        parser = SBOMParser()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sbom.json'
            raw = json.dumps(document, indent=3).encode()
            path.write_bytes(raw)
            parser.load_sbom(path)
            self.assertEqual(parser.source_sha256, hashlib.sha256(raw).hexdigest())
        parser.load_sbom(document)
        self.assertIsNone(parser.source_sha256)

    def test_full_schema_rejects_invalid_optional_field_offline(self):
        doc = scope_to_sbom(normalize_inventory(inventory())['scopes'][0])
        doc['components'][0]['hashes'] = [{'alg': 'SHA-256', 'content': 'not-a-hash'}]
        with self.assertRaises(SBOMValidationError):
            SBOMParser().validate(doc)

    def test_bundled_license_reference_resolves_without_network(self):
        doc = scope_to_sbom(normalize_inventory(inventory())['scopes'][0])
        doc['components'][0]['licenses'] = [{'license': {'id': 'Apache-2.0'}}]
        self.assertTrue(SBOMParser().validate(doc)['schema_validated'])


class ProcessTests(unittest.TestCase):
    def test_output_and_wall_time_are_bounded(self):
        with self.assertRaises(ProcessError):
            run_bounded([sys.executable, '-c', 'print("x" * 10000)'], max_bytes=100)
        start = time.monotonic()
        with self.assertRaises(ProcessError):
            run_bounded([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.15)
        self.assertLess(time.monotonic() - start, 2)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.binary = Path(self.directory.name) / 'grype-fixture'
        self.binary.write_text('''#!/usr/bin/env python3
import json, sys
if sys.argv[1] == 'version': print(json.dumps({'version': 'fixture'})); sys.exit()
if sys.argv[1] == 'db': print(json.dumps({'built': '2026-01-01T00:00:00Z', 'checksum': 'db1', 'valid': True})); sys.exit()
doc = json.load(open(sys.argv[1][5:]))
c = doc['components'][0]
print(json.dumps({'descriptor': {'version': 'fixture', 'db': {'checksum':'db1'}}, 'matches': [{
'artifact': {'id': c['bom-ref'], 'name': c['name'], 'version': c['version'], 'purl': c['purl']},
'vulnerability': {'id': 'CVE-2026-1234', 'namespace': 'debian:distro:debian:12', 'severity': 'High',
'cvss': [{'metrics': {'baseScore': 7.5}}], 'fix': {'versions':['3.0.2-1'], 'state':'fixed'}},
'matchDetails': [{'type':'exact-direct-match'}]}]}))
''')
        self.binary.chmod(0o755)

    def tearDown(self):
        self.directory.cleanup()

    def test_grype_json_cvss_fix_and_scope(self):
        result = GrypeScanner(str(self.binary)).scan_scope(normalize_inventory(inventory())['scopes'][0])
        actual = result['findings'][0]
        self.assertEqual(actual['cvss_score'], 7.5)
        self.assertEqual(actual['fixed_versions'], ['3.0.2-1'])
        self.assertEqual(actual['component_id'], 'openssl-host')

    def test_os_scope_requires_distro(self):
        scope = normalize_inventory(inventory())['scopes'][0]
        scope['distro'] = {}
        with self.assertRaises(ScanError):
            GrypeScanner(str(self.binary)).scan_scope(scope)

    def test_pipeline_no_key_no_fake_ai_and_broken_scope_partial(self):
        source = inventory()
        source['scopes'].append({'id': 'container', 'distro': {}, 'components': copy.deepcopy(source['scopes'][0]['components'])})
        result = AnalysisPipeline(scanner_binary=str(self.binary)).analyze(source)
        self.assertFalse(result['coverage']['complete'])
        self.assertEqual(result['coverage']['scopes_scanned'], 1)
        self.assertEqual(result['scanner']['status'], 'partial')
        self.assertEqual(result['findings'][0]['applicability'], 'under_investigation')
        self.assertEqual(result['findings'][0]['advisory_match_status'], 'exact_distribution_match')
        self.assertEqual(result['ai_usage']['calls'], 0)

    def test_failure_does_not_report_clean(self):
        result = AnalysisPipeline(scanner_binary='/missing/grype').analyze(inventory())
        self.assertEqual(result['scanner']['status'], 'failed')
        self.assertFalse(result['coverage']['complete'])
        self.assertTrue(result['errors'])

    def test_unknown_source_never_substitutes_head(self):
        source = inventory()
        source['scopes'][0]['components'][0]['custom_build'] = True
        pipeline = AnalysisPipeline(scanner_binary=str(self.binary))
        seen = []
        def investigate(item, evidence, tools):
            seen.append(tools.default_revision)
            return {'success': False, 'state': 'unavailable', 'error': 'fixture',
                    'usage': {'calls': 0, 'tool_calls': 0, 'input_tokens': 0, 'output_tokens': 0, 'input_characters': 0}}
        with patch.object(pipeline.ai, 'health', return_value={'configured': True}), patch.object(pipeline.ai, 'investigate', side_effect=investigate):
            pipeline.analyze(source)
            pipeline.analyze(source, {'source_revision': 'a' * 40})
            pipeline.settings['source_revision'] = 'b' * 40
            pipeline.analyze(source, {'source_revision': ''})
        self.assertEqual(seen, [None, 'a' * 40, None])

    def test_failed_inventory_scope_remains_partial_despite_successful_scan(self):
        fact = {'collector': 'inventory', 'status': 'observed', 'inventory_digest': 'd1',
                'collected_at': datetime.now(timezone.utc).isoformat(),
                'value': [{'scope': 'host', 'status': 'unknown', 'error': 'dpkg timeout'}]}
        result = AnalysisPipeline(scanner_binary=str(self.binary)).analyze(inventory(), {'inventory_digest': 'd1', 'runtime_facts': [fact]})
        self.assertEqual(result['coverage']['scopes_scanned'], 1)
        self.assertFalse(result['coverage']['complete'])
        self.assertEqual(result['coverage']['inventory_profile'], 'debian_package_metadata')
        self.assertEqual(result['errors'][0]['stage'], 'inventory_collection')
        self.assertTrue(result['findings'])

    def test_stale_or_wrong_digest_coverage_cannot_be_complete(self):
        fact = {'collector': 'inventory', 'status': 'observed', 'inventory_digest': 'd1',
                'collected_at': (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                'value': [{'scope': 'host', 'status': 'complete'}]}
        pipeline = AnalysisPipeline(scanner_binary=str(self.binary))
        stale = pipeline.analyze(inventory(), {'inventory_digest': 'd1', 'runtime_facts': [fact]})
        self.assertFalse(stale['coverage']['complete'])
        fact['collected_at'] = datetime.now(timezone.utc).isoformat()
        mismatched = pipeline.analyze(inventory(), {'inventory_digest': 'other', 'runtime_facts': [fact]})
        self.assertFalse(mismatched['coverage']['complete'])

    def test_referenced_review_evidence_survives_rescan_without_unrelated_records(self):
        from app.services.sbom_parser import stable_id
        review = {'build_id': 'build-a', 'device_id': 'leaf1', 'inventory_digest': 'd1', 'context_hash': stable_id([]),
                  'scope_id': 'host', 'component_id': 'openssl-host', 'cve_id': 'CVE-2026-1234', 'version': '3.0.1-1',
                  'verification': 'reviewed', 'applicability': 'not_affected', 'justification': 'Reviewed build evidence',
                  'vex_justification': 'vulnerable_code_not_present', 'evidence_ids': ['review1']}
        pipeline = AnalysisPipeline(scanner_binary=str(self.binary), settings={'trusted_assessments': [review],
            'trusted_evidence': [{'id': 'review1', 'type': 'operator_review'}, {'id': 'unrelated', 'type': 'operator_review'}]})
        result = pipeline.analyze(inventory(), {'device_id': 'leaf1', 'inventory_digest': 'd1'})
        self.assertEqual(result['findings'][0]['applicability'], 'not_affected')
        self.assertEqual(result['findings'][0]['vex_justification'], 'vulnerable_code_not_present')
        ids = {record['id'] for record in result['evidence']}
        self.assertIn('review1', ids)
        self.assertNotIn('unrelated', ids)


class AssessmentTests(unittest.TestCase):
    def test_null_score_preserved_and_no_auto_heal(self):
        result = AssessmentEngine().evaluate(finding(), 'build-a', {'artifact_verified': True})
        self.assertIsNone(result['risk_score'])
        self.assertEqual(result['action_type'], 'maintenance_window')
        self.assertEqual(result['candidate_fixed_versions'], ['3.0.2-1'])

    def test_patch_claim_alone_does_not_suppress(self):
        item = finding()
        item['component']['patches'] = [{'cve': item['cve_id'], 'verified': True}]
        result = AssessmentEngine().evaluate(item, 'build-a')
        self.assertEqual(result['applicability'], 'under_investigation')

    def test_reviewed_record_must_match_scope_build_version(self):
        record = {'build_id': 'build-a', 'scope_id': 'host', 'component_id': 'openssl-host',
                  'cve_id': 'CVE-2026-1234', 'version': '3.0.1-1', 'evidence_ids': ['verified-patch'],
                  'verification': 'artifact_verified', 'applicability': 'fixed', 'justification': 'Verified artifact patch'}
        engine = AssessmentEngine([record])
        self.assertEqual(engine.evaluate(finding(), 'build-a', {'artifact_verified': True})['applicability'], 'fixed')
        self.assertNotEqual(engine.evaluate(finding(), 'build-b')['applicability'], 'fixed')
        changed = finding()
        changed['scope_id'] = 'bgp'
        self.assertNotEqual(engine.evaluate(changed, 'build-a')['applicability'], 'fixed')

    def test_debian_epoch_and_backport_order(self):
        self.assertEqual(compare_versions('deb', '1:1.0-1', '9.0-1'), 1)
        self.assertEqual(compare_versions('deb', '1.0-1~bpo12+1', '1.0-1'), -1)

    def test_device_review_scope_and_later_retraction(self):
        base = {'build_id': 'build-a', 'scope_id': 'host', 'component_id': 'openssl-host', 'cve_id': 'CVE-2026-1234',
                'version': '3.0.1-1', 'evidence_ids': ['review1'], 'verification': 'reviewed',
                'device_id': 'leaf1', 'inventory_digest': 'd1', 'context_hash': 'facts1',
                'applicability': 'not_affected', 'justification': 'Verified disabled feature',
                'vex_justification': 'vulnerable_code_not_in_execute_path', 'created_at': '2026-09-01T00:00:00Z'}
        context = {'device_id': 'leaf1', 'inventory_digest': 'd1', 'context_hash': 'facts1'}
        engine = AssessmentEngine([base])
        self.assertEqual(engine.evaluate(finding(), 'build-a', context)['applicability'], 'not_affected')
        self.assertEqual(engine.evaluate(finding(), 'build-a', {**context, 'device_id': 'leaf2'})['applicability'], 'under_investigation')
        self.assertEqual(engine.evaluate(finding(), 'build-a', {**context, 'context_hash': 'facts2'})['applicability'], 'under_investigation')
        newer = {**base, 'applicability': 'under_investigation', 'justification': 'Earlier exemption withdrawn', 'created_at': '2026-09-02T00:00:00Z'}
        self.assertEqual(AssessmentEngine([base, newer]).evaluate(finding(), 'build-a', context)['applicability'], 'under_investigation')

    def test_stale_mismatched_and_fresh_exposure(self):
        fact = {'name': 'exposure', 'scope_id': 'host', 'component_id': 'openssl-host', 'status': 'observed',
                'inventory_digest': 'inventory-a', 'value': 'constrained', 'ttl_seconds': 60,
                'collected_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}
        context = {'inventory_digest': 'inventory-a', 'runtime_facts': [fact]}
        self.assertEqual(AssessmentEngine().evaluate(finding(), 'build-a', context)['exposure'], 'unknown')
        fact['collected_at'] = datetime.now(timezone.utc).isoformat()
        self.assertEqual(AssessmentEngine().evaluate(finding(), 'build-a', context)['exposure'], 'constrained')
        context['inventory_digest'] = 'inventory-b'
        self.assertEqual(AssessmentEngine().evaluate(finding(), 'build-a', context)['exposure'], 'unknown')


class SourceToolsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        for args in [['init', '-q'], ['config', 'user.email', 'test@example.test'], ['config', 'user.name', 'Test']]:
            subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)
        (self.root / 'source.c').write_text('int vulnerable_symbol(void) { return 1; }\n')
        (self.root / 'escape').symlink_to('/etc/passwd')
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'commit', '-qm', 'fixture'], check=True)
        self.revision = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD'], text=True).strip()
        self.tools = SourceTools({'sonic': str(self.root)})

    def tearDown(self):
        self.directory.cleanup()

    def test_reads_exact_commit_not_worktree(self):
        (self.root / 'source.c').write_text('changed\n')
        record = self.tools.call('get_source', {'root': 'sonic', 'revision': self.revision, 'path': 'source.c'})
        self.assertIn('vulnerable_symbol', record['data']['text'])
        self.assertEqual(record['provenance']['revision'], self.revision)

    def test_paths_symlinks_and_mutable_refs_rejected(self):
        for path, revision in [('../secret', self.revision), ('/etc/passwd', self.revision), ('escape', self.revision), ('source.c', 'HEAD')]:
            with self.assertRaises(EvidenceToolError):
                self.tools.call('get_source', {'root': 'sonic', 'revision': revision, 'path': path})

    def test_unknown_tool_rejected(self):
        with self.assertRaises(EvidenceToolError):
            self.tools.call('run_shell', {'command': 'echo unsafe'})

    def test_no_roots_exposes_only_valid_fact_and_version_tools(self):
        import jsonschema
        tools = SourceTools().list_tools()
        self.assertNotIn('get_source', [t['function']['name'] for t in tools])
        for tool in tools:
            jsonschema.Draft7Validator.check_schema(tool['function']['parameters'])

    def test_real_agent_fact_aliases_and_saved_advisory_tools(self):
        tools = SourceTools(runtime_facts=[{'collector': 'listeners', 'scope': 'host', 'status': 'observed', 'value': ['tcp:22']}],
                            components=[{'id': 'component1', 'scope_id': 'host', 'name': 'openssl', 'version': '3.0.1'}],
                            evidence_records=[{'id': 'scan1', 'cve_id': 'CVE-2026-1234', 'scope_id': 'host', 'component_id': 'component1',
                                'data': {'vulnerability': {'id': 'CVE-2026-1234', 'description': 'Relevant vulnerable code prerequisite'}}}])
        facts = tools.call('get_runtime_facts', {'names': ['listeners'], 'scope_id': 'host'})
        self.assertEqual(facts['data']['missing'], [])
        advisory = tools.call('get_advisory', {'cve_id': 'CVE-2026-1234'})
        self.assertEqual(advisory['data']['advisories'][0]['evidence_id'], 'scan1')
        component = tools.call('get_component', {'component_id': 'component1', 'scope_id': 'host'})
        self.assertEqual(component['data']['version'], '3.0.1')
        wrong = tools.call('get_component', {'component_id': 'component1', 'scope_id': 'bgp'})
        self.assertEqual(wrong['data']['status'], 'unknown')

    def test_runtime_requests_are_scoped_deduplicated_and_bounded(self):
        tools = SourceTools(components=[{'id': 'component1', 'scope_id': 'host'}])
        with self.assertRaises(EvidenceToolError):
            tools.call('request_runtime_facts', {'collector': 'listeners', 'scope_id': 'host'})
        tools.allow_runtime_requests, tools.inventory_digest, tools.max_fact_requests = True, 'd1', 1
        tools.allowed_scopes = {'host'}
        for arguments in [{'collector': 'shell', 'scope_id': 'host'},
                          {'collector': 'listeners', 'scope_id': 'not-enrolled'},
                          {'collector': 'listeners', 'scope_id': 'host', 'component_id': 'wrong'}]:
            with self.assertRaises(EvidenceToolError):
                tools.call('request_runtime_facts', arguments)
        first = tools.call('request_runtime_facts', {'collector': 'listeners', 'scope_id': 'host', 'component_id': 'component1'})
        again = tools.call('request_runtime_facts', {'collector': 'listeners', 'scope_id': 'host'})
        self.assertEqual(first['data']['status'], 'pending')
        self.assertEqual(first['data']['request_id'], again['data']['request_id'])
        self.assertEqual(len(tools.requests), 1)
        self.assertEqual(next(iter(tools.requests.values()))['args'], {})
        with self.assertRaises(EvidenceToolError):
            tools.call('request_runtime_facts', {'collector': 'services', 'scope_id': 'host'})

    def test_runtime_request_uses_fresh_observation_and_does_not_spin_on_failure(self):
        tools = SourceTools(runtime_facts=[{'collector': 'listeners', 'scope': 'host', 'status': 'observed',
            'inventory_digest': 'd1', 'collected_at': datetime.now(timezone.utc).isoformat(), 'value': ['tcp:22']}])
        tools.allow_runtime_requests, tools.inventory_digest, tools.allowed_scopes = True, 'd1', {'host'}
        observed = tools.call('request_runtime_facts', {'collector': 'listeners', 'scope_id': 'host'})
        self.assertEqual(observed['data']['status'], 'observed')
        self.assertEqual(tools.requests, {})
        tools.runtime_facts[0]['status'] = 'unknown'
        failed = tools.call('request_runtime_facts', {'collector': 'listeners', 'scope_id': 'host'})
        self.assertEqual(failed['data']['status'], 'unknown')
        self.assertEqual(tools.requests, {})


class AIHTTPTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        test = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                test.requests.append(payload)
                if len(test.requests) == 1:
                    message = {'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'call1', 'type': 'function', 'function': {
                        'name': 'request_runtime_facts' if getattr(test, 'tool_mode', '') == 'runtime' else 'compare_versions',
                        'arguments': json.dumps({'collector': 'listeners', 'scope_id': 'host', 'component_id': 'openssl-host'}
                           if getattr(test, 'tool_mode', '') == 'runtime' else {'ecosystem': 'deb', 'installed': '1.0-1', 'other': '1.1-1'})}}]}
                else:
                    record = json.loads(payload['messages'][-1]['content'])
                    proposal = {key: finding()[key] for key in ['cve_id', 'component_id', 'scope_id']}
                    proposal.update(applicability='under_investigation', rationale='Version order alone does not establish applicability.', evidence_ids=[record['id']], unknowns=['patch status'])
                    message = {'role': 'assistant', 'content': json.dumps(proposal)}
                body = json.dumps({'choices': [{'message': message}], 'usage': {'prompt_tokens': 20, 'completion_tokens': 10}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = AIClient('custom', '', model='test-model', api_url=f'http://127.0.0.1:{self.server.server_port}/v1')

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_real_http_tool_loop_and_usage(self):
        result = self.client.investigate(finding(), [{'id': 'scan-1', 'type': 'scanner_match'}], SourceTools())
        self.assertTrue(result['success'], result)
        self.assertEqual(result['usage']['calls'], 2)
        self.assertEqual(result['usage']['tool_calls'], 1)
        self.assertEqual(result['usage']['input_tokens'], 40)

    def test_real_http_ai_runtime_request_returns_pending_for_agent_sync(self):
        self.tool_mode = 'runtime'
        pipeline = AnalysisPipeline()
        pipeline.ai = self.client
        scanned = {'findings': [finding()], 'evidence': [{'id': 'scan-1', 'type': 'scanner_match'}],
                   'scope_id': 'host', 'components_scanned': 1, 'missing_versions': [],
                   'scanner': {'version': 'fixture', 'database': {'built': 'db1'}}}
        with patch.object(pipeline.scanner, 'scan_scope', return_value=scanned):
            result = pipeline.analyze(inventory(), {'device_id': 'leaf1', 'inventory_digest': 'd1'})
        self.assertEqual(result['ai_usage']['calls'], 2)
        self.assertEqual(len(result['evidence_requests']), 1)
        request = result['evidence_requests'][0]
        self.assertEqual(request['collector'], 'listeners')
        self.assertEqual(request['inventory_digest'], 'd1')
        self.assertEqual(request['status'], 'queued')
        self.assertEqual(request['args'], {})
        self.assertEqual(result['findings'][0]['assessment_state'], 'pending_analysis')
        self.assertEqual(result['findings'][0]['applicability'], 'under_investigation')

    def test_bad_citation_and_identity_rejected(self):
        proposed = {key: finding()[key] for key in ['cve_id', 'component_id', 'scope_id']}
        proposed.update(applicability='not_affected', rationale='Claim', evidence_ids=['invented'], unknowns=[])
        with self.assertRaises(Exception):
            self.client.validate_proposal(proposed, finding(), {'scan-1'})

    def test_budget_stops_before_http(self):
        self.client.max_input_chars = 10
        result = self.client.investigate(finding(), [], SourceTools())
        self.assertFalse(result['success'])
        self.assertEqual(len(self.requests), 0)

    def test_unconfigured_provider_not_simulated(self):
        result = AIClient().investigate(finding(), [], SourceTools())
        self.assertFalse(result['success'])
        self.assertEqual(result['usage']['calls'], 0)

    def test_breaker_recovers_after_cooldown(self):
        self.client.failure_threshold = 1
        with patch.object(self.client, '_request', side_effect=ValueError('malformed provider JSON')):
            result = self.client.investigate(finding(), [], SourceTools())
        self.assertFalse(result['success'])
        self.assertTrue(self.client.circuit_breaker_open)
        blocked = self.client.investigate(finding(), [], SourceTools())
        self.assertEqual(blocked['usage']['calls'], 0)
        self.client.opened_at -= self.client.cooldown + 1
        recovered = self.client.investigate(finding(), [{'id': 'scan-1'}], SourceTools())
        self.assertTrue(recovered['success'], recovered)
        self.assertEqual(self.client.consecutive_failures, 0)

    def test_tool_budget_abstains(self):
        self.client.max_tool_calls = 0
        result = self.client.investigate(finding(), [], SourceTools())
        self.assertFalse(result['success'])
        self.assertIn('tool-call budget', result['error'])
        self.assertEqual(result['usage']['tool_calls'], 0)

    def test_malformed_provider_output_abstains(self):
        with patch.object(self.client, '_request', return_value={'choices': []}):
            result = self.client.investigate(finding(), [], SourceTools())
        self.assertFalse(result['success'])
        self.assertNotIn('proposal', result)

    def test_anthropic_tool_wire_format(self):
        self.client.provider = 'anthropic'
        responses = [{'content': [{'type': 'tool_use', 'id': 'call1', 'name': 'compare_versions',
                                   'input': {'ecosystem': 'deb', 'installed': '1.0', 'other': '2.0'}}]},
                     {'content': [{'type': 'text', 'text': json.dumps({**{k: finding()[k] for k in ['cve_id', 'component_id', 'scope_id']},
                          'applicability': 'under_investigation', 'rationale': 'Need patch provenance', 'evidence_ids': [], 'unknowns': []})}]}]
        with patch.object(self.client, '_request', side_effect=responses) as request:
            result = self.client.investigate(finding(), [], SourceTools())
        self.assertTrue(result['success'], result)
        second = request.call_args_list[1].args[0]
        self.assertEqual(second['messages'][-1]['content'][0]['type'], 'tool_result')
        self.assertIn('input_schema', second['tools'][0])


class ReleaseTests(unittest.TestCase):
    def test_release_parser(self):
        self.assertEqual(parse_sonic_release('sonic.master.123-abcdef1')['commit'], 'abcdef1')
        with self.assertRaises(ValueError):
            parse_sonic_release('master')


if __name__ == '__main__':
    unittest.main()
