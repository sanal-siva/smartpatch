"""Opt-in actual central Grype checks for a deliberately tiny advisory corpus."""
import json
import os
from pathlib import Path
from datetime import datetime, timezone

import pytest

from app.services.scanner import GrypeScanner
from app.services.assessment import AssessmentEngine, RULESET_VERSION


@pytest.mark.skipif(not os.getenv('SMART_PATCH_TEST_REAL_GRYPE'), reason='Requires actual central Grype and its downloaded database')
def test_lldpd_release_lineage_corpus():
    root = Path(__file__).resolve().parents[2]
    corpus = json.loads((root / 'tests/fixtures/lldpd_cve_2023_41910.json').read_text())
    binary = os.getenv('SMART_PATCH_TEST_GRYPE', str(root / '.tools/grype-0.112.0/grype'))
    scanner = GrypeScanner(binary, env={'GRYPE_DB_CACHE_DIR': str(root / '.state/grype-db'), 'GRYPE_DB_AUTO_UPDATE': 'false'})
    scanner_status = scanner.status()
    assert scanner_status['status'] == 'ready', scanner_status
    outcomes = []
    for case in corpus['cases']:
        version = case['version']
        scope = {'id': 'corpus:' + case['id'], 'kind': 'synthetic_package_metadata',
                 'distro': {'name': 'debian', 'version': case['debian_release']}, 'components': [
                     {'id': 'corpus-lldpd', 'name': 'lldpd', 'version': version, 'source_name': 'lldpd',
                      'source_version': version, 'ecosystem': 'deb', 'arch': 'amd64',
                      'purl': 'pkg:deb/debian/lldpd@' + version + '?arch=amd64'}]}
        scanned = scanner.scan_scope(scope)
        matches = [match for match in scanned['findings'] if match['cve_id'] == corpus['selected_cve']]
        outcome = {**case, 'selected_cve_matches': len(matches), 'observed_selected_cve_match': bool(matches),
                   'total_other_candidates': len(scanned['findings']) - len(matches),
                   'match_evidence': [{'namespace': match.get('advisory_namespace'), 'fix_versions': match.get('fixed_versions'),
                                       'evidence_ids': match['evidence_ids']} for match in matches]}
        if case.get('expected_policy_applicability') and matches:
            assessment = AssessmentEngine().evaluate(matches[0], 'synthetic-corpus-build', {'artifact_verified': True})
            outcome['policy_applicability'] = assessment['applicability']
            outcome['lineage_signal'] = assessment.get('release_lineage')
        outcome['passed'] = (bool(matches) == case['expected_selected_cve_match'] and
                             (not case.get('expected_policy_applicability') or outcome.get('policy_applicability') == case['expected_policy_applicability']))
        outcomes.append(outcome)
    report = {'corpus_id': corpus['corpus_id'], 'label': corpus['label'], 'run_at': datetime.now(timezone.utc).isoformat(),
              'ruleset_version': RULESET_VERSION, 'scanner': scanner_status, 'provenance': corpus['provenance'],
              'cases': outcomes, 'selected_cves_covered': [corpus['selected_cve']], 'cases_passed': sum(case['passed'] for case in outcomes),
              'cases_total': len(outcomes), 'limitations': corpus['limitations']}
    destination = Path(os.getenv('SMART_PATCH_CORPUS_REPORT', str(root / 'test-results/lldpd-advisory-corpus.json')))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + '\n')
    assert all(case['passed'] for case in outcomes), report
