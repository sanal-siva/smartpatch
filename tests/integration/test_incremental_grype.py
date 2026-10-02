"""Opt-in central-host parity test; no switch access or package installations."""
import copy
import json
import os
from pathlib import Path
import time
from unittest.mock import patch

import pytest

from app.services.scanner import GrypeScanner


def package(name, version):
    return {'id': 'parity:' + name, 'name': name, 'version': version,
            'source_name': name, 'source_version': version, 'ecosystem': 'deb', 'arch': 'amd64',
            'purl': f'pkg:deb/debian/{name}@{version}?arch=amd64'}


def canonical(items):
    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))


@pytest.mark.skipif(not os.getenv('SMART_PATCH_TEST_REAL_GRYPE'),
                    reason='Requires actual central Grype and its downloaded database')
def test_real_grype_incremental_matches_full_current_scope(tmp_path):
    root = Path(__file__).resolve().parents[2]
    binary = os.getenv('SMART_PATCH_TEST_GRYPE', str(root / '.tools/grype-0.112.0/grype'))
    database = os.getenv('SMART_PATCH_TEST_GRYPE_DB', str(root / '.state/grype-db'))
    env = {'GRYPE_DB_CACHE_DIR': database, 'GRYPE_DB_AUTO_UPDATE': 'false'}
    scanner = GrypeScanner(binary, env=env, cache_dir=tmp_path / 'cache')
    full = GrypeScanner(binary, env=env)
    baseline = {'id': 'container:parity', 'kind': 'container', 'image_digest': 'synthetic-static-image',
                'distro': {'name': 'debian', 'version': '13'}, 'components': [
                    package('socat', '1.8.0.2-1'), package('rsync', '3.4.1+ds1-5'),
                    package('base-files', '13.8+deb13u1')]}
    timings = {}
    started = time.monotonic()
    previous = scanner.scan_scope(baseline)
    timings['baseline_seconds'] = round(time.monotonic() - started, 3)
    assert any(f['package_name'] == 'socat' for f in previous['findings']), 'Fixture must have a real socat candidate'
    current = copy.deepcopy(baseline)
    current['components'][0] = package('socat', '1.8.0.3-1+deb13u1')
    started = time.monotonic()
    with patch.object(scanner, '_scan_scope_uncached', wraps=scanner._scan_scope_uncached) as calls:
        incremental = scanner.scan_scope(current)
    timings['incremental_seconds'] = round(time.monotonic() - started, 3)
    assert calls.call_count == 1
    assert [p['name'] for p in calls.call_args.args[0]['components']] == ['socat']
    assert incremental['scan_mode'] == 'incremental'
    assert incremental['components_matched'] == 1 and incremental['components_reused'] == 2
    started = time.monotonic()
    reference = full.scan_scope(current)
    timings['full_current_seconds'] = round(time.monotonic() - started, 3)
    assert canonical(incremental['findings']) == canonical(reference['findings'])
    assert canonical(incremental['evidence']) == canonical(reference['evidence'])
    assert not any(f['package_name'] == 'socat' for f in reference['findings']), 'Updated socat fixture must demonstrate zero matches'
    assert incremental['components_scanned'] == reference['components_scanned'] == 3
    # Restart reads explicit negative coverage as well as positive matches.
    restarted = GrypeScanner(binary, env=env, cache_dir=tmp_path / 'cache')
    with patch.object(restarted, '_scan_scope_uncached', side_effect=AssertionError('all coverage cached')):
        again = restarted.scan_scope(current)
    assert again['components_reused'] == 3 and again['components_matched'] == 0
    assert canonical(again['findings']) == canonical(reference['findings'])
    report = {'label': 'Synthetic Debian package metadata, real central Grype; no switch/package changes',
              'scanner': scanner.status(), 'timings': timings, 'covered_packages': 3,
              'incremental_matched_packages': incremental['components_matched'],
              'incremental_reused_packages': incremental['components_reused'],
              'previous_findings': len(previous['findings']), 'current_findings': len(reference['findings']),
              'exact_findings_and_evidence_parity': True, 'zero_match_reuse_after_restart': True,
              'limitation': 'Tiny correctness fixture; timings are not a fleet performance benchmark'}
    destination = os.getenv('SMART_PATCH_INCREMENTAL_REPORT')
    if destination:
        Path(destination).write_text(json.dumps(report, indent=2) + '\n')
