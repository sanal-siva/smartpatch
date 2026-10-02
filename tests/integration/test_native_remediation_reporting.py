"""Cross-repository wire contract; simulated phases, no package operations.

Set SMART_PATCH_NATIVE_ROOT to the community collector source for standalone CI.
The usual sibling checkout is discovered for the shared hackathon workspace.
"""
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest

from .test_remediation_batches_acceptance import fleet

NATIVE = Path(os.environ.get('SMART_PATCH_NATIVE_ROOT',
    Path(__file__).resolve().parents[3] / 'sonic-buildimage/src/sonic-smart-patch'))
if not (NATIVE / 'smart_patch/remediation_status.py').is_file():
    pytest.skip('Cross-repository contract needs the community Smart Patch source', allow_module_level=True)
sys.path.insert(0, str(NATIVE))

from smart_patch.config import ConfigManager
from smart_patch.remediation import RemediationEngine
from smart_patch.remediation_status import RemediationReporter, get_status
from smart_patch.storage import StateStore, atomic_json


class Response:
    def __init__(self, response):
        self.response = response
    def raise_for_status(self):
        self.response.raise_for_status()
    def iter_content(self, size):
        yield self.response.content
    def close(self):
        self.response.close()


class LocalAPI:
    def __init__(self, client):
        self.client = client
    def post(self, url, json, headers, **kwargs):
        assert urlsplit(url).path == '/api/v1/agents/remediation'
        assert kwargs['allow_redirects'] is False
        return Response(self.client.post('/api/v1/agents/remediation', json=json, headers=headers))


def test_native_plan_phase_reports_and_central_resolution_reach_cli(fleet, tmp_path):
    remote = fleet.enroll('native-wire')
    config = ConfigManager(directory=tmp_path / 'native-config')
    config.set_service_enabled(True)
    config.set_operating_mode('assisted')
    config.set_service_url('https://fixture.invalid')
    config.set_auth_token(remote['headers']['Authorization'].removeprefix('Bearer '))
    store = StateStore(tmp_path / 'native-state')
    with store.transaction() as state:
        state.update(device_id='native-wire', epoch=remote['envelope']['epoch'],
                     build_id=remote['envelope']['build_id'], inventory_digest=remote['envelope']['inventory_digest'],
                     acknowledged_digest=remote['envelope']['inventory_digest'],
                     inventory={remote['component']['component_id']: remote['component']},
                     findings=[remote['finding']])
    atomic_json(store.directory/'remediation-identity.json',
                {key:state[key] for key in ('device_id','epoch','build_id','acknowledged_digest')})
    engine = RemediationEngine(store, config, runner=lambda *args, **kwargs: 'amd64')
    plan = engine.create_plan(remote['finding']['id'], remote['target'])
    reporter = RemediationReporter(config, store, LocalAPI(fleet.client))
    # These are lifecycle protocol fixtures, not an APT install or a scanner run
    # against an actual Debian package.
    with patch('smart_patch.maintenance_resources.container_maintenance_available', return_value=False):
        for phase in ('planned','staging','downloading','downloaded','staged','installing','installed','pending_reassessment'):
            if plan['status'] != phase:
                plan['status'] = phase
                engine._save(plan)
            result = reporter.report_once()
            assert not result['rejected']
            row = next(r for r in result['remediation_status'] if r.get('local_plan_id') == plan['id'])
            assert row['state'] == phase
            assert get_status(store, config)['rows'][0]['state'] == phase
        assert not fleet.store.list('plan'), 'Local telemetry must never fabricate a service-approved plan'
        assert not fleet.store.list('action_request')
        fleet.installed_inventory('native-wire')
        fleet.scan('native-wire', complete=False)
        reporter._last_send = 0
        assert reporter.report_once()['remediation_status'][0]['state'] == 'pending_reassessment'
        fleet.scan('native-wire')
        reporter._last_send = 0
        result = reporter.report_once()
        row = next(r for r in result['remediation_status'] if r.get('local_plan_id') == plan['id'])
        assert row['state'] == 'resolved'
        assert row['central_resolution']['status'] == 'completed'
        assert get_status(store, config, status='resolved')['rows'][0]['local_plan_id'] == plan['id']
