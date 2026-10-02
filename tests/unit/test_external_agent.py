import copy
import json
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.config import Settings
from app.db.store import inventory_hash, stable_hash
from app.runtime import Runtime
from app.services.external_agent import (ExternalAgentError, create_external_session, get_external_session,
    call_external_tool, submit_external_analysis, fetch_official_advisory, project_external_analysis)
from app.services.source_tools import SourceTools


ADMIN = {'id': 'admin-test', 'role': 'admin'}
OPERATOR = {'id': 'operator-test', 'role': 'operator'}


class Pipeline:
    def __init__(self, *args):
        self.scanner = SimpleNamespace(status=lambda: {'status': 'ready', 'db_revision': 'db1'})
        self.ai = SimpleNamespace(health=lambda: {'configured': False})
        self.tools = SourceTools()


@pytest.fixture
def runtime(tmp_path):
    config = Settings(database_url='sqlite:///:memory:', state_dir=tmp_path / 'state', jobs_enabled=False,
                      bootstrap_token='fixture-bootstrap-secret', source_roots=[], ai_enabled=False)
    runtime = Runtime(config, pipeline_factory=Pipeline)
    components = [{'component_id': 'lldp-pkg', 'scope': 'container:lldp', 'name': 'lldpd',
                   'version': '1.0.16-1+deb12u1', 'source_name': 'lldpd', 'source_version': '1.0.16-1+deb12u1',
                   'distro': {'id': 'debian', 'version_id': '13'}, 'architecture': 'amd64'}]
    envelope = {'device_id': 'leaf1', 'epoch': 'epoch1', 'sequence': 1, 'kind': 'checkpoint', 'build_id': 'build-a',
                'sonic_version': 'master.0-abcdef1', 'inventory_digest': inventory_hash(components),
                'components': components, 'collected_at': '2026-09-30T00:00:00Z'}
    runtime.store.sync(envelope, ADMIN)
    finding = {'cve_id': 'CVE-2023-41910', 'scope_id': 'container:lldp', 'component_id': 'lldp-pkg', 'package_name': 'lldpd',
               'affected_version': '1.0.16-1+deb12u1', 'component': {**components[0], 'id': 'lldp-pkg'},
               'applicability': 'under_investigation', 'assessment_state': 'analyzed', 'severity': 'HIGH',
               'fixed_versions': ['1.0.17-1'], 'evidence_ids': ['scan1']}
    evidence = {'id': 'scan1', 'type': 'scanner_match', 'cve_id': 'CVE-2023-41910', 'scope_id': 'container:lldp', 'component_id': 'lldp-pkg',
                'data': {'vulnerability': {'id': 'CVE-2023-41910', 'description': 'Fixture advisory match', 'namespace': 'debian:distro:debian:13'},
                         'api_key': 'must-not-leak'}}
    runtime.store.store_findings('leaf1', envelope['inventory_digest'], {'findings': [finding], 'evidence': [evidence],
        'coverage': {'complete': True}, 'scanner': {'db_revision': 'db1'}}, 'revision1')
    runtime.finding_id = runtime.store.list('finding')[0]['id']
    yield runtime
    runtime.stop()


def submission(bundle, **changes):
    return {'snapshot_hash': bundle['snapshot_hash'], 'cve_id': bundle['finding']['cve_id'],
            'component_id': bundle['finding']['component_id'], 'scope_id': bundle['finding']['scope_id'],
            'proposed_applicability': 'under_investigation',
            'rationale': 'The scanner match needs backport and exact shipped-artifact verification before an applicability verdict.',
            'evidence_ids': [bundle['evidence'][0]['id']], 'unknowns': ['Exact artifact binding is unverified'], **changes}


def test_bundle_is_bounded_and_independent_of_provider_key(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    assert bundle['source'] == 'codex_interactive'
    assert bundle['snapshot']['artifact_verified'] is False
    assert bundle['limits']['max_tool_calls'] == 12
    text = json.dumps(bundle)
    assert len(text) < 32000
    assert bundle['context_chars'] <= bundle['limits']['max_context_chars']
    assert bundle['agent_identity_verified'] is False
    assert 'fixture-bootstrap-secret' not in text and 'must-not-leak' not in text
    assert runtime.configuration()['ai_enabled'] is False
    assert bundle['submission_schema']['additionalProperties'] is False


def test_action_receipt_keeps_frozen_investigation_current(runtime):
    bundle=create_external_session(runtime,runtime.finding_id,OPERATOR)
    runtime.store.update_device('leaf1',{'facts':[{'collector':'remediation','status':'complete',
        'collected_at':datetime.now(timezone.utc).isoformat(),'value':{'action':'stage_plan','status':'staged'}}]})
    current=get_external_session(runtime,bundle['session_id'],OPERATOR)
    assert current['snapshot_hash']==bundle['snapshot_hash']
    result=submit_external_analysis(runtime,bundle['session_id'],submission(bundle),OPERATOR)
    assert result['promoted'] is False


def test_agent_role_and_cross_operator_sessions_are_rejected(runtime):
    with pytest.raises(ExternalAgentError) as error:
        create_external_session(runtime, runtime.finding_id, {'id': 'agent', 'role': 'agent'})
    assert error.value.status_code == 403
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    with pytest.raises(ExternalAgentError):
        get_external_session(runtime, bundle['session_id'], {'id': 'another', 'role': 'operator'})


def test_recorded_tool_citations_attach_to_finding_but_do_not_change_verdict(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    tool = call_external_tool(runtime, bundle['session_id'], 'compare_versions',
        {'ecosystem': 'deb', 'installed': '1.0.16-1+deb12u1', 'other': '1.0.17-1'}, OPERATOR)
    evidence_id = tool['evidence']['id']
    result = submit_external_analysis(runtime, bundle['session_id'], submission(bundle,
        proposed_applicability='fixed', evidence_ids=['scan1', evidence_id],
        rationale='Candidate backport interpretation requires administrator review; this proposal is not an adopted verdict.'), OPERATOR)
    assert result['review_required'] is True and result['promoted'] is False
    actual = runtime.store.get('finding', runtime.finding_id)
    assert actual['applicability'] == 'under_investigation'
    assert actual['latest_external_analysis']['proposed_applicability'] == 'fixed'
    assert evidence_id in actual['evidence_ids']
    assert any(item['id'] == evidence_id for item in actual['evidence'])
    assert runtime.store.list('reviewed_assessment') == []
    assert get_external_session(runtime, bundle['session_id'], OPERATOR)['status'] == 'submitted'


@pytest.mark.parametrize('field,value', [('artifact_id', 'new-artifact'), ('artifact_verified', True),
                                        ('binding_revision', 'new-binding'), ('build_id', 'new-build')])
def test_changed_binding_rejects_submission(runtime, field, value):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    runtime.store.update_device('leaf1', {field: value})
    with pytest.raises(ExternalAgentError) as error:
        submit_external_analysis(runtime, bundle['session_id'], submission(bundle), OPERATOR)
    assert error.value.status_code == 409
    assert runtime.store.list('external_agent_analysis') == []


def test_changed_source_and_advisory_rejects_submission(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    with patch.object(runtime, '_source_revision', return_value='a' * 40):
        with pytest.raises(ExternalAgentError):
            submit_external_analysis(runtime, bundle['session_id'], submission(bundle), OPERATOR)
    runtime.advisory_generation += 1
    with pytest.raises(ExternalAgentError):
        submit_external_analysis(runtime, bundle['session_id'], submission(bundle), OPERATOR)


def test_context_change_before_session_requires_fresh_assessment(runtime):
    runtime.store.update_device('leaf1', {'facts': [{'collector': 'listeners', 'scope': 'container:lldp', 'status': 'observed',
                'collected_at': datetime.now(timezone.utc).isoformat(), 'value': ['changed']} ]})
    with pytest.raises(ExternalAgentError) as error:
        create_external_session(runtime, runtime.finding_id, OPERATOR)
    assert error.value.status_code == 409


def test_fabricated_or_cross_session_evidence_is_rejected(runtime):
    first = create_external_session(runtime, runtime.finding_id, OPERATOR)
    second = create_external_session(runtime, runtime.finding_id, OPERATOR)
    tool = call_external_tool(runtime, first['session_id'], 'compare_versions', {'ecosystem': 'deb', 'installed': '1', 'other': '2'}, OPERATOR)
    with pytest.raises(ExternalAgentError):
        submit_external_analysis(runtime, second['session_id'], submission(second, evidence_ids=[tool['evidence']['id']]), OPERATOR)
    with pytest.raises(ExternalAgentError):
        submit_external_analysis(runtime, second['session_id'], submission(second, evidence_ids=['invented']), OPERATOR)


def test_tool_schema_scope_budget_and_expiry_are_enforced(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    with pytest.raises(ExternalAgentError):
        call_external_tool(runtime, bundle['session_id'], 'run_shell', {'cmd': 'id'}, OPERATOR)
    with pytest.raises(ExternalAgentError):
        call_external_tool(runtime, bundle['session_id'], 'get_component', {'component_id': 'lldp-pkg', 'scope_id': 'host'}, OPERATOR)
    with pytest.raises(ExternalAgentError):
        call_external_tool(runtime, bundle['session_id'], 'compare_versions', {'ecosystem': 'deb', 'installed': '1', 'other': '2', 'extra': 'not allowed'}, OPERATOR)
    record = runtime.store.get('external_agent_session', bundle['session_id'])
    runtime.store.put('external_agent_session', record['id'], {**record, 'tool_calls': 12}, 'leaf1')
    with pytest.raises(ExternalAgentError) as error:
        call_external_tool(runtime, record['id'], 'compare_versions', {'ecosystem': 'deb', 'installed': '1', 'other': '2'}, OPERATOR)
    assert error.value.status_code == 429
    runtime.store.put('external_agent_session', record['id'], {**record, 'expires_at': (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()}, 'leaf1')
    with pytest.raises(ExternalAgentError) as error:
        submit_external_analysis(runtime, record['id'], submission(bundle), OPERATOR)
    assert error.value.status_code == 410


def test_interactive_runtime_request_works_without_enabling_automatic_ai(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    result = call_external_tool(runtime, bundle['session_id'], 'request_runtime_facts',
        {'collector': 'listeners', 'scope_id': 'container:lldp', 'component_id': 'lldp-pkg'}, OPERATOR)
    assert result['evidence']['data']['status'] == 'pending'
    assert runtime.store.list('evidence_request')[0]['status'] == 'queued'
    assert runtime.configuration()['ai_enabled'] is False


def test_official_fetch_is_registered_and_references_are_not_equated_with_evidence(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    proof = {'id': 'advisory-test', 'type': 'official_advisory_fetch', 'source': 'https://security-tracker.debian.org/tracker/CVE-2023-41910',
             'data': {'text': 'Fixture: bookworm fixed 1.0.16-1+deb12u1'}, 'content_sha256': 'a' * 64}
    with patch('app.services.external_agent.fetch_official_advisory', return_value=proof):
        fetched = call_external_tool(runtime, bundle['session_id'], 'fetch_official_advisory', {'cve_id': 'CVE-2023-41910'}, OPERATOR)
    result = submit_external_analysis(runtime, bundle['session_id'], submission(bundle,
        evidence_ids=[fetched['evidence']['id']], external_references=[proof['source']]), OPERATOR)
    assert result['evidence'][0]['type'] == 'official_advisory_fetch'
    assert result['external_references'][0]['verification'].startswith('reference_only')
    assert runtime.store.get('finding', runtime.finding_id)['applicability'] == 'under_investigation'


def test_schema_rejects_identity_mutation_and_extra_fields(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    with pytest.raises(ExternalAgentError):
        submit_external_analysis(runtime, bundle['session_id'], submission(bundle, component_id='another'), OPERATOR)
    with pytest.raises(ExternalAgentError):
        submit_external_analysis(runtime, bundle['session_id'], {**submission(bundle), 'auto_trust': True}, OPERATOR)


def test_archived_proposal_survives_identical_rescan_without_reapplying_evidence(runtime):
    original = runtime.store.get('finding', runtime.finding_id)
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    tool = call_external_tool(runtime, bundle['session_id'], 'compare_versions', {'ecosystem': 'deb', 'installed': '1', 'other': '2'}, OPERATOR)
    proposal = submit_external_analysis(runtime, bundle['session_id'], submission(bundle,
        evidence_ids=['scan1', tool['evidence']['id']]), OPERATOR)
    after_submit = runtime.store.get('finding', runtime.finding_id)
    assert project_external_analysis(runtime, after_submit)['latest_external_analysis']['stale'] is False
    runtime.store.store_findings('leaf1', original['inventory_digest'], {'findings': [original], 'evidence': original['evidence'],
        'coverage': {'complete': True}, 'scanner': {'db_revision': 'db1'}}, 'new-identical-scan')
    rescanned = runtime.store.get('finding', runtime.finding_id)
    assert 'latest_external_analysis' not in rescanned
    projected = project_external_analysis(runtime, rescanned)
    assert projected['latest_external_analysis']['id'] == proposal['id']
    assert projected['latest_external_analysis']['stale'] is False
    assert projected['applicability'] == 'under_investigation'
    assert tool['evidence']['id'] not in projected['evidence_ids']
    assert 'latest_external_analysis' not in runtime.store.get('finding', runtime.finding_id)  # read projection only


def test_archived_proposal_is_explicitly_stale_after_binding_change(runtime):
    bundle = create_external_session(runtime, runtime.finding_id, OPERATOR)
    submit_external_analysis(runtime, bundle['session_id'], submission(bundle), OPERATOR)
    runtime.store.update_device('leaf1', {'binding_revision': 'changed-binding'})
    projected = project_external_analysis(runtime, runtime.store.get('finding', runtime.finding_id))
    assert projected['latest_external_analysis']['stale'] is True
    assert 'binding_revision_changed' in projected['latest_external_analysis']['stale_reasons']
    assert projected['applicability'] == 'under_investigation'
