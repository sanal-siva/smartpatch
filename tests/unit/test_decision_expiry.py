from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.services.assessment import AssessmentEngine, finding_decision_fresh, result_cache_fresh
from app.services.pipeline import AnalysisPipeline
from app.services.sbom_parser import stable_id
from tests.unit.test_analysis_services import finding, inventory


def case(review_seconds=600, fact_seconds=120):
    start = datetime.now(timezone.utc)
    context = {'device_id': 'leaf1', 'inventory_digest': 'digest1', 'context_hash': 'ctx1',
               'runtime_facts': [{'collector': 'features', 'collected_at': start.isoformat(), 'ttl_seconds': fact_seconds}]}
    record = {'id': 'review1', 'build_id': 'build-a', 'scope_id': 'host', 'component_id': 'openssl-host',
              'cve_id': 'CVE-2026-1234', 'version': '3.0.1-1', 'evidence_ids': ['review-evidence'],
              'verification': 'reviewed', 'device_id': 'leaf1', 'inventory_digest': 'digest1', 'context_hash': 'ctx1',
              'applicability': 'not_affected', 'justification': 'Feature is disabled in the observed deployment',
              'expires_at': (start + timedelta(seconds=review_seconds)).isoformat()}
    return start, context, record


def test_decision_validity_is_bounded_by_supporting_fact():
    start, context, record = case()
    result = AssessmentEngine([record]).evaluate(finding(), 'build-a', context)
    assert result['applicability'] == 'not_affected'
    assert datetime.fromisoformat(result['decision_valid_until']) == start + timedelta(seconds=120)
    assert result_cache_fresh({'findings': [result]}, context, at=start + timedelta(seconds=100))
    assert not result_cache_fresh({'findings': [result]}, context, at=start + timedelta(seconds=121))


def test_review_expiry_invalidates_cache_even_when_context_hash_is_unchanged():
    start, context, record = case(review_seconds=30, fact_seconds=600)
    result = AssessmentEngine([record]).evaluate(finding(), 'build-a', context)
    assert datetime.fromisoformat(result['decision_valid_until']) == start + timedelta(seconds=30)
    assert not finding_decision_fresh(result, at=start + timedelta(seconds=31))
    assert not result_cache_fresh({'recommendations': [result]}, at=start + timedelta(seconds=31))


def test_legacy_unbounded_exemption_is_not_reused():
    assert not finding_decision_fresh({'applicability': 'not_affected', 'decision_basis': 'operator_review'})
    assert result_cache_fresh({'recommendations': [{'applicability': 'under_investigation', 'exposure': 'unknown'}]})


def test_exposure_carries_independent_expiry():
    start = datetime.now(timezone.utc)
    context = {'inventory_digest': 'd1', 'runtime_facts': [{'scope_id': 'host', 'component_id': 'openssl-host',
        'name': 'exposure', 'status': 'observed', 'value': 'constrained', 'inventory_digest': 'd1',
        'collected_at': start.isoformat(), 'ttl_seconds': 10}]}
    result = AssessmentEngine().evaluate(finding(), 'build-a', context)
    assert result['exposure'] == 'constrained'
    assert not finding_decision_fresh(result, at=start + timedelta(seconds=11))


def test_requested_later_finding_is_investigated_before_budget_is_consumed():
    first = finding()
    second = {**finding(), 'id': 'second', 'cve_id': 'CVE-2026-9999'}
    stored_id = stable_id(['leaf1', second['component_id'], second['scope_id'], second['cve_id']])
    pipeline = AnalysisPipeline(settings={'ai_max_findings': 1})
    scanned = {'findings': [first, second], 'evidence': [{'id': 'scan-1', 'type': 'scanner_match'}],
               'scope_id': 'host', 'components_scanned': 1, 'missing_versions': [],
               'scanner': {'version': 'fixture', 'database': {'built': 'db1'}}}
    seen = []
    def investigate(item, evidence, tools):
        seen.append(item['cve_id'])
        return {'success': True, 'state': 'analyzed', 'proposal': {'applicability': 'under_investigation',
                'rationale': 'Missing source evidence', 'evidence_ids': ['scan-1'], 'unknowns': []},
                'usage': {'calls': 1, 'tool_calls': 0, 'input_tokens': 0, 'output_tokens': 0, 'input_characters': 0}}
    with patch.object(pipeline.scanner, 'scan_scope', return_value=scanned), patch.object(pipeline.ai, 'health', return_value={'configured': True}), patch.object(pipeline.ai, 'investigate', side_effect=investigate):
        result = pipeline.analyze(inventory(), {'device_id': 'leaf1', 'finding_ids': [stored_id]})
    assert seen == ['CVE-2026-9999']
    assert result['analysis_selection']['matched_finding_ids'] == [stored_id]
    assert result['ai_usage']['calls'] == 1
