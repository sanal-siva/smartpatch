from copy import deepcopy
from datetime import timedelta

import pytest

from app.services.applicability_context import applicability_facts, assessment_facts
from app.services.assessment import AssessmentEngine, relevant_fact_deadlines, finding_decision_fresh
from tests.unit.test_analysis_services import finding
from tests.unit.test_decision_expiry import case


def test_explicit_receipt_filter_preserves_real_and_unknown_runtime_evidence():
    facts = [{'collector': collector, 'value': {'fixture': True}} for collector in (
        'inventory', 'resources', 'remediation', 'maintenance_action', 'services', 'listeners',
        'features', 'routing', 'processes', 'interfaces', 'kernel', 'future_evidence_collector')]
    before = deepcopy(facts)
    assert [f['collector'] for f in applicability_facts(facts)] == [f['collector'] for f in facts[4:]]
    assert assessment_facts(facts) == facts[:2] + facts[4:]
    assert facts == before
    assert applicability_facts(None) == []


@pytest.mark.parametrize('collector', ['remediation', 'maintenance_action'])
def test_expired_action_receipt_does_not_expire_or_shorten_review(collector):
    start, context, review = case()
    before = AssessmentEngine([review]).evaluate(finding(), 'build-a', context)
    context['runtime_facts'].append({'collector': collector, 'collected_at': '2000-01-01T00:00:00Z',
                                   'ttl_seconds': 1, 'value': {'action': 'stage_plan', 'status': 'staged'}})
    after = AssessmentEngine([review]).evaluate(finding(), 'build-a', context)
    assert after['applicability'] == 'not_affected'
    assert after['decision_valid_until'] == before['decision_valid_until']
    assert relevant_fact_deadlines(context) == [start + timedelta(seconds=120)]
    assert finding_decision_fresh(after, context, at=start + timedelta(seconds=100))
    assert not finding_decision_fresh(after, context, at=start + timedelta(seconds=121))
