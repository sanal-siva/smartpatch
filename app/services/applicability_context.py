"""Pure fact projections shared by assessment, freshness and cache guards.

Action results remain in device/audit storage, but are operational receipts, not
evidence of software applicability. Inventory and resources still participate in
full assessment freshness so collection failures cannot reuse complete coverage.
"""

# `remediation` is emitted by smart_patch/actions.py; `maintenance_action` is the
# compatibility collector used by existing action-protocol clients and fixtures.
OPERATIONAL_COLLECTORS = frozenset({'remediation', 'maintenance_action', 'smart_patch_maintenance'})
NON_APPLICABILITY_COLLECTORS = OPERATIONAL_COLLECTORS | {'inventory', 'resources'}


def applicability_facts(facts):
    """Preserve all runtime evidence except explicitly non-applicability facts."""
    return [fact for fact in (facts or []) if fact.get('collector') not in NON_APPLICABILITY_COLLECTORS]


def assessment_facts(facts):
    """Include inventory-quality inputs for cache/commit guards, omit receipts."""
    return [fact for fact in (facts or []) if fact.get('collector') not in OPERATIONAL_COLLECTORS]
