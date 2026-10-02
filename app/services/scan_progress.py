"""Coalesced work counters for scans; percentages describe workflow, not time."""
import copy
import time


def workflow_percentage(data):
    def fraction(done, total):
        total = max(0, int(data.get(total, 0)))
        return min(1, max(0, int(data.get(done, 0))) / total) if total else 1

    phase = data.get('phase')
    if phase == 'preparing':
        return 2
    if phase == 'matching':
        return 5 + int(50 * fraction('scopes_completed', 'scopes_total'))
    if phase == 'assessing':
        return 55 + int(25 * fraction('findings_completed', 'findings_total'))
    if phase == 'reviewing_evidence':
        return 80 + int(10 * fraction('evidence_completed', 'findings_total'))
    if phase == 'cached':
        return 90
    if phase == 'saving':
        return min(98, 92 + max(0, int(data.get('saving_step', 0))) * 2)
    return 0


class ScanProgress:
    """Keep every latest counter in memory, persist at most twice/second.

    Phase and scope boundaries are flushed immediately. A large finding set
    therefore does not cause one additional database transaction per finding.
    Completion/failure are handled atomically with the operation status.
    """
    def __init__(self, store, operation_id, *, clock=time.monotonic, interval=0.5):
        self.store = store
        self.operation_id = operation_id
        self.clock, self.interval = clock, interval
        self.data = {'progress_kind': 'workflow'}
        self.percentage = 0
        self.last_write = None

    def emit(self, event):
        event = dict(event)
        force = event.pop('force', False)
        boundary = any(event.get(key, self.data.get(key)) != self.data.get(key)
                       for key in ('phase', 'scope_id'))
        self.data.update(event)
        # Never move backwards between discovery, matching, assessment and save.
        # 100 is reserved for the durable terminal operation transition.
        self.percentage = min(99, max(self.percentage, workflow_percentage(self.data)))
        current = self.clock()
        if force or boundary or self.last_write is None or current - self.last_write >= self.interval:
            self.store.update_operation(self.operation_id, progress_percentage=self.percentage,
                                        progress_data=copy.deepcopy(self.data))
            self.last_write = current


def matching_counts(scanned):
    """Older/custom scanners still report logical coverage and cache_hit only."""
    covered = max(0, int(scanned.get('components_scanned', 0)))
    cached = bool(scanned.get('cache_hit'))
    return {
        'components_matched': max(0, int(scanned.get('components_matched', 0 if cached else covered))),
        'components_reused': max(0, int(scanned.get('components_reused', covered if cached else 0))),
        'components_removed': max(0, int(scanned.get('components_removed', 0))),
    }
