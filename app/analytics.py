"""Analytics from timed observations and recorded inventory transitions.

The scheduler captures hourly snapshots. Reading a dashboard never creates or
backfills history. Package update counts use committed change events, not guesses
from the current inventory or an assumed scan cadence.
"""
from collections import Counter
from datetime import datetime, timezone, timedelta
from math import ceil
from app.db.store import now


def _components(devices):
    for device in devices:
        for component in device.get('components', []):
            yield device, component


def inventory_counts(devices):
    return {'devices': len(devices), 'components': sum(len(device.get('components', [])) for device in devices),
            'unique_packages': len({(component.get('source_name') or component.get('name'),
                                    component.get('source_version') or component.get('version'),
                                    component.get('architecture')) for _device, component in _components(devices)})}


def _package_type(component):
    explicit = str(component.get('package_type') or '').replace('_', '-').lower()
    if explicit in {'linux-kernel', 'frr', 'openssl', 'standard'}:
        return explicit
    name = str(component.get('name') or component.get('package_name') or '').lower()
    if name == 'linux' or name.startswith(('linux-image-', 'linux-headers-', 'linux-modules-', 'linux-kbuild-', 'sonic-linux')):
        return 'linux-kernel'
    if name == 'frr' or name.startswith('frr-'):
        return 'frr'
    if name == 'openssl' or name.startswith('libssl'):
        return 'openssl'
    return 'standard'


def package_type_breakdown(devices):
    groups = {kind: {'components': 0, 'packages': set(), 'devices': set()}
              for kind in ('linux-kernel', 'frr', 'openssl', 'standard')}
    for device, component in _components(devices):
        bucket = groups[_package_type(component)]
        bucket['components'] += 1
        bucket['packages'].add((component.get('source_name') or component.get('name'),
                                component.get('source_version') or component.get('version'),
                                component.get('architecture')))
        bucket['devices'].add(device['id'])
    return [{'package_type': kind, 'components': bucket['components'],
             'unique_packages': len(bucket['packages']), 'devices': len(bucket['devices'])}
            for kind, bucket in groups.items()]


def capture_snapshot(store, *, observed_at=None):
    """Record the measured state in its UTC hour; repeated calls update that hour.

    Production callers omit observed_at. It permits deterministic time-controlled
    tests without changing clocks. Existing daily records remain readable.
    """
    timestamp = observed_at or now()
    instant = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('Snapshot observation must have a timezone')
    instant = instant.astimezone(timezone.utc)
    timestamp = instant.isoformat().replace('+00:00', 'Z')
    bucket = instant.replace(minute=0, second=0, microsecond=0).isoformat().replace('+00:00', 'Z')
    devices = store.devices()
    counts = store.finding_counts()
    states = Counter(counts['applicability'])
    snapshot = {
        'date': timestamp[:10], 'snapshot_time': bucket, 'measured_at': timestamp,
        'granularity': 'hour', 'devices': len(devices),
        'components': sum(len(device.get('components', [])) for device in devices),
        'unique_packages': len({(component.get('source_name') or component.get('name'),
                                component.get('source_version') or component.get('version'),
                                component.get('architecture')) for _device, component in _components(devices)}),
        'unique_cves': counts['unique_cves'],
        **{key: states[key] for key in ('affected', 'under_investigation', 'fixed', 'not_affected')},
    }
    store.put('snapshot', bucket, snapshot)
    return snapshot


def package_update_trends(events, cutoff):
    updates = {}
    coverage = {'inventory_events': 0, 'events_with_change_records': 0,
                'incomplete_events': 0, 'legacy_events_without_changes': 0,
                'change_records_examined': 0, 'updates_counted': 0,
                'first_recorded_change_at': None}
    seen_events = set()
    for event in events:
        if not str(event.get('type', '')).startswith('inventory.') or event.get('created_at', '') < cutoff:
            continue
        if event.get('id') and event['id'] in seen_events:
            continue
        seen_events.add(event.get('id'))
        coverage['inventory_events'] += 1
        details = event.get('details') or {}
        changes = details.get('package_changes')
        if not isinstance(changes, list):
            coverage['legacy_events_without_changes'] += 1
            continue
        coverage['events_with_change_records'] += 1
        if details.get('package_changes_complete') is False:
            coverage['incomplete_events'] += 1
        timestamp = event.get('created_at')
        if timestamp and (coverage['first_recorded_change_at'] is None or timestamp < coverage['first_recorded_change_at']):
            coverage['first_recorded_change_at'] = timestamp
        seen_changes = set()
        for change in changes:
            coverage['change_records_examined'] += 1
            if not isinstance(change, dict) or change.get('change') != 'updated':
                continue
            before, after = change.get('previous_version'), change.get('version')
            package = change.get('package_name')
            if not isinstance(package, str) or not package or not isinstance(before, str) or not isinstance(after, str) or before == after:
                continue
            identity = (change.get('component_id'), change.get('scope'), package, before, after)
            if identity in seen_changes:
                continue
            seen_changes.add(identity)
            coverage['updates_counted'] += 1
            bucket = updates.setdefault(package, {'package_name': package, 'updates': 0, 'device_ids': set(),
                                                   'scope_ids': set(), 'last_updated': '', 'latest_observed_version': None})
            bucket['updates'] += 1
            if event.get('device_id'):
                bucket['device_ids'].add(event['device_id'])
            bucket['scope_ids'].add((event.get('device_id'), change.get('scope')))
            if timestamp and timestamp >= bucket['last_updated']:
                bucket['last_updated'], bucket['latest_observed_version'] = timestamp, after
    rows = [{'package_name': row['package_name'], 'updates': row['updates'],
             'devices': len(row['device_ids']), 'scopes': len(row['scope_ids']),
             'last_updated': row['last_updated'], 'latest_observed_version': row['latest_observed_version']}
            for row in updates.values()]
    rows.sort(key=lambda row: (-row['updates'], row['package_name']))
    coverage['complete'] = coverage['incomplete_events'] == 0 and coverage['legacy_events_without_changes'] == 0
    return rows[:20], coverage


def aggregate_history(snapshots, resolution):
    """Preserve observations; daily points are the actual last value, never an average."""
    if resolution not in {'hour', 'day'}:
        raise ValueError('History resolution must be hour or day')
    observed = []
    for snapshot in snapshots:
        instant = datetime.fromisoformat(snapshot['measured_at'].replace('Z', '+00:00'))
        if instant.tzinfo is None:
            raise ValueError('Stored observation needs a timezone')
        instant = instant.astimezone(timezone.utc)
        point = {**snapshot, 'observation_count': 1,
                 'peak_affected': snapshot.get('affected'),
                 'first_observed_at': snapshot['measured_at'], 'last_observed_at': snapshot['measured_at']}
        observed.append((instant, point))
    observed.sort(key=lambda item: item[0])
    if resolution == 'hour':
        return [point for _instant, point in observed]
    days = {}
    for instant, point in observed:
        day = instant.date().isoformat()
        bucket = days.get(day)
        previous_count = bucket['observation_count'] if bucket else 0
        peaks = [value for value in (bucket.get('peak_affected') if bucket else None, point.get('affected'))
                 if isinstance(value, (int, float)) and not isinstance(value, bool)]
        days[day] = {**point, 'date': day, 'snapshot_time': day + 'T00:00:00Z', 'granularity': 'day',
                     'observation_count': previous_count + 1,
                     'peak_affected': max(peaks) if peaks else None,
                     'first_observed_at': bucket['first_observed_at'] if bucket else point['measured_at'],
                     'last_observed_at': point['measured_at']}
    return [days[key] for key in sorted(days)]


def build_analytics(store, days=30):
    days = max(1, min(int(days), 366))
    current_time = datetime.now(timezone.utc)
    cutoff = (current_time - timedelta(days=days)).isoformat().replace('+00:00', 'Z')
    resolution = 'hour' if days <= 7 else 'day'
    history_start = (current_time - timedelta(days=days) if resolution == 'hour' else
                     current_time.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days-1))
    history_cutoff = history_start.isoformat().replace('+00:00', 'Z')
    history_end = current_time.isoformat().replace('+00:00', 'Z')
    observations = [row for row in store.list('snapshot') if history_cutoff <= row['measured_at'] <= history_end]
    snapshots = aggregate_history(observations, resolution)
    discoveries = store.cve_discovery_trends(history_cutoff, history_end, resolution)
    devices = store.devices()
    top_updated, change_coverage = package_update_trends(store.list('event'), cutoff)
    severity_grid = store.finding_package_counts()
    requests = [request for request in store.list('request') if request.get('submitted_at', '') >= cutoff]
    durations = sorted(request['assessment_duration_ms'] for request in requests
                       if isinstance(request.get('assessment_duration_ms'), (int, float)))
    hits = sum(bool(request.get('response_cached')) for request in requests)
    metrics = {'total_requests': len(requests), 'completed': sum(r.get('status') == 'completed' for r in requests),
               'failed': sum(r.get('status') == 'failed' for r in requests),
               'pending': sum(r.get('status') in ('queued', 'in_progress') for r in requests),
               'p95_duration_ms': durations[max(0, ceil(len(durations) * .95) - 1)] if durations else None,
               'average_duration_ms': round(sum(durations) / len(durations), 2) if durations else None,
               'cache_hit_rate': hits / len(requests) if requests else None, 'cache_hits': hits, 'cache_misses': len(requests) - hits}
    timing = ('date', 'measured_at', 'snapshot_time', 'granularity', 'observation_count', 'peak_affected', 'first_observed_at', 'last_observed_at')
    return {'window_days': days, 'snapshot_interval_seconds': 3600,
            'history_resolution': resolution, 'history_aggregation': 'last_observed_per_utc_day' if resolution == 'day' else 'recorded_hourly_observations',
            'history_window_start': history_cutoff, 'history_window_end': history_end, 'history_observations': len(observations), 'history_points': len(snapshots),
            'package_trends': [{key: row.get(key) for key in (*timing, 'components', 'unique_packages', 'devices')} for row in snapshots],
            'cve_trends': [{key: row.get(key) for key in (*timing, 'affected', 'under_investigation', 'fixed', 'not_affected', 'unique_cves')} for row in snapshots],
            'cve_discovery_trends': [{**row, 'granularity': resolution} for row in discoveries['series']],
            'cve_discovery_summary': {key: value for key, value in discoveries.items() if key != 'series'} | {
                'identity': 'distinct_cve_across_smart_patch_device_fleet', 'resolution': resolution,
                'candidate_matches_included': True,
                'semantics': 'Each CVE is counted once, at its earliest retained observation on a Smart Patch device, regardless of package, scope, device, or later applicability. Catalog-only release findings are excluded.'},
            'current_inventory': inventory_counts(devices),
            'package_type_breakdown': package_type_breakdown(devices),
            'top_updated_packages': top_updated, 'package_change_coverage': change_coverage,
            'severity_package_grid': severity_grid, 'request_metrics': metrics, 'requests': requests[:500],
            'notes': ['Up to 7 days displays recorded hourly observations. Longer charts show the last actual observation in each of the selected UTC calendar days, with observation count and daily peak affected metadata. Missing days remain missing; request/change metrics use the rolling day window.',
                      'Package family uses recorded type or name-based classification of current component occurrences; it does not establish remediation eligibility.',
                      'Top-updated counts use recorded scoped version transitions only. Added/removed baseline entries are excluded; legacy or truncated change events make this ranking partial.',
                      'Severity grid counts current recorded component findings, including unresolved candidates.',
                      'Discovery counts distinct CVEs first observed in the device fleet, including unresolved scanner candidates. Repeated or reappearing CVEs are not new discoveries. Earlier missing history is not reconstructed; no discovery does not prove scan coverage or safety.',
                      'Request latency and cache metrics describe the assessment API, separately from background scan jobs.']}
