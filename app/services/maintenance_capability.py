"""Collector-reported, short-lived permission to maintain a container locally."""
import re
from datetime import datetime, timezone

PROTECTED_PACKAGE = re.compile(r'^(linux-|frr|libssl|openssl|libc6|systemd|docker|containerd|sonic-|swss|syncd)')


def container_maintenance(device, max_age=180):
    device = device or {}
    reported = device.get('maintenance') or {}
    if reported.get('maintenance_mode') is not True:
        return False, 'Enable maintenance mode on the switch before container package maintenance'
    if reported.get('capabilities', {}).get('container_package_update') != 1:
        return False, 'Update the switch collector to support container package maintenance'
    if reported.get('epoch') != device.get('epoch') or reported.get('build_id') != device.get('build_id'):
        return False, 'Maintenance permission belongs to an earlier switch epoch or build'
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(reported['reported_at'].replace('Z', '+00:00'))).total_seconds()
        if age < 0 or age > max_age:
            return False, 'Waiting for a fresh switch maintenance-mode report'
    except (KeyError, TypeError, ValueError):
        return False, 'Waiting for a fresh switch maintenance-mode report'
    return True, 'Switch maintenance mode permits the selected container to restart'


def package_automation(device, scope, package):
    if PROTECTED_PACKAGE.match(package):
        return False, 'This protected package needs operator-led image or service maintenance'
    if scope == 'host':
        return True, 'Host package transaction requires collector preflight'
    if scope and scope.startswith('container:'):
        allowed, reason = container_maintenance(device)
        if not allowed:
            return allowed, reason
        identity = (device.get('maintenance') or {}).get('containers',{}).get(scope,{})
        if (not identity.get('running') or not identity.get('id') or not identity.get('image')
                or identity.get('name') != '/' + scope.removeprefix('container:')):
            return False, 'Waiting for the running container identity from the switch before approval'
        return True, reason
    return False, 'This package scope is not supported by package maintenance'


def maintenance_view(device):
    allowed, reason = container_maintenance(device)
    return {'container_maintenance_eligible': allowed, 'maintenance_reason': reason}


def plan_container_matches(plan, device):
    if not plan.get('scope','').startswith('container:'):
        return True
    expected = plan.get('container_identity') or {}
    observed = (device.get('maintenance') or {}).get('containers',{}).get(plan['scope'],{})
    return bool(expected and all(expected.get(key)==observed.get(key) for key in ('id','image','name')))
