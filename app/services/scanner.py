"""Central-only Grype adapter with independent distro scopes and evidence."""
import copy
import json
import os
import re
import tempfile
import threading
import fcntl
import yaml
from pathlib import Path
from .process import ProcessError, run_bounded
from .sbom_parser import scope_to_sbom, stable_id


class ScanError(RuntimeError):
    pass


def assessment_cache_context(scanner, status):
    """Bind the outer assessment cache to the same matcher inputs as scope reuse.

    Injected/custom scanners without configuration introspection retain their
    status-based contract. The production Grype adapter always supplies the
    effective configuration digest; unknown/external configuration is not cached.
    No configuration contents or credentials leave the adapter.
    """
    identity = {key: status.get(key) for key in ('status', 'version', 'db_revision', 'db_identity')}
    configuration = getattr(scanner, '_configuration', None)
    guarded = callable(configuration)
    digest = None
    if guarded:
        try:
            digest, _ = configuration()
        except Exception:
            # A failed introspection cannot authorize a cached result. A full
            # match can still fail/report its own configuration error normally.
            pass
    identity.update(configuration=digest, configuration_guarded=guarded)
    reusable = (status.get('status') == 'ready' and bool(status.get('db_revision'))
                and (not guarded or bool(digest)))
    return identity, reusable


class GrypeScanner:
    def __init__(self, binary='grype', timeout=180, max_output_bytes=64 * 1024 * 1024, env=None,
                 cache_dir=None, cache_max_bytes=256 * 1024 * 1024, cache_max_entries=256):
        self.binary, self.timeout, self.max_output_bytes = binary, timeout, max_output_bytes
        self.env = dict(os.environ, GRYPE_CHECK_FOR_APP_UPDATE='false')
        self.env.update(env or {})
        self.cache_dir = Path(cache_dir).resolve() if cache_dir else None
        self.cache_max_bytes, self.cache_max_entries = int(cache_max_bytes), int(cache_max_entries)
        self.cache_hits, self.cache_misses = 0, 0
        self._cache_locks = [threading.Lock() for _ in range(64)]
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._prune_cache()

    def status(self):
        result = {'status': 'unavailable', 'version': None, 'db_revision': None, 'db_built_at': None}
        try:
            version = json.loads(run_bounded([self.binary, 'version', '-o', 'json'], timeout=10, env=self.env))
            result['version'] = version.get('version')
            database = json.loads(run_bounded([self.binary, 'db', 'status', '-o', 'json'], timeout=15, env=self.env))
            result.update(status='ready', db_revision=database.get('checksum') or database.get('built') or database.get('builtAt'),
                          db_built_at=database.get('built') or database.get('builtAt'))
            database_identity = dict(database)
            if database.get('path'):
                try:
                    stat = Path(database['path']).stat()
                    database_identity['file'] = [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
                except OSError:
                    pass
            result['db_identity'] = stable_id(database_identity)
            if database.get('valid') is False:
                result.update(status='unavailable', error='scanner database is invalid')
        except (OSError, ValueError, ProcessError) as exc:
            result['error'] = str(exc)
        return result

    def _configuration(self):
        """Hash the effective configuration, including implicitly loaded YAML files.

        External/VEX documents can change independently of the scanner database;
        those configurations deliberately bypass all reuse. Never persist config
        contents, which can include registry credentials.
        """
        try:
            raw = run_bounded([self.binary, 'config', '--load'], timeout=10,
                              max_bytes=1024 * 1024, env=self.env)
            value = yaml.safe_load(raw)
            if not isinstance(value, dict):
                return None, 'effective_scanner_configuration_unavailable'
            if value.get('vex-documents') or (value.get('external-sources') or {}).get('enable'):
                return None, 'external_matching_context_requires_full_scan'
            dpkg = (value.get('match') or {}).get('dpkg') or {}
            if (value.get('add-cpes-if-none') or value.get('match-upstream-kernel-headers')
                    or dpkg.get('using-cpes') or dpkg.get('use-cpes-for-eol') or value.get('exclude')):
                return None, 'matching_configuration_requires_full_scan'
            return stable_id({'effective': value,
                              'environment': {k: v for k, v in self.env.items()
                                              if k.startswith(('GRYPE_', 'SYFT_'))}}), None
        except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError, ProcessError):
            return None, 'effective_scanner_configuration_unavailable'

    @staticmethod
    def _incremental_reason(scope):
        """Only verified package-local Debian matching is eligible for sparse scans.

        The generated CycloneDX document has no dependency graph. Other ecosystems
        (notably language-package relationship and CPE matching) retain full-scope
        matching until their context independence is validated separately.
        """
        distro = scope.get('distro') or {}
        name = distro.partition(':')[0] if isinstance(distro, str) else distro.get('name')
        if str(name).lower() != 'debian':
            return 'only_debian_package_local_matching_is_supported'
        identities, ids, purls = set(), set(), set()
        for package in scope['components']:
            if any(not isinstance(package.get(field), str) or not package[field]
                   for field in ('id', 'name', 'version')):
                return 'missing_package_identity_or_version'
            kind = package.get('ecosystem') or package.get('type') or 'deb'
            purl = package.get('purl') or ''
            if (not isinstance(kind, str) or kind not in {'deb', 'dpkg'}
                    or not isinstance(purl, str) or (purl and not purl.startswith('pkg:deb/debian/'))):
                return 'scope_contains_non_debian_packages'
            # Absence of an architecture can conceal multiple installed occurrences.
            architecture = package.get('arch')
            if not isinstance(architecture, str) or not architecture.strip():
                return 'missing_or_ambiguous_package_identity'
            identity = (package['name'], architecture)
            if not identity[1] or identity in identities or package['id'] in ids or (purl and purl in purls):
                return 'missing_or_ambiguous_package_identity'
            identities.add(identity)
            ids.add(package['id'])
            if purl:
                purls.add(purl)
        return None

    @staticmethod
    def _cache_identity_reason(scope):
        """Exact-scope caching still requires complete, unambiguous occurrences."""
        ids, debian_occurrences = set(), set()
        for package in scope['components']:
            if any(not isinstance(package.get(field), str) or not package[field]
                   for field in ('id', 'name', 'version')):
                return 'missing_package_identity_or_version'
            if package['id'] in ids:
                return 'missing_or_ambiguous_package_identity'
            ids.add(package['id'])
            kind = package.get('ecosystem') or package.get('type') or 'deb'
            if kind in {'deb', 'dpkg'}:
                architecture = package.get('arch')
                identity = (package['name'], architecture)
                if (not isinstance(architecture, str) or not architecture.strip()
                        or identity in debian_occurrences):
                    return 'missing_or_ambiguous_package_identity'
                debian_occurrences.add(identity)
        purls = [item.get('purl') for item in scope_to_sbom(scope)['components']]
        if any(not isinstance(purl, str) or not purl for purl in purls) or len(set(purls)) != len(purls):
            return 'missing_or_ambiguous_package_identity'
        return None

    @staticmethod
    def _state_identity(status):
        return {key: status.get(key) for key in ('status', 'version', 'db_revision', 'db_identity')}

    def _ensure_stable(self, status, configuration, result):
        after = self.status()
        after_configuration, _ = self._configuration()
        metadata = result.get('scanner') or {}
        database = metadata.get('database') or {}
        if isinstance(database.get('status'), dict):
            database = database['status']
        revision = database.get('checksum') or database.get('built') or database.get('builtAt')
        if (self._state_identity(after) != self._state_identity(status)
                or after_configuration != configuration
                or metadata.get('version') != status.get('version')
                or revision != status.get('db_revision')):
            raise ScanError('Scanner, advisory database or configuration changed during matching; reassessment required')

    @staticmethod
    def _complete(scope, result):
        """A successful empty matches list is explicit coverage, not missing data."""
        return (isinstance(result, dict) and result.get('scope_id') == scope['id']
                and not result.get('missing_versions')
                and result.get('components_scanned') == len(scope['components'])
                and isinstance(result.get('findings'), list) and isinstance(result.get('evidence'), list)
                and isinstance(result.get('scanner'), dict))

    @staticmethod
    def _fingerprints(scope):
        # Full source metadata is intentional: hashes, patches, source versions and
        # custom context must never be inherited from a different package occurrence.
        generated = {item['bom-ref']: item for item in scope_to_sbom(scope)['components']}
        return {item['id']: stable_id({'component': item, 'sbom': generated.get(item['id'])})
                for item in scope['components']}

    @staticmethod
    def _package_receipts(scope, result, fingerprints):
        receipts = {item['id']: {'fingerprint': fingerprints[item['id']], 'finding_ids': [], 'evidence_ids': []}
                    for item in scope['components']}
        for field in ('findings', 'evidence'):
            target = 'finding_ids' if field == 'findings' else 'evidence_ids'
            for item in result[field]:
                receipts[item['component_id']][target].append(item['id'])
        for value in receipts.values():
            value['finding_ids'].sort()
            value['evidence_ids'].sort()
        return receipts

    def _read_baseline(self, path, key):
        try:
            if path.stat().st_size > min(self.max_output_bytes, self.cache_max_bytes):
                return None
            stored = json.loads(path.read_text())
            payload = stored['payload']
            if (stored.get('checksum') != stable_id(payload) or payload.get('format') != 2
                    or payload.get('key') != key):
                return None
            scope, result = payload['scope'], payload['result']
            fingerprints = self._fingerprints(scope)
            if not self._complete(scope, result) or payload.get('fingerprints') != fingerprints:
                return None
            component_ids = set(fingerprints)
            components = {item['id']: item for item in scope['components']}
            if payload.get('packages') != self._package_receipts(scope, result, fingerprints):
                return None
            if len(component_ids) != len(scope['components']):
                return None
            evidence = {item['id']: item for item in result['evidence']}
            if len(evidence) != len(result['evidence']):
                return None
            for item in result['evidence']:
                if item.get('component_id') not in component_ids or item.get('scope_id') != scope['id']:
                    return None
            for item in result['findings']:
                component = components.get(item.get('component_id')) or {}
                if (item.get('component_id') not in component_ids or item.get('scope_id') != scope['id']
                        or item.get('component') != component or item.get('affected_version') != component.get('version')
                        or item.get('package_name') != component.get('name') or not item.get('evidence_ids')
                        or any(ref not in evidence or evidence[ref].get('component_id') != item['component_id']
                               for ref in item['evidence_ids'])):
                    return None
            return payload
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return None

    def _store_baseline(self, path, key, scope, result):
        if not self._complete(scope, result):
            return
        fingerprints = self._fingerprints(scope)
        payload = {'format': 2, 'key': key, 'scope': scope,
                   'fingerprints': fingerprints, 'result': result,
                   'packages': self._package_receipts(scope, result, fingerprints)}
        raw = json.dumps({'payload': payload, 'checksum': stable_id(payload)}, separators=(',', ':')).encode()
        if len(raw) > min(self.cache_max_bytes, self.max_output_bytes):
            return
        stripe = int(key[:4], 16) % len(self._cache_locks)
        # We hold this stripe's process lock, so any previous unfinished writes in
        # the stripe belong to a crashed worker and can be reclaimed safely.
        for abandoned in self.cache_dir.glob(f'.pending-{stripe}-*'):
            try:
                abandoned.unlink()
            except FileNotFoundError:
                pass
        descriptor, temporary = tempfile.mkstemp(prefix=f'.pending-{stripe}-', dir=self.cache_dir)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        self._prune_cache()

    @staticmethod
    def _metrics(result, matched, reused=0, removed=0, mode='full', reason=None):
        result.update(cache_hit=mode == 'cached', scan_mode=mode,
                      components_matched=matched, components_reused=reused, components_removed=removed)
        if reason:
            result['incremental_fallback_reason'] = reason
        else:
            result.pop('incremental_fallback_reason', None)
        return result

    @staticmethod
    def _merge(scope, baseline, fresh, reusable):
        components = {item['id']: item for item in scope['components']}
        previous = baseline['result']
        result = {'scope_id': scope['id'], 'findings': [], 'evidence': [], 'missing_versions': [],
                  'components_scanned': len(components),
                  'scanner': copy.deepcopy((fresh or previous)['scanner'])}
        for field in ('findings', 'evidence'):
            result[field] = [copy.deepcopy(item) for item in previous[field]
                             if item['component_id'] in reusable]
            if fresh:
                result[field].extend(copy.deepcopy(fresh[field]))
        for finding in result['findings']:
            # Rebind the current occurrence. Cached assessment/enrichment state is
            # never stored: this cache contains scanner output only.
            component = components[finding['component_id']]
            finding.update(component=copy.deepcopy(component), package_name=component['name'],
                           affected_version=component['version'])
        return result

    def scan_scope(self, scope):
        identity_reason = self._cache_identity_reason(scope)
        reason = identity_reason or self._incremental_reason(scope)
        if self.cache_dir is None:
            value = self._scan_scope_uncached(scope)
            return self._metrics(value, value['components_scanned'], reason='scanner_cache_disabled')
        # Validate the advisory database on every lookup, including all-cache-hit
        # requests. A cache is never authority for advisory freshness.
        status = self.status()
        configuration, configuration_reason = self._configuration()
        if (status.get('status') != 'ready' or not status.get('version')
                or not status.get('db_revision') or not configuration):
            value = self._scan_scope_uncached(scope)
            return self._metrics(value, value['components_scanned'],
                                 reason=configuration_reason or 'scanner_database_identity_unavailable')
        # Sparse Debian baselines exclude only the package array. Other supported
        # inventories retain exact WHOLE-scope caching: any package/context change
        # causes a full match run. The distinct mode prevents mixed-ecosystem
        # results from later becoming a package-level Debian baseline.
        cache_scope = scope if reason else {k: v for k, v in scope.items() if k != 'components'}
        key = stable_id({'format': 2, 'scope': cache_scope,
                         'reuse_mode': 'exact_scope' if reason else 'package',
                         'scanner': self._state_identity(status), 'configuration': configuration})
        stripe = int(key[:4], 16) % len(self._cache_locks)
        path = self.cache_dir / (key + '.json')
        # One bounded baseline per context, plus fixed lock stripes. Concurrent
        # inventories of the same scope serialize across threads and processes.
        with self._cache_locks[stripe], (self.cache_dir / f'.lock-{stripe}').open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                baseline = self._read_baseline(path, key)
                # Unsafe/ambiguous identities receive no reuse, even for an exact
                # repeat; there is no per-occurrence proof to cache reliably.
                if identity_reason:
                    baseline = None
                fingerprints = self._fingerprints(scope)
                reusable = ({ident for ident, fingerprint in fingerprints.items()
                             if baseline['fingerprints'].get(ident) == fingerprint} if baseline else set())
                changed = [item for item in scope['components'] if item['id'] not in reusable]
                removed = len(set(baseline['fingerprints']) - set(fingerprints)) if baseline else 0
                if baseline and not changed:
                    value = self._merge(scope, baseline, None, reusable)
                    self._ensure_stable(status, configuration, value)
                    self.cache_hits += 1
                    self._metrics(value, 0, len(reusable), removed, 'cached', reason)
                else:
                    self.cache_misses += 1
                    subset = {**scope, 'components': changed} if reusable else scope
                    fresh = self._scan_scope_uncached(subset)
                    self._ensure_stable(status, configuration, fresh)
                    if reusable and not self._complete(subset, fresh):
                        raise ScanError('Incremental matching returned incomplete package coverage; reassessment required')
                    value = self._merge(scope, baseline, fresh, reusable) if reusable else fresh
                    self._metrics(value, fresh['components_scanned'], len(reusable), removed,
                                  'incremental' if reusable else 'full', reason)
                if not identity_reason and (not baseline or changed or removed):
                    self._store_baseline(path, key, scope, value)
                elif baseline:
                    try:
                        os.utime(path, None)
                    except OSError:
                        pass
                return value
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _prune_cache(self):
        records = []
        for path in self.cache_dir.glob('*.json'):
            try:
                stat = path.stat()
                records.append((stat.st_mtime, stat.st_size, path))
            except FileNotFoundError:
                continue
        total, count = sum(size for _, size, _ in records), len(records)
        for _, size, path in sorted(records):
            if total <= self.cache_max_bytes and count <= self.cache_max_entries:
                break
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            total -= size
            count -= 1

    def _scan_scope_uncached(self, scope):
        components = scope['components']
        distro = scope.get('distro') or {}
        if isinstance(distro, str):
            name, _, version = distro.partition(':')
            distro = {'name': name, 'version': version}
        has_os_packages = any((p.get('ecosystem') or p.get('type') or 'deb') in {'deb', 'dpkg', 'rpm', 'apk'}
                              or str(p.get('purl', '')).startswith(('pkg:deb/', 'pkg:rpm/', 'pkg:apk/')) for p in components)
        if has_os_packages and (not distro.get('name') or not distro.get('version')):
            raise ScanError(f"scope {scope['id']}: OS package matching requires distro name and version")
        missing = [p['id'] for p in components if not p.get('version')]
        document = scope_to_sbom(scope)
        with tempfile.TemporaryDirectory(prefix='smart-patch-grype-') as directory:
            path = Path(directory) / 'inventory.cdx.json'
            path.write_text(json.dumps(document), encoding='utf-8')
            argv = [self.binary, f'sbom:{path}', '-o', 'json', '-q']
            if distro.get('name') and distro.get('version'):
                override = f"{distro['name']}:{distro['version']}"
                if not re.fullmatch(r'[A-Za-z0-9_.+\-]+:[A-Za-z0-9_.+\-]+', override):
                    raise ScanError('invalid distro identifier')
                argv.extend(['--distro', override])
            try:
                raw = run_bounded(argv, timeout=self.timeout, max_bytes=self.max_output_bytes, env=self.env)
                report = json.loads(raw)
            except (OSError, ValueError, ProcessError) as exc:
                raise ScanError(f"scope {scope['id']}: {exc}") from exc
        if not isinstance(report, dict) or not isinstance(report.get('matches'), list):
            raise ScanError('Grype returned no matches array; result is not a successful scan')
        findings, evidence = [], []
        all_matches = list(report['matches'])
        for ignored in report.get('ignoredMatches', []):
            if isinstance(ignored, dict) and isinstance(ignored.get('match'), dict):
                all_matches.append({**ignored['match'], 'scanner_suppression': ignored.get('appliedIgnoreRules', [])})
        for match in all_matches:
            vulnerability, artifact = match.get('vulnerability', {}), match.get('artifact', {})
            candidates = [p for p in components if p['id'] == artifact.get('id')]
            if not candidates and artifact.get('purl'):
                candidates = [p for p in components if p.get('purl') == artifact['purl']]
            if not candidates:
                candidates = [p for p in components if p['name'] == artifact.get('name') and p['version'] == artifact.get('version')]
            if len(candidates) != 1:
                raise ScanError(f"cannot uniquely bind scanner artifact {artifact.get('name')} to scope {scope['id']}")
            package = candidates[0]
            cve = vulnerability.get('id')
            if not isinstance(cve, str) or not cve:
                raise ScanError('scanner match has no advisory id')
            identity = [scope['id'], package['id'], cve, vulnerability.get('namespace')]
            evidence_id = 'scan-' + stable_id([identity, match])[:24]
            scores = [entry.get('metrics', {}).get('baseScore') for entry in vulnerability.get('cvss', []) if isinstance(entry, dict)]
            if not scores:
                scores = [entry.get('metrics', {}).get('baseScore') for related in match.get('relatedVulnerabilities', [])
                          for entry in related.get('cvss', []) if isinstance(entry, dict)]
            scores = [float(score) for score in scores if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10]
            fix = vulnerability.get('fix') or {}
            evidence.append({'id': evidence_id, 'type': 'scanner_match', 'source': 'grype', 'scope_id': scope['id'],
                             'component_id': package['id'], 'cve_id': cve, 'data': match})
            findings.append({'id': stable_id(identity), 'cve_id': cve, 'scope_id': scope['id'],
                             'component_id': package['id'], 'package_name': package['name'], 'affected_version': package['version'],
                             'component': package, 'distro': distro, 'severity': str(vulnerability.get('severity', 'Unknown')).upper(),
                             'cvss_score': max(scores) if scores else None, 'fixed_versions': fix.get('versions') or [],
                             'fix_state': fix.get('state', 'unknown'), 'advisory_namespace': vulnerability.get('namespace'),
                             'advisory_url': vulnerability.get('dataSource'), 'match_details': match.get('matchDetails', []),
                             'related_vulnerabilities': match.get('relatedVulnerabilities', []), 'evidence_ids': [evidence_id],
                             'applicability': 'under_investigation', 'exposure': 'unknown', 'assessment_state': 'pending_analysis'})
        descriptor = report.get('descriptor') or {}
        return {'findings': findings, 'evidence': evidence, 'missing_versions': missing,
                'scanner': {'version': descriptor.get('version'), 'database': descriptor.get('db', {})},
                'scope_id': scope['id'], 'components_scanned': len(document['components'])}
