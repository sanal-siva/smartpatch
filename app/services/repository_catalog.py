"""Central Debian APT catalog from explicitly configured, authenticated metadata.

Verifies Release signatures and signed SHA256/size entries before parsing a
bounded Packages stream. No switch commands, package installation or inferred
'latest' versions are used. Package availability is as of signed index metadata.
"""
import gzip
import hashlib
import ipaddress
import json
import lzma
import os
import re
import socket
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, HTTPRedirectHandler, build_opener

from .process import run_bounded
from .sbom_parser import stable_id
from .source_tools import compare_versions


class RepositoryError(ValueError):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RepositoryError('Repository redirects are forbidden; configure the final HTTPS origin')


def checked_repository(config, allow_local=False):
    if not isinstance(config, dict):
        raise RepositoryError('Repository configuration must be an object')
    unknown = set(config) - {'base_url', 'suite', 'components', 'architectures', 'keyring'}
    if unknown:
        raise RepositoryError('Unsupported repository configuration fields')
    url = urlparse(config.get('base_url', ''))
    loopback = url.hostname in {'localhost', '127.0.0.1', '::1'}
    if not url.hostname or url.username or url.password or url.query or url.fragment:
        raise RepositoryError('Repository URL must not contain credentials, query or fragment')
    if url.scheme != 'https' and not (allow_local and loopback and url.scheme == 'http'):
        raise RepositoryError('Repository requires HTTPS')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', config.get('suite', '')):
        raise RepositoryError('Invalid suite identifier')
    for field in ('components', 'architectures'):
        values = config.get(field)
        if not isinstance(values, list) or not 1 <= len(values) <= 8 or len(set(values)) != len(values):
            raise RepositoryError(f'{field} requires 1..8 unique identifiers')
        if any(not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value) for value in values):
            raise RepositoryError(f'Invalid {field} identifier')
    keyring = Path(config.get('keyring', ''))
    if not keyring.is_absolute() or not keyring.is_file() or keyring.stat().st_size > 16 * 1024 * 1024:
        raise RepositoryError('keyring must identify an existing, server-approved absolute keyring file (maximum 16 MiB)')
    return {**config, 'base_url': config['base_url'].rstrip('/'), 'keyring': str(keyring.resolve())}


def _fields(lines):
    result, previous = {}, None
    for line in lines:
        if line.startswith((' ', '\t')) and previous:
            result[previous] += '\n' + line.strip()
        elif ':' in line:
            key, value = line.split(':', 1)
            if key in result:
                raise RepositoryError('Duplicate metadata field: ' + key)
            result[key], previous = value.strip(), key
        elif line:
            raise RepositoryError('Malformed Debian metadata line')
    return result


def _safe_path(path):
    value = PurePosixPath(path)
    if not path or value.is_absolute() or '..' in value.parts or '\\' in path or '\x00' in path:
        raise RepositoryError('Repository metadata contains an unsafe path')
    return str(value)


class RepositoryCatalog:
    def __init__(self, cache_dir=None, *, timeout=30, max_compressed_bytes=32 * 1024 * 1024,
                 max_decompressed_bytes=128 * 1024 * 1024, max_packages=250000, allow_local=False,
                 max_catalog_seconds=300):
        self.timeout, self.max_compressed_bytes = timeout, max_compressed_bytes
        self.max_decompressed_bytes, self.max_packages, self.allow_local = max_decompressed_bytes, max_packages, allow_local
        self.max_catalog_seconds = max_catalog_seconds
        self.cache_dir = Path(cache_dir).resolve() if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _fetch(self, url, path, limit):
        parsed = urlparse(url)
        if not (self.allow_local and parsed.hostname in {'localhost', '127.0.0.1', '::1'}):
            addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(entry[4][0]).is_global for entry in addresses):
                raise RepositoryError('Repository endpoint must resolve only to public addresses')
        digest, size = hashlib.sha256(), 0
        deadline = time.monotonic() + self.timeout * 4
        request = Request(url, headers={'Accept-Encoding': 'identity', 'User-Agent': 'SONiC-Smart-Patch-RepositoryCatalog/1'})
        with build_opener(NoRedirects()).open(request, timeout=self.timeout) as response, path.open('wb') as target:
            if response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise RepositoryError('Unexpected HTTP content encoding')
            while True:
                if time.monotonic() > deadline:
                    raise RepositoryError('Repository download exceeded time budget')
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise RepositoryError('Repository download exceeds configured byte limit')
                digest.update(chunk)
                target.write(chunk)
        return digest.hexdigest(), size

    def _release(self, repository, folder):
        base = repository['base_url'] + '/dists/' + quote(repository['suite'], safe='')
        signed, release = folder / 'InRelease', folder / 'Release'
        keyring = repository['keyring']
        home = folder / 'gnupg'
        home.mkdir(mode=0o700)
        try:
            self._fetch(base + '/InRelease', signed, 2 * 1024 * 1024)
        except HTTPError as exc:
            if exc.code != 404:
                raise
            self._fetch(base + '/Release', release, 2 * 1024 * 1024)
            signature = folder / 'Release.gpg'
            self._fetch(base + '/Release.gpg', signature, 65536)
            command = ['gpgv', '--homedir', str(home), '--keyring', keyring, '--status-fd', '1', str(signature), str(release)]
        else:
            command = ['gpgv', '--homedir', str(home), '--keyring', keyring, '--status-fd', '1', '--output', str(release), str(signed)]
        verified = run_bounded(command, timeout=15, max_bytes=65536)
        statuses = [line.split() for line in verified.splitlines() if line.startswith('[GNUPG:]')]
        valid = [line[2] for line in statuses if len(line) > 2 and line[1] == 'VALIDSIG']
        if not valid or any(line[1] in {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG'} for line in statuses if len(line) > 1):
            raise RepositoryError('Release signature is invalid, expired or revoked')
        fields = _fields(release.read_text(encoding='utf-8').splitlines())
        if repository['suite'] not in {fields.get('Suite'), fields.get('Codename')}:
            raise RepositoryError('Signed Release suite/codename differs from configured suite')
        current = datetime.now(timezone.utc)
        try:
            date = parsedate_to_datetime(fields['Date'])
            if date.tzinfo is None or (date - current).total_seconds() > 300:
                raise ValueError('invalid publication date')
            expires = parsedate_to_datetime(fields['Valid-Until']) if fields.get('Valid-Until') else None
            if expires and (expires.tzinfo is None or expires <= current):
                raise ValueError('metadata expired')
        except (KeyError, TypeError, ValueError) as exc:
            raise RepositoryError('Signed Release dates are invalid or expired') from exc
        hashes = {}
        for entry in fields.get('SHA256', '').splitlines():
            if not entry.strip():
                continue
            values = entry.split()
            if len(values) != 3 or not re.fullmatch(r'[0-9a-fA-F]{64}', values[0]) or not values[1].isdigit():
                raise RepositoryError('Invalid signed SHA256 entry')
            name = _safe_path(values[2])
            if name in hashes:
                raise RepositoryError('Duplicate signed file checksum')
            hashes[name] = (values[0].lower(), int(values[1]))
        if not hashes:
            raise RepositoryError('Release has no SHA256 index manifest')
        evidence = {'id': 'apt-release-' + hashlib.sha256(release.read_bytes()).hexdigest()[:24],
                    'type': 'signed_repository_release', 'repository': repository['base_url'], 'suite': repository['suite'],
                    'signing_fingerprints': valid, 'published_at': date.isoformat(),
                    'valid_until': expires.isoformat() if expires else None, 'verified_at': current.isoformat()}
        return base, fields, hashes, evidence

    def _packages(self, path):
        """Stream stanzas; memory stays bounded by one compressed chunk and one stanza."""
        total, buffered, stanza, stanza_bytes, count = 0, b'', [], 0, 0
        for chunk in self._decompressed_chunks(path):
                total += len(chunk)
                if total > self.max_decompressed_bytes:
                    raise RepositoryError('Decompressed Packages index exceeds configured limit')
                buffered += chunk
                lines = buffered.split(b'\n')
                buffered = lines.pop()
                if len(buffered) > 256 * 1024:
                    raise RepositoryError('Metadata line exceeds limit')
                for raw in lines:
                    line = raw.decode('utf-8', errors='strict').rstrip('\r')
                    if not line:
                        if stanza:
                            count += 1
                            if count > self.max_packages:
                                raise RepositoryError('Package count exceeds configured limit')
                            yield _fields(stanza)
                            stanza, stanza_bytes = [], 0
                    else:
                        stanza_bytes += len(raw)
                        if stanza_bytes > 512 * 1024:
                            raise RepositoryError('Package stanza exceeds configured limit')
                        stanza.append(line)
        if buffered:
            stanza.append(buffered.decode('utf-8'))
        if stanza:
            if count >= self.max_packages:
                raise RepositoryError('Package count exceeds configured limit')
            yield _fields(stanza)

    @staticmethod
    def _decompressed_chunks(path):
        if path.name.endswith('.xz'):
            decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
            with path.open('rb') as source:
                while True:
                    compressed = source.read(65536)
                    if not compressed:
                        break
                    if decoder.eof:
                        if compressed.strip(b'\x00'):
                            raise RepositoryError('Unexpected data after XZ stream')
                        continue
                    output = decoder.decompress(compressed, max_length=65536)
                    if output:
                        yield output
                    while not decoder.needs_input and not decoder.eof:
                        output = decoder.decompress(b'', max_length=65536)
                        if output:
                            yield output
                    if decoder.eof and decoder.unused_data.strip(b'\x00'):
                        raise RepositoryError('Unexpected concatenated XZ data')
            if not decoder.eof:
                raise RepositoryError('Truncated XZ stream')
        else:
            opener = gzip.open if path.name.endswith('.gz') else open
            with opener(path, 'rb') as source:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    yield chunk

    def _index(self, repository, component, architecture, base, hashes, folder, wanted):
        if architecture not in {'all', *repository['architectures']}:
            raise RepositoryError('Unexpected architecture')
        stem = component + '/binary-' + architecture + '/Packages'
        name = next((stem + suffix for suffix in ('.xz', '.gz', '') if stem + suffix in hashes), None)
        if not name:
            raise RepositoryError('Signed Release has no index for ' + stem)
        expected_hash, expected_size = hashes[name]
        if expected_size > self.max_compressed_bytes:
            raise RepositoryError('Signed index size exceeds compressed input limit')
        path = folder / ('Packages' + ('.xz' if name.endswith('.xz') else '.gz' if name.endswith('.gz') else ''))
        actual_hash, actual_size = self._fetch(base + '/' + name, path, self.max_compressed_bytes)
        if (actual_hash, actual_size) != (expected_hash, expected_size):
            raise RepositoryError('Packages checksum/size does not match signed Release')
        index_id = stable_id([repository['base_url'], repository['suite'], component, architecture])
        candidates, count, observed = [], 0, []
        # Bound snapshot storage independently from decompressed bytes.
        for package in self._packages(path):
            count += 1
            package_name, version, arch = package.get('Package'), package.get('Version'), package.get('Architecture')
            if (not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,255}', package_name or '')
                    or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]{0,255}', version or '') or arch not in {architecture, 'all'}):
                raise RepositoryError('Package identity or architecture is invalid')
            observed.append((package_name, arch, version))
            if package_name not in wanted:
                continue
            filename = _safe_path(package.get('Filename', ''))
            checksum = package.get('SHA256', '')
            if not re.fullmatch(r'[0-9a-fA-F]{64}', checksum):
                raise RepositoryError('Candidate package lacks SHA256 checksum')
            source = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?:\s+\(([^)]+)\))?', package.get('Source') or package_name)
            if not source:
                raise RepositoryError('Candidate source package metadata is invalid')
            candidates.append({'name': package_name, 'version': version, 'architecture': arch,
                               'source_name': source.group(1), 'source_version': source.group(2) or version,
                               'filename': filename, 'sha256': checksum.lower(), 'repository': repository['base_url'],
                               'suite': repository['suite'], 'index_sha256': expected_hash})
        changes = self._track_index(index_id, observed) if self.cache_dir else {'baseline_created': None, 'new_packages_count': None, 'new_packages': []}
        evidence = {'id': 'apt-index-' + expected_hash[:24], 'type': 'verified_packages_index',
                    'repository': repository['base_url'], 'suite': repository['suite'], 'component': component,
                    'architecture': architecture, 'path': name, 'sha256': expected_hash, 'bytes': expected_size,
                    'packages_count': count, **changes}
        for candidate in candidates:
            candidate['evidence_id'] = evidence['id']
        return candidates, evidence

    def _track_index(self, ident, rows):
        database = self.cache_dir / 'catalog.sqlite3'
        if database.exists() and database.stat().st_size > 512 * 1024 * 1024:
            raise RepositoryError('Repository catalog exceeds 512 MiB disk bound')
        with sqlite3.connect(database, timeout=30) as connection:
            connection.execute('CREATE TABLE IF NOT EXISTS packages (idx TEXT, name TEXT, arch TEXT, version TEXT, PRIMARY KEY(idx,name,arch))')
            baseline = connection.execute('SELECT 1 FROM packages WHERE idx=? LIMIT 1', (ident,)).fetchone() is None
            connection.execute('CREATE TEMP TABLE current_packages (name TEXT, arch TEXT, version TEXT, PRIMARY KEY(name,arch))')
            connection.executemany('INSERT OR REPLACE INTO current_packages VALUES (?,?,?)', rows)
            count = 0 if baseline else connection.execute('SELECT COUNT(*) FROM current_packages c LEFT JOIN packages p ON p.idx=? AND p.name=c.name AND p.arch=c.arch WHERE p.name IS NULL', (ident,)).fetchone()[0]
            added = [] if baseline else [{'name': r[0], 'architecture': r[1], 'version': r[2]} for r in connection.execute('SELECT c.name,c.arch,c.version FROM current_packages c LEFT JOIN packages p ON p.idx=? AND p.name=c.name AND p.arch=c.arch WHERE p.name IS NULL LIMIT 200', (ident,))]
            connection.execute('DELETE FROM packages WHERE idx=?', (ident,))
            connection.execute('INSERT INTO packages SELECT ?,name,arch,version FROM current_packages', (ident,))
        return {'baseline_created': baseline, 'new_packages_count': count, 'new_packages': added, 'new_packages_truncated': count > len(added)}

    def lookup(self, repositories, packages):
        started = time.monotonic()
        if not isinstance(repositories, list) or len(repositories) > 16:
            raise RepositoryError('Configure at most 16 repositories')
        if sum(len(r.get('components', [])) * len(r.get('architectures', [])) for r in repositories if isinstance(r, dict)) > 32:
            raise RepositoryError('Configure at most 32 component/architecture indices per catalog run')
        requested = [p for p in packages if (p.get('ecosystem') in {'deb', 'dpkg'} or str(p.get('purl', '')).startswith('pkg:deb/'))]
        wanted = {p['name'] for p in requested}
        evidence, candidates, errors = [], [], []
        for config in repositories:
            try:
                if time.monotonic() - started > self.max_catalog_seconds:
                    raise RepositoryError('Repository catalog exceeded overall time budget')
                repository = checked_repository(config, self.allow_local)
                with tempfile.TemporaryDirectory(prefix='smart-patch-apt-') as temporary:
                    folder = Path(temporary)
                    base, fields, hashes, release_evidence = self._release(repository, folder)
                    evidence.append(release_evidence)
                    for component in repository['components']:
                        if component not in fields.get('Components', '').split():
                            raise RepositoryError('Configured component is absent from signed Release')
                        for arch in repository['architectures']:
                            if time.monotonic() - started > self.max_catalog_seconds:
                                raise RepositoryError('Repository catalog exceeded overall time budget')
                            if arch not in fields.get('Architectures', '').split():
                                raise RepositoryError('Configured architecture is absent from signed Release')
                            found, proof = self._index(repository, component, arch, base, hashes, folder, wanted)
                            proof['release_evidence_id'] = release_evidence['id']
                            evidence.append(proof)
                            candidates.extend(found)
            except Exception as exc:
                errors.append({'repository': config.get('base_url', '') if isinstance(config, dict) else '',
                               'stage': 'repository_catalog', 'message': f'{type(exc).__name__}: {str(exc)[:500]}'})
        complete = bool(repositories) and not errors
        configured_arches = {a for config in repositories if isinstance(config, dict) for a in config.get('architectures', []) if isinstance(a, str)}
        by_name = {}
        for candidate in candidates:
            by_name.setdefault(candidate['name'], []).append(candidate)
        output = []
        for package in requested:
            arch = package.get('arch') or package.get('architecture')
            architecture_covered = bool(arch and (arch == 'all' or arch in configured_arches))
            applicable = [c for c in by_name.get(package['name'], []) if not arch or c['architecture'] in {arch, 'all'}]
            latest = None
            versions = []
            for candidate in applicable:
                if candidate['version'] not in versions:
                    versions.append(candidate['version'])
                if latest is None or compare_versions('deb', latest['version'], candidate['version']) < 0:
                    latest = candidate
            status = 'available' if latest and complete and architecture_covered else 'not_found' if complete and architecture_covered else 'unknown'
            newer = None
            comparison_error = None
            if latest and complete and architecture_covered and package.get('version'):
                try:
                    newer = compare_versions('deb', package['version'], latest['version']) < 0
                except (ValueError, OSError) as exc:
                    comparison_error = str(exc)[:200]
            output.append({'component_id': package.get('id') or package.get('component_id'), 'name': package['name'],
                'architecture': arch, 'installed_version': package.get('version'),
                'latest_available_version': latest['version'] if latest and complete and architecture_covered else None,
                'available_versions': versions, 'newer_version_available': newer, 'status': status,
                'version_comparison_error': comparison_error,
                'availability_basis': 'signature-verified configured APT indices' if complete else 'incomplete or unconfigured repository catalog',
                'candidate': latest if latest and complete and architecture_covered else None,
                'evidence_ids': sorted({c['evidence_id'] for c in applicable})})
        return {'packages': output, 'evidence': evidence, 'coverage': {'complete': complete, 'repositories_total': len(repositories),
                'repositories_verified': sum(e['type'] == 'signed_repository_release' for e in evidence)}, 'errors': errors}
