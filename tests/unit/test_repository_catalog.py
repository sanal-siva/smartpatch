import functools
import hashlib
import lzma
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from app.services.repository_catalog import RepositoryCatalog, RepositoryError, checked_repository


@pytest.fixture(scope='module')
def signer(tmp_path_factory):
    home = tmp_path_factory.mktemp('smart-patch-repository-signing')
    home.chmod(0o700)
    subprocess.run(['gpg', '--homedir', str(home), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                    '--quick-generate-key', 'Smart Patch Test <repository@example.test>', 'ed25519', 'sign', '1d'],
                   check=True, capture_output=True, timeout=30)
    keyring = home / 'trusted.gpg'
    keyring.write_bytes(subprocess.check_output(['gpg', '--homedir', str(home), '--batch', '--export'], timeout=10))
    yield home, keyring
    subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'], capture_output=True, timeout=10)


@pytest.fixture
def repository(tmp_path, signer):
    home, keyring = signer
    base = tmp_path / 'repository'
    index = base / 'dists/bookworm/main/binary-amd64'
    index.mkdir(parents=True)
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = functools.partial(QuietHandler, directory=str(base))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = {'base_url': f'http://127.0.0.1:{server.server_port}', 'suite': 'bookworm',
              'components': ['main'], 'architectures': ['amd64'], 'keyring': str(keyring)}
    def publish(versions=('9.0-1', '1:1.0-1'), *, new_package=False, expired=False):
        paragraphs = []
        for name, version in [('openssl', v) for v in versions] + ([('smart-patch-new', '1.0-1')] if new_package else []):
            digest = hashlib.sha256((name + version).encode()).hexdigest()
            paragraphs.append(f'Package: {name}\nVersion: {version}\nArchitecture: amd64\nFilename: pool/main/{name}_{version}_amd64.deb\nSHA256: {digest}\nSize: 10\n\n')
        raw = ''.join(paragraphs).encode()
        packed = lzma.compress(raw)
        (index / 'Packages.xz').write_bytes(packed)
        current = datetime.now(timezone.utc)
        expiration = current + timedelta(days=-1 if expired else 1)
        release = base / 'dists/bookworm/Release'
        release.write_text(f'Origin: Smart Patch Test\nSuite: bookworm\nCodename: bookworm\nDate: {format_datetime(current)}\nValid-Until: {format_datetime(expiration)}\nArchitectures: amd64\nComponents: main\nSHA256:\n {hashlib.sha256(packed).hexdigest()} {len(packed)} main/binary-amd64/Packages.xz\n')
        subprocess.run(['gpg', '--homedir', str(home), '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '',
                        '--clearsign', '--output', str(release.with_name('InRelease')), str(release)],
                       check=True, capture_output=True, timeout=10)
    publish()
    yield config, publish, base
    server.shutdown()
    server.server_close()
    thread.join()


def package():
    return {'id': 'openssl1', 'name': 'openssl', 'version': '0.9-1', 'arch': 'amd64', 'ecosystem': 'deb'}


def test_signed_catalog_uses_native_debian_order_and_evidence(repository, tmp_path):
    config, _, _ = repository
    result = RepositoryCatalog(tmp_path / 'cache', allow_local=True).lookup([config], [package()])
    assert result['coverage']['complete'], result['errors']
    available = result['packages'][0]
    assert available['latest_available_version'] == '1:1.0-1'
    assert available['newer_version_available'] is True
    assert available['candidate']['sha256']
    assert result['evidence'][0]['signing_fingerprints']


def test_modified_signed_release_is_rejected(repository):
    config, _, base = repository
    path = base / 'dists/bookworm/InRelease'
    path.write_text(path.read_text().replace('Origin: Smart Patch Test', 'Origin: Tampered'))
    result = RepositoryCatalog(allow_local=True).lookup([config], [package()])
    assert not result['coverage']['complete']
    assert result['packages'][0]['latest_available_version'] is None
    assert result['errors']


def test_checksum_tampering_is_rejected(repository):
    config, _, base = repository
    (base / 'dists/bookworm/main/binary-amd64/Packages.xz').write_bytes(lzma.compress(b'Package: attacker\n'))
    result = RepositoryCatalog(allow_local=True).lookup([config], [package()])
    assert not result['coverage']['complete']
    assert 'checksum/size' in result['errors'][0]['message']


def test_expired_release_is_rejected(repository):
    config, publish, _ = repository
    publish(expired=True)
    result = RepositoryCatalog(allow_local=True).lookup([config], [package()])
    assert not result['coverage']['complete']
    assert 'expired' in result['errors'][0]['message']


def test_decompression_limit_prevents_catalog_import(repository):
    config, _, _ = repository
    result = RepositoryCatalog(allow_local=True, max_decompressed_bytes=40).lookup([config], [package()])
    assert not result['coverage']['complete']
    assert 'Decompressed' in result['errors'][0]['message']


def test_new_upstream_names_are_detected_after_baseline(repository, tmp_path):
    config, publish, _ = repository
    catalog = RepositoryCatalog(tmp_path / 'cache', allow_local=True)
    first = catalog.lookup([config], [package()])
    assert first['evidence'][1]['baseline_created'] is True
    publish(new_package=True)
    second = catalog.lookup([config], [package()])
    assert second['evidence'][1]['new_packages_count'] == 1
    assert second['evidence'][1]['new_packages'][0]['name'] == 'smart-patch-new'


def test_no_configuration_keeps_latest_unknown():
    result = RepositoryCatalog().lookup([], [package()])
    assert result['packages'][0]['latest_available_version'] is None
    assert result['packages'][0]['status'] == 'unknown'


def test_private_http_repository_is_not_enabled_by_configuration(repository):
    config, _, _ = repository
    with pytest.raises(RepositoryError, match='HTTPS'):
        checked_repository(config)


def test_wrong_keyring_cannot_verify_repository(repository, tmp_path):
    config, _, _ = repository
    unknown = tmp_path / 'untrusted.gpg'
    unknown.write_bytes(b'')
    result = RepositoryCatalog(allow_local=True).lookup([{**config, 'keyring': str(unknown)}], [package()])
    assert not result['coverage']['complete']
    assert result['packages'][0]['status'] == 'unknown'


def test_unknown_architecture_does_not_claim_latest(repository):
    config, _, _ = repository
    item = package()
    item.pop('arch')
    result = RepositoryCatalog(allow_local=True).lookup([config], [item])
    assert result['packages'][0]['latest_available_version'] is None
    assert result['packages'][0]['status'] == 'unknown'


def test_detached_release_signature_fallback(repository, signer):
    config, _, base = repository
    home, _ = signer
    release = base / 'dists/bookworm/Release'
    subprocess.run(['gpg', '--homedir', str(home), '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '',
                    '--detach-sign', '--output', str(release.with_name('Release.gpg')), str(release)],
                   check=True, capture_output=True, timeout=10)
    release.with_name('InRelease').unlink()
    result = RepositoryCatalog(allow_local=True).lookup([config], [package()])
    assert result['coverage']['complete'], result['errors']


def test_unconfigured_architecture_is_unknown_not_absent(repository):
    config, _, _ = repository
    result = RepositoryCatalog(allow_local=True).lookup([config], [{**package(), 'arch': 'arm64'}])
    assert result['packages'][0]['status'] == 'unknown'
    assert result['packages'][0]['latest_available_version'] is None
