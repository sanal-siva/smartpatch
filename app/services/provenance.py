"""Verify an approved builder's external release-index signature and artifact binding.

This verifies a signed *release baseline*. It neither attests a switch's runtime
nor proves that its currently executing software is identical to that baseline.
Only public keys provisioned in the server's trusted-build-key directory are used.
"""
import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_SIGNATURE_TEXT = 4096
MAX_SIGNATURE_BYTES = 1024
KEY_ID_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
DIGEST_PATTERN = re.compile(r'[0-9a-fA-F]{64}\Z')
REQUEST_FIELDS = {'release_id', 'manifest_text', 'release_index_text', 'signature_base64', 'key_id'}


class ProvenanceVerificationError(ValueError):
    """The submitted release binding cannot be verified with an approved key."""


def _raw_document(value, label):
    if not isinstance(value, str) or not value or len(value) > MAX_DOCUMENT_BYTES:
        raise ProvenanceVerificationError(f'{label} must be nonempty UTF-8 text, at most 1 MiB')
    try:
        raw = value.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ProvenanceVerificationError(f'{label} contains invalid Unicode') from exc
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ProvenanceVerificationError(f'{label} exceeds the 1 MiB UTF-8 byte limit')
    return raw


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceVerificationError('Duplicate JSON object keys are forbidden')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ProvenanceVerificationError('Non-finite JSON numbers are forbidden')


def _json_object(raw, label):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except ProvenanceVerificationError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProvenanceVerificationError(f'{label} is not a bounded valid JSON object') from exc
    if not isinstance(value, dict):
        raise ProvenanceVerificationError(f'{label} must be a JSON object')
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > 10000:
            raise ProvenanceVerificationError(f'{label} exceeds JSON structural limits')
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProvenanceVerificationError('Non-finite JSON numbers are forbidden')
    if type(value.get('schema_version')) is not int or value['schema_version'] != 1:
        raise ProvenanceVerificationError(f'{label} requires schema_version 1')
    return value


def _sha256(value, label):
    if not isinstance(value, str):
        raise ProvenanceVerificationError(f'{label} must contain a SHA-256 digest')
    digest = value.removeprefix('sha256:')
    if not DIGEST_PATTERN.fullmatch(digest):
        raise ProvenanceVerificationError(f'{label} must contain a SHA-256 digest')
    return digest.lower()


def _trusted_public_key(directory, key_id):
    """Open a regular file relative to an approved directory, without symlinks.

    O_NOFOLLOW on both the directory and key file prevents the final components
    from being replaced by symlinks. The open directory descriptor pins key lookup
    to that directory even if its name is subsequently replaced.
    """
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
        raise ProvenanceVerificationError('key_id must be a safe approved-key identifier')
    directory_fd = key_fd = None
    try:
        directory_fd = os.open(Path(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if os.fstat(directory_fd).st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProvenanceVerificationError('Approved key directory must not be writable by group or others')
        key_fd = os.open(key_id + '.pem', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory_fd)
        info = os.fstat(key_fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_KEY_BYTES:
            raise ProvenanceVerificationError('Approved key must be a regular PEM file no larger than 16 KiB')
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProvenanceVerificationError('Approved key must not be writable by group or others')
        chunks = []
        size = 0
        while size <= MAX_KEY_BYTES:
            block = os.read(key_fd, min(4096, MAX_KEY_BYTES + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        if size > MAX_KEY_BYTES:
            raise ProvenanceVerificationError('Approved key exceeds the 16 KiB limit')
        pem = b''.join(chunks)
    except OSError as exc:
        raise ProvenanceVerificationError('Approved public key is unavailable or uses a forbidden symlink') from exc
    finally:
        if key_fd is not None:
            os.close(key_fd)
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ProvenanceVerificationError('Approved key is not a supported PEM public key') from exc
    if isinstance(key, rsa.RSAPublicKey):
        if not 2048 <= key.key_size <= 8192:
            raise ProvenanceVerificationError('RSA build keys must be 2048–8192 bits')
    elif not isinstance(key, ed25519.Ed25519PublicKey):
        raise ProvenanceVerificationError('Only RSA and Ed25519 build-signing public keys are supported')
    return key


def _verify_signature(raw_index, signature_text, key):
    if not isinstance(signature_text, str) or not signature_text or len(signature_text) > MAX_SIGNATURE_TEXT:
        raise ProvenanceVerificationError('Signature must be bounded base64 text')
    try:
        signature = base64.b64decode(''.join(signature_text.split()), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProvenanceVerificationError('Signature is not valid base64') from exc
    if not 0 < len(signature) <= MAX_SIGNATURE_BYTES:
        raise ProvenanceVerificationError('Decoded signature exceeds supported bounds')
    try:
        if isinstance(key, rsa.RSAPublicKey):
            if len(signature) != (key.key_size + 7) // 8:
                raise ProvenanceVerificationError('Signature length does not match the approved RSA key')
            key.verify(signature, raw_index, padding.PKCS1v15(), hashes.SHA256())
            return 'rsa-pkcs1v15-sha256'
        if len(signature) != 64:
            raise ProvenanceVerificationError('Ed25519 signatures must be 64 bytes')
        key.verify(signature, raw_index)
        return 'ed25519'
    except InvalidSignature as exc:
        raise ProvenanceVerificationError('Release-index signature verification failed') from exc


def verify_release_binding(body, artifact, trusted_key_dir):
    """Return a verified signed-baseline binding; do not modify registry/device state.

    ``artifact`` must come from the server registry, never the request body. Its
    ``source_sha256`` is the SHA-256 of the exact original SBOM upload/download
    bytes. Canonicalized parsed-JSON digests are deliberately not substituted.
    Returned digest fields use the ``sha256:<hex>`` representation.
    """
    if not isinstance(body, dict) or set(body) != REQUEST_FIELDS:
        raise ProvenanceVerificationError('Supply exactly release_id, manifest_text, release_index_text, signature_base64 and key_id')
    release_id = body['release_id']
    if not isinstance(release_id, str) or not release_id.strip() or len(release_id) > 256:
        raise ProvenanceVerificationError('A valid registered release_id is required')
    if not isinstance(artifact, dict) or not artifact:
        raise ProvenanceVerificationError('A registered SBOM artifact is required')
    if artifact.get('release_id') is not None and artifact['release_id'] != release_id:
        raise ProvenanceVerificationError('Registered artifact belongs to a different release')
    sbom_digest = _sha256(artifact.get('source_sha256'), 'Registered raw SBOM source_sha256')
    raw_manifest = _raw_document(body['manifest_text'], 'Manifest')
    raw_index = _raw_document(body['release_index_text'], 'Release index')
    key = _trusted_public_key(trusted_key_dir, body['key_id'])
    algorithm = _verify_signature(raw_index, body['signature_base64'], key)
    index = _json_object(raw_index, 'Release index')
    manifest = _json_object(raw_manifest, 'Manifest')

    actual_manifest_digest = hashlib.sha256(raw_manifest).hexdigest()
    expected_manifest_digest = _sha256(index.get('manifest_sha256'), 'Release-index manifest_sha256')
    if not hmac.compare_digest(actual_manifest_digest, expected_manifest_digest):
        raise ProvenanceVerificationError('Manifest digest does not match the signed release index')
    build_id = manifest.get('build_id')
    if not isinstance(build_id, str) or not build_id.startswith('sha256:') or index.get('build_id') != build_id:
        raise ProvenanceVerificationError('Manifest and signed release-index build_id values must match')
    _sha256(build_id, 'Manifest build_id')
    canonical = json.dumps({k: v for k, v in manifest.items() if k != 'build_id'},
                           sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    calculated_build_id = 'sha256:' + hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(build_id, calculated_build_id):
        raise ProvenanceVerificationError('Manifest build_id does not match its canonical build identity')

    records = index.get('artifacts')
    if not isinstance(records, list) or not 1 <= len(records) <= 32:
        raise ProvenanceVerificationError('Release index must contain a bounded artifact list')
    digests = {}
    for record in records:
        if not isinstance(record, dict):
            raise ProvenanceVerificationError('Each indexed artifact must be an object')
        kind = record.get('kind')
        if not isinstance(kind, str) or not kind or len(kind) > 64 or kind in digests:
            raise ProvenanceVerificationError('Indexed artifact kinds must be nonempty and unique')
        digests[kind] = _sha256(record.get('sha256'), f'{kind} artifact sha256')
        if 'bytes' in record and (type(record['bytes']) is not int or record['bytes'] <= 0):
            raise ProvenanceVerificationError('Indexed artifact byte sizes must be positive integers')
    if not {'image', 'sbom'} <= digests.keys():
        raise ProvenanceVerificationError('Signed release index requires both image and SBOM artifact records')
    if 'sbom_available' in index and index['sbom_available'] is not True:
        raise ProvenanceVerificationError('Signed index contradicts its SBOM artifact record')
    if not hmac.compare_digest(sbom_digest, digests['sbom']):
        raise ProvenanceVerificationError('Registered raw SBOM digest does not match the signed release index')
    public_der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        'artifact_id': artifact.get('id'),
        'build_id': build_id,
        'manifest_digest': 'sha256:' + actual_manifest_digest,
        'sbom_digest': 'sha256:' + sbom_digest,
        'image_digest': 'sha256:' + digests['image'],
        'index_digest': 'sha256:' + hashlib.sha256(raw_index).hexdigest(),
        'key_id': body['key_id'],
        'key_fingerprint': 'sha256:' + hashlib.sha256(public_der).hexdigest(),
        'signature_algorithm': algorithm,
        'verification': 'signature_verified',
        'binding_scope': 'signed_release_baseline',
        'verified_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
    }
