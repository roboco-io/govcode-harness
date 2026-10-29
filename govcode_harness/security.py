"""Bounded canonical JSON and local synthetic-reference Ed25519 signatures.

Trust subjects and roles are caller-owned, never supplied by signed claims.
Cryptography is imported only when key or signature operations are requested.
"""
import base64
import json
import os
import re
import stat
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32
CONTEXT = 'synthetic_reference'
ROLES = {'author', 'approver', 'operator', 'auditor'}


class SecurityError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    nodes = 0
    def check(item, depth):
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > 50000:
            raise SecurityError('JSON_LIMIT')
        if item is None or type(item) in (bool, int, str):
            return
        if type(item) is float:
            import math
            if not math.isfinite(item): raise SecurityError('JSON_INVALID')
            return
        if type(item) is list:
            for entry in item: check(entry, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for entry in item.values(): check(entry, depth + 1)
            return
        raise SecurityError('JSON_INVALID')
    try:
        check(value, 0)
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
        if len(encoded) > MAX_BYTES: raise SecurityError('JSON_LIMIT')
        return encoded
    except SecurityError:
        raise
    except Exception:
        raise SecurityError('JSON_INVALID') from None


def identifier(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value):
        raise SecurityError('IDENTIFIER_INVALID')
    return value


def safe_path(value):
    path = Path(value).absolute()
    for part in (path, *path.parents):
        if part.is_symlink(): raise SecurityError('PATH_UNSAFE')
    return path


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise SecurityError('JSON_DUPLICATE_KEY')
            result[key] = value
        return result
    try:
        path = safe_path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise SecurityError('PATH_UNSAFE')
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: raise SecurityError('JSON_LIMIT')
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(SecurityError('JSON_INVALID')))
        canonical(value)
        return value
    except SecurityError: raise
    except Exception: raise SecurityError('JSON_INVALID') from None


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except ImportError:
        raise SecurityError('CRYPTO_UNAVAILABLE') from None


def _decode(value, size):
    if type(value) is not str: raise SecurityError('SIGNATURE_INVALID')
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != size: raise ValueError()
        return raw
    except Exception: raise SecurityError('SIGNATURE_INVALID') from None


def generate_keypair(directory, key_id):
    identifier(key_id)
    private, _, serialization = _crypto()
    try:
        directory = safe_path(directory)
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        key = private.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        path = directory / 'private.key'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {'key_id': key_id, 'public_key': base64.b64encode(public).decode('ascii'), 'private_path': str(path)}
    except SecurityError: raise
    except Exception: raise SecurityError('KEY_CREATE_FAILED') from None


def sign(payload, private_path, key_id):
    identifier(key_id)
    encoded = canonical(payload)
    private, _, _ = _crypto()
    try:
        path = safe_path(private_path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise SecurityError('PATH_UNSAFE')
            if os.fstat(stream.fileno()).st_mode & 0o077: raise SecurityError('KEY_PERMISSIONS')
            raw = stream.read(33)
        key = private.from_private_bytes(raw)
        signature = key.sign(encoded)
        # Roundtrip prevents mutable aliasing of the caller's payload.
        return {'format': 'govcode-signed-v1', 'key_id': key_id, 'payload': json.loads(encoded), 'signature': base64.b64encode(signature).decode('ascii')}
    except SecurityError: raise
    except Exception: raise SecurityError('SIGN_FAILED') from None


def verify(envelope, trust, required_role, tenant_id, project_id):
    try:
        canonical(envelope)
        canonical(trust)
        if required_role not in ROLES or trust.get('context') != CONTEXT: raise SecurityError('TRUST_INVALID')
        if set(envelope) != {'format', 'key_id', 'payload', 'signature'} or envelope['format'] != 'govcode-signed-v1': raise SecurityError('ENVELOPE_INVALID')
        identifier(envelope['key_id'])
        key = trust['keys'][envelope['key_id']]
        if key.get('revoked') is not False: raise SecurityError('KEY_REVOKED')
        if required_role not in key['roles']: raise SecurityError('ROLE_REQUIRED')
        if key['tenant_id'] != tenant_id or key['project_id'] != project_id: raise SecurityError('SCOPE_MISMATCH')
        payload = envelope['payload']
        if payload['context'] != CONTEXT or payload['tenant_id'] != tenant_id or payload['project_id'] != project_id: raise SecurityError('SCOPE_MISMATCH')
        if payload['actor_id'] != key['actor_id']: raise SecurityError('SUBJECT_MISMATCH')
        identifier(payload['actor_id'])
        _, public, _ = _crypto()
        public.from_public_bytes(_decode(key['public_key'], 32)).verify(_decode(envelope['signature'], 64), canonical(payload))
        return json.loads(canonical(payload))
    except SecurityError: raise
    except Exception: raise SecurityError('SIGNATURE_INVALID') from None
