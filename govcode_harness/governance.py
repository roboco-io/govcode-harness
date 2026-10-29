"""Signed policy lifecycle for a synthetic, local reference authority only.

Offline callers must pin a sequence floor and supply their newest signed
revocations. Cached revocation data cannot promise immediate revocation.
Neither VERIFIED claims nor approvals here establish real legal applicability.
"""
import copy
import datetime as dt
import functools
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from . import security

CONTEXT = security.CONTEXT


class GovernanceError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _guard(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except GovernanceError: raise
        except security.SecurityError as error: raise GovernanceError(error.code) from None
        except Exception: raise GovernanceError('GOVERNANCE_INVALID') from None
    return guarded


def _require(condition, code='GOVERNANCE_INVALID'):
    if not condition: raise GovernanceError(code)


def digest(value):
    return hashlib.sha256(security.canonical(value)).hexdigest()


def _time(value):
    _require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value) is not None, 'TIME_INVALID')
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + '+00:00')
        _require(parsed.utcoffset() == dt.timedelta(0), 'TIME_INVALID')
        return parsed
    except GovernanceError: raise
    except Exception: raise GovernanceError('TIME_INVALID') from None


def _hash(value):
    _require(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'DIGEST_INVALID')


def _common(payload, now):
    security.identifier(payload['event_id'])
    _require(_time(payload['created_at']) <= _time(now), 'EVENT_IN_FUTURE')


def _scope(policy, tenant_id, project_id):
    _require(type(policy) is dict, 'POLICY_INVALID')
    allowed = {'id', 'version', 'basis_kind', 'scope', 'condition', 'effect', 'kind', 'control_id', 'lifecycle', 'enabled', 'evidence_requirements'}
    _require(not (set(policy) - allowed), 'POLICY_FIELD_UNKNOWN')
    security.identifier(policy['id'])
    security.identifier(policy['version'])
    if 'kind' in policy: _require(policy['kind'] == 'policy', 'POLICY_INVALID')
    if 'lifecycle' in policy: _require(policy['lifecycle'] == 'draft', 'POLICY_INVALID')
    if 'enabled' in policy: _require(policy['enabled'] is False, 'POLICY_INVALID')
    scope = policy['scope']
    _require(set(scope) == {'tenant_id', 'project_id', 'languages', 'stage'}, 'POLICY_SCOPE_INVALID')
    _require(scope['tenant_id'] == tenant_id and scope['project_id'] == project_id, 'SCOPE_MISMATCH')
    _require(scope['languages'] == ['python'] and scope['stage'] in ('merge', 'deploy'), 'POLICY_SCOPE_UNSUPPORTED')
    condition = policy['condition']
    _require(set(condition) == {'field', 'operator', 'value'}, 'POLICY_EXPRESSION_INVALID')
    _require(condition['field'] == 'finding.category' and condition['operator'] == 'eq', 'POLICY_EXPRESSION_UNSUPPORTED')
    security.identifier(condition['value'])
    _require(policy['effect'] == 'deny', 'POLICY_EFFECT_UNSUPPORTED')
    _require(policy['basis_kind'] in ('example_policy', 'statutory_obligation'), 'POLICY_BASIS_INVALID')


def _basis(policy, obligations, start, end=None):
    _require(type(obligations) is list, 'BASIS_INVALID')
    if policy['basis_kind'] == 'example_policy':
        _require(not obligations, 'EXAMPLE_BASIS_MIXED')
        return
    _require(bool(obligations), 'BASIS_REQUIRED')
    ids = set()
    for obligation in obligations:
        _require(set(obligation) == {'id', 'status', 'applicability', 'source_id', 'source_version', 'source_digest', 'effective_from', 'effective_to'}, 'BASIS_INVALID')
        _require(obligation['status'] == 'VERIFIED' and obligation['applicability'] == 'APPLICABLE', 'BASIS_UNCONFIRMED')
        for field in ('id', 'source_id', 'source_version'): security.identifier(obligation[field])
        _require(obligation['id'] not in ids, 'BASIS_DUPLICATE')
        ids.add(obligation['id'])
        _hash(obligation['source_digest'])
        begins, ends = _time(obligation['effective_from']), _time(obligation['effective_to'])
        _require(begins < ends and begins <= _time(start) < ends, 'BASIS_NOT_EFFECTIVE')
        if end is not None: _require(_time(end) <= ends, 'BASIS_NOT_EFFECTIVE')


def _signed_action(envelope, trust, tenant_id, project_id, now):
    payload = envelope.get('payload', {})
    action = payload.get('action')
    roles = {'draft': 'author', 'submit': 'author', 'approve': 'approver', 'retire': 'operator', 'revoke': 'operator'}
    _require(action in roles, 'ACTION_INVALID')
    payload = security.verify(envelope, trust, roles[action], tenant_id, project_id)
    fields = {'context', 'tenant_id', 'project_id', 'actor_id', 'event_id', 'created_at', 'action'}
    fields |= {'policy', 'obligations'} if action == 'draft' else {'policy_id', 'version', 'policy_digest'}
    _require(set(payload) == fields, 'ACTION_FIELDS_INVALID')
    _common(payload, now)
    return payload


def _transition(states, seen, envelope, trust, tenant_id, project_id, now):
    payload = _signed_action(envelope, trust, tenant_id, project_id, now)
    _require(payload['event_id'] not in seen, 'EVENT_REPLAY')
    action = payload['action']
    if action == 'draft':
        policy = payload['policy']
        _scope(policy, tenant_id, project_id)
        _basis(policy, payload['obligations'], now)
        identity = (policy['id'], policy['version'])
        _require(identity not in states, 'POLICY_VERSION_IMMUTABLE')
        states[identity] = {'policy': copy.deepcopy(policy), 'policy_digest': digest(policy), 'obligations': copy.deepcopy(payload['obligations']), 'state': 'draft', 'author_record': copy.deepcopy(envelope)}
    else:
        identity = (payload['policy_id'], payload['version'])
        _require(identity in states, 'POLICY_UNKNOWN')
        record = states[identity]
        _require(payload['policy_digest'] == record['policy_digest'], 'POLICY_DIGEST_MISMATCH')
        previous = {'submit': {'draft'}, 'approve': {'review'}, 'retire': {'approved'}, 'revoke': {'draft', 'review', 'approved', 'retired'}}[action]
        _require(record['state'] in previous, 'TRANSITION_INVALID')
        _require(_time(payload['created_at']) >= _time(record['last_created_at']) and _time(now) >= _time(record['last_received_at']), 'EVENT_TIME_ORDER')
        if action == 'submit':
            _require(payload['actor_id'] == record['author_record']['payload']['actor_id'], 'AUTHOR_MISMATCH')
            record['submit_record'] = copy.deepcopy(envelope)
        if action == 'approve':
            _require(payload['actor_id'] != record['author_record']['payload']['actor_id'], 'SELF_APPROVAL')
            _basis(record['policy'], record['obligations'], now)
            record['approver_record'] = copy.deepcopy(envelope)
        record['state'] = {'submit': 'review', 'approve': 'approved', 'retire': 'retired', 'revoke': 'revoked'}[action]
    states[identity]['last_created_at'] = payload['created_at']
    states[identity]['last_received_at'] = now
    seen.add(payload['event_id'])
    return identity


def _write_new(path, value):
    path = security.safe_path(path)
    encoded = security.canonical(value)
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        os.unlink(temporary)


class PolicyRegistry:
    """Immutable version events, serialized by a local advisory file lock.

    This local hash chain detects modification and missing interior records.
    An external sequence floor is required to detect complete storage rollback.
    """
    @classmethod
    @_guard
    def create(cls, root, tenant_id, project_id, trust):
        security.identifier(tenant_id)
        security.identifier(project_id)
        _require(trust.get('context') == CONTEXT, 'TRUST_INVALID')
        root = security.safe_path(root)
        root.mkdir(mode=0o700, exist_ok=False)
        (root / 'events').mkdir(mode=0o700)
        _write_new(root / 'registry.json', {'format': 'govcode-registry-v1', 'context': CONTEXT, 'tenant_id': tenant_id, 'project_id': project_id, 'operational_approval': False})
        fd = os.open(root / '.lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        return cls(root, trust)

    @_guard
    def __init__(self, root, trust):
        self.root = security.safe_path(root)
        self.trust = json.loads(security.canonical(trust))
        metadata = security.read_json(self.root / 'registry.json')
        _require(set(metadata) == {'format', 'context', 'tenant_id', 'project_id', 'operational_approval'} and metadata['format'] == 'govcode-registry-v1' and metadata['context'] == CONTEXT and metadata['operational_approval'] is False, 'REGISTRY_INVALID')
        self.tenant_id, self.project_id = metadata['tenant_id'], metadata['project_id']
        security.identifier(self.tenant_id)
        security.identifier(self.project_id)
        self._anchor = digest(metadata)
        with self._locked(): self._load()

    @contextmanager
    def _locked(self):
        import fcntl
        path = security.safe_path(self.root / '.lock')
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            _require(stat.S_ISREG(os.fstat(fd).st_mode), 'PATH_UNSAFE')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self):
        states, seen, previous, count = {}, set(), self._anchor, 0
        directory = security.safe_path(self.root / 'events')
        files = sorted(directory.iterdir())
        _require(len(files) <= 10000, 'REGISTRY_LIMIT')
        for path in files:
            if path.name.startswith('.pending-'):
                _require(path.is_file() and not path.is_symlink(), 'REGISTRY_INVALID')
                continue
            count += 1
            _require(path.name == f'{count:08d}.json', 'EVENT_CHAIN_INVALID')
            event = security.read_json(path)
            _require(set(event) == {'index', 'previous_digest', 'signed_action', 'received_at', 'record_digest'}, 'EVENT_CHAIN_INVALID')
            body = {key: value for key, value in event.items() if key != 'record_digest'}
            _require(event['index'] == count and event['previous_digest'] == previous and event['record_digest'] == digest(body), 'EVENT_CHAIN_INVALID')
            _transition(states, seen, event['signed_action'], self.trust, self.tenant_id, self.project_id, event['received_at'])
            previous = event['record_digest']
        self._states, self._seen, self._previous, self._count = states, seen, previous, count

    @_guard
    def apply(self, signed_action, now):
        with self._locked():
            self._load()
            states, seen = copy.deepcopy(self._states), set(self._seen)
            identity = _transition(states, seen, signed_action, self.trust, self.tenant_id, self.project_id, now)
            event = {'index': self._count + 1, 'previous_digest': self._previous, 'signed_action': signed_action, 'received_at': now}
            event['record_digest'] = digest(event)
            _write_new(self.root / 'events' / f'{self._count + 1:08d}.json', event)
            record = states[identity]
            return {'policy_id': identity[0], 'version': identity[1], 'policy_digest': record['policy_digest'], 'state': record['state'], 'record_digest': event['record_digest'], 'context': CONTEXT, 'operational_approval': False}

    @_guard
    def issue_bundle(self, policy_refs, private_path, key_id, not_before, expires_at, sequence):
        _require(type(sequence) is int and sequence > 0, 'SEQUENCE_INVALID')
        _require(_time(not_before) < _time(expires_at), 'BUNDLE_WINDOW_INVALID')
        _require(type(policy_refs) is list and bool(policy_refs), 'POLICIES_REQUIRED')
        with self._locked():
            self._load()
            selected, identities = [], set()
            for ref in policy_refs:
                _require(set(ref) == {'id', 'version'}, 'POLICY_REFERENCE_INVALID')
                identity = (ref['id'], ref['version'])
                _require(identity not in identities, 'POLICY_DUPLICATE')
                identities.add(identity)
                _require(identity in self._states, 'POLICY_UNKNOWN')
                record = self._states[identity]
                _require(record['state'] == 'approved', 'POLICY_NOT_APPROVED')
                _basis(record['policy'], record['obligations'], not_before, expires_at)
                selected.append({key: copy.deepcopy(record[key]) for key in ('policy', 'policy_digest', 'obligations', 'author_record', 'submit_record', 'approver_record')})
            actor = self.trust['keys'][key_id]['actor_id']
            payload = {'kind': 'policy_bundle', 'context': CONTEXT, 'tenant_id': self.tenant_id, 'project_id': self.project_id, 'actor_id': actor, 'sequence': sequence, 'not_before': not_before, 'expires_at': expires_at, 'operational_approval': False, 'policies': selected}
            bundle = security.sign(payload, private_path, key_id)
            validate_bundle(bundle, self.trust, self.tenant_id, self.project_id, not_before)
            return bundle


def _validated_revocations(revocations, trust, tenant_id, project_id, now):
    if revocations is None:
        return {'epoch': 0, 'bundle_digests': [], 'key_ids': [], 'policy_digests': [], 'record_digests': []}
    rev = security.verify(revocations, trust, 'operator', tenant_id, project_id)
    fields = {'kind', 'context', 'tenant_id', 'project_id', 'actor_id', 'event_id', 'created_at', 'epoch', 'bundle_digests', 'key_ids', 'policy_digests'}
    _require(set(rev) in (fields, fields | {'record_digests'}) and rev['kind'] == 'policy_revocations', 'REVOCATIONS_INVALID')
    rev.setdefault('record_digests', [])
    _common(rev, now)
    _require(type(rev['epoch']) is int and rev['epoch'] >= 0, 'REVOCATIONS_INVALID')
    for field in ('bundle_digests', 'key_ids', 'policy_digests', 'record_digests'):
        _require(type(rev[field]) is list and len(set(rev[field])) == len(rev[field]), 'REVOCATIONS_INVALID')
    for item in rev['bundle_digests'] + rev['policy_digests'] + rev['record_digests']: _hash(item)
    for item in rev['key_ids']: security.identifier(item)
    return rev


@_guard
def validate_bundle(bundle, trust, tenant_id, project_id, now, *, min_sequence=0, revocations=None):
    payload = security.verify(bundle, trust, 'operator', tenant_id, project_id)
    _require(set(payload) == {'kind', 'context', 'tenant_id', 'project_id', 'actor_id', 'sequence', 'not_before', 'expires_at', 'operational_approval', 'policies'}, 'BUNDLE_INVALID')
    _require(payload['kind'] == 'policy_bundle' and payload['operational_approval'] is False, 'BUNDLE_INVALID')
    _require(type(min_sequence) is int and min_sequence >= 0 and type(payload['sequence']) is int and payload['sequence'] > 0 and payload['sequence'] >= min_sequence, 'BUNDLE_ROLLBACK')
    _require(_time(payload['not_before']) <= _time(now) < _time(payload['expires_at']), 'BUNDLE_EXPIRED_OR_NOT_YET_VALID')
    _require(type(payload['policies']) is list and bool(payload['policies']), 'POLICIES_REQUIRED')
    rev = _validated_revocations(revocations, trust, tenant_id, project_id, now)
    _require(payload['sequence'] >= rev['epoch'], 'BUNDLE_ROLLBACK')
    revoked_keys, revoked_policies, revoked_bundles, revoked_records = set(rev['key_ids']), set(rev['policy_digests']), set(rev['bundle_digests']), set(rev['record_digests'])
    bundle_digest = digest(payload)
    _require(bundle_digest not in revoked_bundles and bundle['key_id'] not in revoked_keys, 'BUNDLE_REVOKED')
    identities, nonces, approved = set(), set(), []
    for entry in payload['policies']:
        _require(set(entry) == {'policy', 'policy_digest', 'obligations', 'author_record', 'submit_record', 'approver_record'}, 'BUNDLE_POLICY_INVALID')
        states, seen = {}, set()
        for field in ('author_record', 'submit_record', 'approver_record'):
            envelope = entry[field]
            _require(envelope['key_id'] not in revoked_keys, 'SIGNER_REVOKED')
            _require(digest(envelope) not in revoked_records, 'RECORD_REVOKED')
            _transition(states, seen, envelope, trust, tenant_id, project_id, now)
        _require(len(states) == 1, 'BUNDLE_POLICY_INVALID')
        identity, record = next(iter(states.items()))
        _require(record['state'] == 'approved' and identity not in identities, 'POLICY_NOT_APPROVED')
        _require(not nonces.intersection(seen), 'EVENT_REPLAY')
        nonces.update(seen)
        identities.add(identity)
        _require(record['policy'] == entry['policy'] and record['policy_digest'] == entry['policy_digest'] and record['obligations'] == entry['obligations'], 'POLICY_DIGEST_MISMATCH')
        _require(record['policy_digest'] not in revoked_policies, 'POLICY_REVOKED')
        _basis(record['policy'], record['obligations'], payload['not_before'], payload['expires_at'])
        approved.append(copy.deepcopy(entry))
    return {'bundle_digest': bundle_digest, 'sequence': payload['sequence'], 'policies': approved, 'tenant_id': tenant_id, 'project_id': project_id, 'context': CONTEXT, 'operational_approval': False, 'not_before': payload['not_before'], 'expires_at': payload['expires_at']}


def _commit(value):
    _require(type(value) is str and re.fullmatch(r'[a-f0-9]{40}', value) is not None, 'COMMIT_INVALID')


def _finding_map(value):
    _require(type(value) is dict, 'EXCEPTION_FINDINGS_INVALID')
    security.canonical(value)
    for finding_id, finding_hash in value.items():
        security.identifier(finding_id)
        _hash(finding_hash)
    return value


@_guard
def finding_digest(run, finding, policy):
    """Bind finding semantics to caller-verified source, tool, scope and policy.

    Callers must supply freshly recomputed or admin-registered verified records.
    Unsigned display IDs are deliberately excluded from this identity.
    """
    tenant_id, project_id = policy['scope']['tenant_id'], policy['scope']['project_id']
    _scope(policy, tenant_id, project_id)
    _require(type(run) is dict and type(finding) is dict, 'FINDING_CONTEXT_INVALID')
    security.canonical(run)
    security.canonical(finding)
    _commit(run['commit_sha'])
    _hash(run['tool_digest'])
    _require(run['tenant_id'] == tenant_id and run['project_id'] == project_id, 'SCOPE_MISMATCH')
    _require(finding.get('kind', 'finding') == 'finding' and finding.get('coverage', 'supported') == 'supported', 'FINDING_CONTEXT_INVALID')
    for field in ('detector_id', 'detector_version', 'category'):
        _require(type(finding[field]) is str and 0 < len(finding[field]) <= 128, 'FINDING_CONTEXT_INVALID')
    _require(finding['severity'] in ('low', 'medium', 'high', 'critical'), 'FINDING_CONTEXT_INVALID')
    location = finding['location']
    _require(type(location) is dict and set(location) == {'path', 'line'}, 'FINDING_CONTEXT_INVALID')
    path = location['path']
    _require(type(path) is str and bool(path) and not path.startswith('/') and '\\' not in path and all(part not in ('', '.', '..') for part in path.split('/')), 'FINDING_CONTEXT_INVALID')
    _require(type(location['line']) is int and location['line'] > 0, 'FINDING_CONTEXT_INVALID')
    classes = finding['data_classes']
    _require(type(classes) is list and bool(classes) and all(type(item) is str and 0 < len(item) <= 128 for item in classes) and len(set(classes)) == len(classes), 'FINDING_CONTEXT_INVALID')
    semantics = {field: finding[field] for field in ('detector_id', 'detector_version', 'category', 'severity', 'location')}
    semantics['data_classes'] = sorted(classes)
    if 'rule_id' in finding:
        security.identifier(finding['rule_id'])
        semantics['rule_id'] = finding['rule_id']
    return digest({'format': 'govcode-finding-binding-v1', 'context': CONTEXT, 'tenant_id': tenant_id, 'project_id': project_id, 'commit_sha': run['commit_sha'], 'tool_digest': run['tool_digest'], 'policy_digest': digest(policy), 'finding': semantics})


@_guard
def validate_exception(approval, trust, policy, current_finding_ids, now, *, revocations=None, commit_sha=None, tool_digest=None, finding_digests=None):
    """Validate independent approval against mandatory fresh source bindings."""
    tenant_id, project_id = policy['scope']['tenant_id'], policy['scope']['project_id']
    _scope(policy, tenant_id, project_id)
    _require(policy['basis_kind'] == 'example_policy', 'STATUTORY_EXCEPTION_FORBIDDEN')
    _require(commit_sha is not None and tool_digest is not None and finding_digests is not None, 'EXCEPTION_CONTEXT_REQUIRED')
    _commit(commit_sha)
    _hash(tool_digest)
    current_map = _finding_map(finding_digests)
    _require(type(current_finding_ids) in (list, set, tuple) and len(set(current_finding_ids)) == len(current_finding_ids), 'EXCEPTION_FINDINGS_INVALID')
    _require(set(current_map) == set(current_finding_ids), 'EXCEPTION_SCOPE_MISMATCH')
    rev = _validated_revocations(revocations, trust, tenant_id, project_id, now)
    _require(digest(policy) not in rev['policy_digests'], 'POLICY_REVOKED')
    _require(approval['key_id'] not in rev['key_ids'], 'SIGNER_REVOKED')
    _require(digest(approval) not in rev['record_digests'], 'RECORD_REVOKED')
    approved = security.verify(approval, trust, 'approver', tenant_id, project_id)
    _require(set(approved) == {'kind', 'context', 'tenant_id', 'project_id', 'actor_id', 'event_id', 'created_at', 'request'} and approved['kind'] == 'exception_approval', 'EXCEPTION_INVALID')
    _common(approved, now)
    request_envelope = approved['request']
    _require(request_envelope['key_id'] not in rev['key_ids'], 'SIGNER_REVOKED')
    _require(digest(request_envelope) not in rev['record_digests'], 'RECORD_REVOKED')
    request = security.verify(request_envelope, trust, 'author', tenant_id, project_id)
    fields = {'kind', 'context', 'tenant_id', 'project_id', 'actor_id', 'event_id', 'created_at', 'policy_id', 'version', 'policy_digest', 'finding_ids', 'compensating_control', 'expires_at', 'commit_sha', 'tool_digest', 'finding_digests'}
    _require(set(request) in (fields, fields | {'run_id'}) and request['kind'] == 'exception_request', 'EXCEPTION_INVALID')
    if 'run_id' in request: security.identifier(request['run_id'])
    _common(request, now)
    _require(request['actor_id'] != approved['actor_id'], 'SELF_APPROVAL')
    _require(request['event_id'] != approved['event_id'] and _time(request['created_at']) <= _time(approved['created_at']), 'EXCEPTION_INVALID')
    _require(request['policy_id'] == policy['id'] and request['version'] == policy['version'] and request['policy_digest'] == digest(policy), 'EXCEPTION_POLICY_MISMATCH')
    _require(_time(now) < _time(request['expires_at']), 'EXCEPTION_EXPIRED')
    _require(type(request['compensating_control']) is str and bool(request['compensating_control'].strip()) and len(request['compensating_control']) <= 4096, 'COMPENSATING_CONTROL_REQUIRED')
    findings = request['finding_ids']
    _require(type(findings) is list and bool(findings) and len(set(findings)) == len(findings), 'EXCEPTION_FINDINGS_INVALID')
    for finding in findings: security.identifier(finding)
    _commit(request['commit_sha'])
    _hash(request['tool_digest'])
    requested_map = _finding_map(request['finding_digests'])
    _require(set(requested_map) == set(findings) and set(findings) <= set(current_map), 'EXCEPTION_SCOPE_MISMATCH')
    _require(request['commit_sha'] == commit_sha and request['tool_digest'] == tool_digest, 'EXCEPTION_SOURCE_MISMATCH')
    _require(all(requested_map[finding] == current_map[finding] for finding in findings), 'EXCEPTION_FINDING_MISMATCH')
    return sorted(findings)
