"""Immutable, signed project profile revisions for a local synthetic reference.

An approved profile may still contain unknown facts. It is not an applicability
decision or project gate. Callers own trust freshness and durable checkpoints.
"""
from contextlib import contextmanager
import functools
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from . import security
from . import project_contracts as contracts

MAX_EVENTS = 1000
MAX_HISTORY_BYTES = 16_000_000


class ProfileError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code='PROFILE_REGISTRY_INVALID'):
    if not condition:
        raise ProfileError(code)


def _guard(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ProfileError:
            raise
        except (security.SecurityError, contracts.ContractError) as error:
            raise ProfileError(error.code) from None
        except Exception:
            raise ProfileError('PROFILE_REGISTRY_INVALID') from None
    return guarded


def _clone(value):
    return json.loads(security.canonical(value))


def _write_new(path, value):
    path = security.safe_path(path)
    data = security.canonical(value)
    fd, temp = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temp)


@_guard
def read_fact(profile, name):
    """Return an explicit state; missing, false and not-applicable never coerce."""
    value = contracts.validate(profile)
    _require(value['kind'] == 'project_profile', 'PROFILE_KIND_INVALID')
    security.identifier(name)
    return _clone(value['facts'].get(name, {'state': 'missing'}))


@_guard
def information_gaps(profile, required_facts=()):
    """Information/review hints, not completed WorkItems or requirement exclusions."""
    value = contracts.validate(profile)
    _require(value['kind'] == 'project_profile', 'PROFILE_KIND_INVALID')
    if not isinstance(required_facts, (list, tuple)) or len(required_facts) > 256:
        raise ProfileError('FACT_LIST_INVALID')
    for name in required_facts:
        security.identifier(name)
    gaps = []
    for name in sorted(set(value['facts']) | set(required_facts)):
        fact = value['facts'].get(name, {'state': 'missing'})
        if fact['state'] != 'known':
            gaps.append({'fact': name, 'state': fact['state'],
                'owner_ref': fact.get('owner_ref', value['owner_ref']),
                'reason_ref': fact.get('reason_ref', 'FACT_NOT_PROVIDED'),
                'action': {'unknown': 'confirm_fact', 'missing': 'provide_fact',
                           'not_applicable': 'review_applicability'}[fact['state']]})
    return gaps


class ProjectProfileRegistry:
    """Append-only events under a local advisory lock; no implicit approval fallback."""

    @classmethod
    @_guard
    def create(cls, root, tenant_id, project_id, trust):
        root = security.safe_path(root)
        security.identifier(tenant_id)
        security.identifier(project_id)
        _require(trust.get('context') == security.CONTEXT, 'TRUST_INVALID')
        _require(not root.exists(), 'PROFILE_STORE_EXISTS')
        root.mkdir(mode=0o700)
        (root / 'events').mkdir(mode=0o700)
        fd = os.open(root / '.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        metadata = dict(format='govcode-project-profiles-v1', context=security.CONTEXT,
            tenant_id=tenant_id, project_id=project_id, registry_id=uuid.uuid4().hex,
            operational_approval=False)
        _write_new(root / 'registry.json', metadata)
        return cls(root, trust)

    @_guard
    def __init__(self, root, trust, *, checkpoint=None):
        self.root = security.safe_path(root)
        _require(self.root.is_dir(), 'PROFILE_STORE_MISSING')
        _require(security.safe_path(self.root / 'events').is_dir(), 'PROFILE_STORE_MISSING')
        self.trust = _clone(trust)
        _require(self.trust.get('context') == security.CONTEXT, 'TRUST_INVALID')
        self.metadata = security.read_json(self.root / 'registry.json')
        m = self.metadata
        _require(set(m) == {'format', 'context', 'tenant_id', 'project_id', 'registry_id', 'operational_approval'})
        _require(m['format'] == 'govcode-project-profiles-v1' and m['context'] == security.CONTEXT
                 and m['operational_approval'] is False)
        for key in ('tenant_id', 'project_id', 'registry_id'):
            security.identifier(m[key])
        self.tenant_id, self.project_id = m['tenant_id'], m['project_id']
        self._anchor = _clone(checkpoint) if checkpoint is not None else None
        if self._anchor is not None:
            a = self._anchor
            _require(set(a) == {'sequence', 'head_digest', 'tenant_id', 'project_id', 'registry_id'}, 'CHECKPOINT_INVALID')
            _require(type(a['sequence']) is int and 0 <= a['sequence'] <= MAX_EVENTS, 'CHECKPOINT_INVALID')
            _require(type(a['head_digest']) is str and re.fullmatch(r'[a-f0-9]{64}', a['head_digest']) is not None, 'CHECKPOINT_INVALID')
            _require(all(a[k] == m[k] for k in ('tenant_id', 'project_id', 'registry_id')), 'CHECKPOINT_SCOPE_MISMATCH')
        with self._locked():
            self._read()

    @contextmanager
    def _locked(self):
        try:
            import fcntl
        except ImportError:
            raise ProfileError('PROFILE_LOCK_UNAVAILABLE') from None
        path = security.safe_path(self.root / '.lock')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'PATH_UNSAFE')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _signed(self, envelope, received_at):
        raw = envelope.get('payload', {})
        action = raw.get('action') if raw.get('kind') == 'profile_action' else raw.get('decision')
        role = {'revise': 'author', 'submit': 'author', 'approve': 'approver',
                'reject': 'approver', 'retire': 'operator', 'revoke': 'operator'}.get(action)
        _require(role is not None, 'PROFILE_ACTION_INVALID')
        value = contracts.validate(security.verify(envelope, self.trust, role, self.tenant_id, self.project_id))
        _require(value['kind'] == ('profile_approval' if action in ('approve', 'reject') else 'profile_action'), 'PROFILE_PROTOCOL_INVALID')
        _require(contracts.timestamp(value['created_at']) <= contracts.timestamp(received_at), 'EVENT_IN_FUTURE')
        return action, value

    def _transition(self, records, latest, seen, envelope, received_at, previous_created):
        action, value = self._signed(envelope, received_at)
        _require(value['event_id'] not in seen, 'EVENT_REPLAY')
        if previous_created is not None:
            _require(contracts.timestamp(value['created_at']) >= contracts.timestamp(previous_created), 'EVENT_TIME_ORDER')
        if action == 'revise':
            profile = value['profile']
            identity = profile['id'], profile['revision']
            head = latest.get(profile['id'], 0)
            _require(value['expected_revision'] == head, 'REVISION_CONFLICT')
            _require(profile['revision'] == head + 1, 'PROFILE_REVISION_INVALID')
            if head:
                parent = records[(profile['id'], head)]
                _require(profile['parent_digest'] == parent['profile_digest'], 'PROFILE_PARENT_MISMATCH')
                _require(value['actor_id'] == parent['author_id'], 'AUTHOR_MISMATCH')
            records[identity] = dict(profile=_clone(profile), profile_digest=contracts.digest(profile),
                author_id=value['actor_id'], state='draft', approval_record=None)
            latest[profile['id']] = profile['revision']
        else:
            identity = value['profile_id'], value['revision']
            head = latest.get(value['profile_id'], 0)
            _require(value['expected_revision'] == head, 'REVISION_CONFLICT')
            _require(identity in records, 'PROFILE_UNKNOWN')
            record = records[identity]
            _require(value['profile_digest'] == record['profile_digest'], 'PROFILE_DIGEST_MISMATCH')
            if action in ('submit', 'approve', 'reject'):
                _require(value['revision'] == head, 'PROFILE_REVISION_SUPERSEDED')
            allowed = {'submit': {'draft'}, 'approve': {'review'}, 'reject': {'review'},
                       'retire': {'approved'}, 'revoke': {'draft', 'review', 'approved', 'rejected', 'retired'}}
            _require(record['state'] in allowed[action], 'PROFILE_TRANSITION_INVALID')
            if action == 'submit':
                _require(value['actor_id'] == record['author_id'], 'AUTHOR_MISMATCH')
            if action in ('approve', 'reject'):
                _require(value['actor_id'] != record['author_id'], 'SELF_APPROVAL')
            if action == 'approve':
                _require(contracts.timestamp(value['not_before']) <= contracts.timestamp(received_at)
                         < contracts.timestamp(value['expires_at']), 'PROFILE_APPROVAL_EXPIRED')
                record['approval_record'] = _clone(envelope)
            record['state'] = {'submit': 'review', 'approve': 'approved', 'reject': 'rejected',
                               'retire': 'retired', 'revoke': 'revoked'}[action]
        records[identity]['last_created_at'] = value['created_at']
        records[identity]['last_received_at'] = received_at
        seen.add(value['event_id'])
        return identity, value['created_at']

    def _read(self):
        _require(security.read_json(self.root / 'registry.json') == self.metadata, 'PROFILE_METADATA_CHANGED')
        files = sorted(security.safe_path(self.root / 'events').iterdir())
        _require(len(files) <= MAX_EVENTS, 'PROFILE_HISTORY_LIMIT')
        records, latest, seen = {}, {}, set()
        head = contracts.digest(self.metadata)
        heads = [head]
        total, last_received, last_created = 0, None, None
        for number, path in enumerate(files, 1):
            _require(path.name == f'{number:08}.json', 'PROFILE_HISTORY_INVALID')
            event = security.read_json(path)
            total += len(security.canonical(event))
            _require(total <= MAX_HISTORY_BYTES, 'PROFILE_HISTORY_LIMIT')
            _require(set(event) == {'sequence', 'previous_digest', 'received_at', 'signed_action', 'event_digest'})
            _require(type(event['sequence']) is int and event['sequence'] == number and event['previous_digest'] == head, 'PROFILE_HASH_CHAIN_INVALID')
            body = {key: event[key] for key in event if key != 'event_digest'}
            _require(event['event_digest'] == contracts.digest(body), 'PROFILE_HASH_CHAIN_INVALID')
            if last_received is not None:
                _require(contracts.timestamp(event['received_at']) >= contracts.timestamp(last_received), 'EVENT_TIME_ORDER')
            _, last_created = self._transition(records, latest, seen, event['signed_action'], event['received_at'], last_created)
            head, last_received = event['event_digest'], event['received_at']
            heads.append(head)
        if self._anchor is not None:
            a = self._anchor
            _require(len(files) >= a['sequence'] and heads[a['sequence']] == a['head_digest'], 'PROFILE_ROLLBACK')
        self._history_bytes = total
        return records, latest, seen, head, last_received, last_created

    def _view(self, record):
        result = _clone(record)
        result.update(context=security.CONTEXT, operational_approval=False,
                      requirements_evaluated=False, information_gaps=information_gaps(record['profile']))
        return result

    @_guard
    def apply(self, signed_action, now):
        envelope = _clone(signed_action)
        contracts.timestamp(now)
        with self._locked():
            records, latest, seen, head, last_received, last_created = self._read()
            _require(len(seen) < MAX_EVENTS, 'PROFILE_HISTORY_LIMIT')
            if last_received is not None:
                _require(contracts.timestamp(now) >= contracts.timestamp(last_received), 'EVENT_TIME_ORDER')
            identity, _ = self._transition(records, latest, seen, envelope, now, last_created)
            event = dict(sequence=len(seen), previous_digest=head, received_at=now, signed_action=envelope)
            event['event_digest'] = contracts.digest(event)
            _require(self._history_bytes + len(security.canonical(event)) <= MAX_HISTORY_BYTES, 'PROFILE_HISTORY_LIMIT')
            result = self._view(records[identity])
            _write_new(self.root / 'events' / f'{len(seen):08}.json', event)
            return result

    @_guard
    def get(self, profile_id, revision=None):
        security.identifier(profile_id)
        with self._locked():
            records, latest, *_ = self._read()
            target = latest.get(profile_id) if revision is None else revision
            _require(type(target) is int and (profile_id, target) in records, 'PROFILE_UNKNOWN')
            return self._view(records[(profile_id, target)])

    @_guard
    def history(self, profile_id):
        security.identifier(profile_id)
        with self._locked():
            records, *_ = self._read()
            return [self._view(records[key]) for key in sorted(records) if key[0] == profile_id]

    @_guard
    def active(self, profile_id, now, *, min_revision=0, expected_profile_digest=None):
        security.identifier(profile_id)
        _require(type(min_revision) is int and min_revision >= 0, 'REVISION_INVALID')
        current_time = contracts.timestamp(now)
        with self._locked():
            records, _, _, _, last_received, _ = self._read()
            _require(last_received is None or contracts.timestamp(last_received) <= current_time, 'TIME_ROLLBACK')
            approved = [r for (name, _), r in records.items() if name == profile_id and r['approval_record'] is not None]
            _require(bool(approved), 'PROFILE_NOT_APPROVED')
            record = max(approved, key=lambda r: r['profile']['revision'])
            _require(record['state'] == 'approved', 'PROFILE_APPROVAL_INACTIVE')
            payload = record['approval_record']['payload']
            _require(contracts.timestamp(payload['not_before']) <= current_time < contracts.timestamp(payload['expires_at']), 'PROFILE_APPROVAL_EXPIRED')
            _require(record['profile']['revision'] >= min_revision, 'PROFILE_REVISION_ROLLBACK')
            if expected_profile_digest is not None:
                _require(record['profile_digest'] == expected_profile_digest, 'PROFILE_DIGEST_MISMATCH')
            return self._view(record)

    @_guard
    def checkpoint(self):
        with self._locked():
            _, _, seen, head, *_ = self._read()
            return dict(sequence=len(seen), head_digest=head, tenant_id=self.tenant_id,
                        project_id=self.project_id, registry_id=self.metadata['registry_id'])
