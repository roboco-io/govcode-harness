"""Signed, immutable rule packs and profile-bound selection locks.

All authorities remain synthetic_reference. Pack integrity is not execution of
its checks. Offline revocations need caller-pinned epoch/sequence floors.
"""
from contextlib import contextmanager
import functools
import json
import os
import stat
import uuid

from .. import security
from . import contracts as c, profile as profiles

MAX_EVENTS = 1000
MAX_HISTORY_BYTES = 16_000_000
MAX_FEED_SECONDS = 3600  # Reference freshness policy, not a statutory duration.
REVOCATION_FIELDS = ('key_ids', 'pack_digests', 'release_digests', 'approval_digests', 'lock_digests', 'review_digests')


class PackError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code='PACK_INVALID'):
    if not condition:
        raise PackError(code)


def _guard(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PackError:
            raise
        except (c.ContractError, security.SecurityError, profiles.ProfileError) as error:
            raise PackError(error.code) from None
        except Exception:
            raise PackError('PACK_INVALID') from None
    return wrapped


def _clone(value):
    return json.loads(security.canonical(value))


def _positive(value):
    _require(type(value) is int and value >= 1, 'SEQUENCE_INVALID')
    return value


def _window(value, now):
    _require(c.timestamp(value['not_before']) <= c.timestamp(now) < c.timestamp(value['expires_at']), 'VALIDITY_EXPIRED')


def _within(inner, outer):
    _require(c.timestamp(outer['not_before']) <= c.timestamp(inner['not_before'])
             < c.timestamp(inner['expires_at']) <= c.timestamp(outer['expires_at']), 'VALIDITY_SCOPE_INVALID')


def _signed(envelope, trust, role, kind, tenant_id, project_id, now):
    value = c.validate(security.verify(envelope, trust, role, tenant_id, project_id))
    _require(value['kind'] == kind, 'PACK_PROTOCOL_INVALID')
    _require(c.timestamp(value['created_at']) <= c.timestamp(now), 'EVENT_IN_FUTURE')
    return value


def _not_revoked(envelope, revocations, field=None):
    _require(envelope['key_id'] not in revocations['key_ids'], 'KEY_REVOKED')
    if field:
        _require(c.digest(envelope) not in revocations[field], 'RECORD_REVOKED')


@_guard
def validate_pack(manifest, requirements):
    manifest = c.validate(manifest)
    _require(manifest['kind'] == 'rule_pack_manifest', 'PACK_KIND_INVALID')
    _require(type(requirements) is list and 0 < len(requirements) <= 1000, 'REQUIREMENTS_INVALID')
    security.canonical(dict(manifest=manifest, requirements=requirements))
    requirements = [c.validate(x) for x in requirements]
    scope = manifest['tenant_id'], manifest['project_id']
    _require(all(x['kind'] == 'requirement_spec' and (x['tenant_id'], x['project_id']) == scope for x in requirements), 'SCOPE_MISMATCH')
    _require(len({x['id'] for x in requirements}) == len(requirements), 'REQUIREMENT_CONFLICT')
    actual = {(x['id'], x['version']): x for x in requirements}
    _require(set(actual) == {(x['id'], x['version']) for x in manifest['requirement_refs']}, 'REQUIREMENT_REFERENCE_MISMATCH')
    sources = {(x['id'], x['version']): x for x in manifest['source_refs']}
    checks = {x['id'] for x in manifest['check_specs']}
    for ref in manifest['requirement_refs']:
        requirement = actual[(ref['id'], ref['version'])]
        _require(ref['digest'] == c.digest(requirement), 'REFERENCE_DIGEST_MISMATCH')
        source = requirement['source_ref']
        _require(sources.get((source['id'], source['version'])) == source, 'SOURCE_REFERENCE_MISMATCH')
        _require(set(requirement['check_refs']) <= checks, 'CHECK_REFERENCE_MISSING')
    return dict(manifest=manifest, requirements=sorted(requirements, key=lambda x: (x['id'], x['version'])))


def pack_digest(manifest, requirements):
    return c.digest(validate_pack(manifest, requirements))


def _ready(content, now):
    _window(content['manifest'], now)
    for req in content['requirements']:
        _require(req['source_verification'] == 'confirmed' and req['normativity'] != 'undetermined'
                 and req['basis_kind'] != 'unverified_requirement', 'PACK_SOURCE_UNVERIFIED')


@_guard
def dependency_order(manifests):
    _require(type(manifests) is list and 0 < len(manifests) <= 64, 'PACK_LIMIT')
    values = [c.validate(x) for x in manifests]
    _require(all(x['kind'] == 'rule_pack_manifest' for x in values), 'PACK_KIND_INVALID')
    _require(len({x['pack_id'] for x in values}) == len(values), 'PACK_VERSION_CONFLICT')
    scope = values[0]['tenant_id'], values[0]['project_id']
    _require(all((x['tenant_id'], x['project_id']) == scope for x in values), 'SCOPE_MISMATCH')
    index = {(x['pack_id'], x['version']): x for x in values}
    visiting, finished, order = set(), set(), []
    def visit(key):
        _require(key in index, 'DEPENDENCY_MISSING')
        _require(key not in visiting, 'DEPENDENCY_CYCLE')
        if key in finished:
            return
        visiting.add(key)
        for ref in index[key]['dependencies']:
            visit((ref['id'], ref['version']))
        visiting.remove(key)
        finished.add(key)
        order.append(key)
    for key in sorted(index):
        visit(key)
    for value in values:
        for ref in value['dependencies']:
            _require(ref['digest'] == c.digest(index[(ref['id'], ref['version'])]), 'DEPENDENCY_DIGEST_MISMATCH')
    return order


@_guard
def verify_revocations(envelope, trust, tenant_id, project_id, now, *, min_epoch=1, expected_digest=None):
    _positive(min_epoch)
    _require(envelope is not None, 'REVOCATIONS_REQUIRED')
    envelope, trust = _clone(envelope), _clone(trust)
    _require(type(expected_digest) is str and len(expected_digest)==64,'REVOCATIONS_ANCHOR_REQUIRED')
    _require(c.digest(envelope)==expected_digest,'REVOCATIONS_DIGEST_MISMATCH')
    value = _signed(envelope, trust, 'operator', 'rule_pack_revocations', tenant_id, project_id, now)
    _window(value, now)
    _require((c.timestamp(value['expires_at']) - c.timestamp(value['not_before'])).total_seconds() <= MAX_FEED_SECONDS, 'REVOCATIONS_WINDOW_TOO_LONG')
    _require(value['epoch'] >= min_epoch, 'REVOCATIONS_ROLLBACK')
    _not_revoked(envelope, value)
    return value


def _release(envelope, trust, tenant_id, project_id, now, revoked, min_sequence=1):
    _positive(min_sequence)
    _not_revoked(envelope, revoked, 'release_digests')
    value = _signed(envelope, trust, 'operator', 'rule_pack_release', tenant_id, project_id, now)
    _window(value, now)
    _require(value['sequence'] >= min_sequence, 'PACK_SEQUENCE_ROLLBACK')
    author, submit, approval = value['author_record'], value['submit_record'], value['approval_record']
    records = []
    for record, role, action in [(author,'author','draft'),(submit,'author','submit'),(approval,'approver','approve')]:
        _not_revoked(record, revoked, 'approval_digests' if action == 'approve' else None)
        payload = _signed(record, trust, role, 'rule_pack_action', tenant_id, project_id, now)
        _require(payload['action'] == action, 'PACK_PROTOCOL_INVALID')
        records.append(payload)
    a, s, review = records
    _require(a['actor_id'] == s['actor_id'] and a['actor_id'] != review['actor_id'], 'SELF_APPROVAL')
    _require(len({r['event_id'] for r in [a,s,review,value]}) == 4, 'EVENT_REPLAY')
    _require(a['expected_sequence'] < s['expected_sequence'] < review['expected_sequence'] < value['expected_sequence'], 'PACK_PROOF_ORDER')
    _require(c.timestamp(a['created_at']) <= c.timestamp(s['created_at']) <= c.timestamp(review['created_at']) <= c.timestamp(value['created_at']), 'EVENT_TIME_ORDER')
    content = validate_pack(a['manifest'], a['requirements'])
    manifest = content['manifest']
    digest = c.digest(content)
    _require(digest == value['pack_digest'] and digest not in revoked['pack_digests'], 'PACK_REVOKED_OR_CHANGED')
    _require(all((r['pack_id'],r['version'],r['pack_digest']) == (manifest['pack_id'],manifest['version'],digest) for r in records), 'PACK_SUBJECT_MISMATCH')
    ref = dict(kind='rule_pack_manifest',id=manifest['pack_id'],version=manifest['version'],digest=c.digest(manifest))
    _require(value['pack_ref'] == ref, 'PACK_SUBJECT_MISMATCH')
    _ready(content, now)
    _window(review, now)
    _within(value, manifest)
    _within(value, review)
    return dict(kind='rule_pack_verification', **content, pack_ref=ref, pack_digest=digest,
                sequence=value['sequence'], author_id=a['actor_id'], approver_id=review['actor_id'],
                release_digest=c.digest(envelope), dependencies_checked=False, operational_approval=False)


@_guard
def verify_release(envelope, trust, tenant_id, project_id, now, *, revocations,
                   min_sequence=1, min_revocation_epoch=1, expected_revocation_digest=None):
    envelope, trust = _clone(envelope), _clone(trust)
    revoked = verify_revocations(revocations,trust,tenant_id,project_id,now,min_epoch=min_revocation_epoch,expected_digest=expected_revocation_digest)
    return _release(envelope,trust,tenant_id,project_id,now,revoked,min_sequence)


def _lock(envelope, trust, tenant_id, project_id, now, revoked, min_sequence=1, min_pack_sequences=None):
    _positive(min_sequence)
    _not_revoked(envelope,revoked,'lock_digests')
    value = _signed(envelope,trust,'operator','project_pack_lock_release',tenant_id,project_id,now)
    lock = c.validate(value['lock'])
    _require(lock['kind'] == 'project_pack_lock' and (lock['tenant_id'],lock['project_id']) == (tenant_id,project_id),'SCOPE_MISMATCH')
    _window(lock,now)
    _require(lock['sequence'] >= min_sequence,'LOCK_SEQUENCE_ROLLBACK')
    _require(not lock['policy_bundle_refs'],'LEGACY_POLICY_BUNDLE_UNSUPPORTED')
    selection, review = value['selection_record'], value['review_record']
    _not_revoked(selection,revoked)
    _not_revoked(review,revoked,'review_digests')
    request = _signed(selection,trust,'author','pack_selection_request',tenant_id,project_id,now)
    approved = _signed(review,trust,'approver','pack_selection_review',tenant_id,project_id,now)
    _require(request['lock'] == lock and approved['request_digest'] == c.digest(selection),'SELECTION_CHANGED')
    _require(approved['decision'] == 'approve','SELECTION_UNAPPROVED')
    _require(request['actor_id'] != approved['actor_id'],'SELF_APPROVAL')
    _require(lock['selection_review_ref'] == approved['event_id'],'SELECTION_REVIEW_MISMATCH')
    _require(c.timestamp(request['created_at']) <= c.timestamp(approved['created_at']) <= c.timestamp(value['created_at']),'EVENT_TIME_ORDER')
    _window(approved,now)
    _within(lock,approved)
    floors = {} if min_pack_sequences is None else _clone(min_pack_sequences)
    _require(type(floors) is dict and len(floors) <= 64,'SEQUENCE_INVALID')
    for key, floor in floors.items():
        security.identifier(key)
        _positive(floor)
    _require(0 < len(value['pack_releases']) <= 64,'PACK_LIMIT')
    releases = [_release(r,trust,tenant_id,project_id,now,revoked,
                         floors.get(r.get('payload',{}).get('pack_ref',{}).get('id'),1)) for r in value['pack_releases']]
    refs = [r['pack_ref'] for r in releases]
    key = lambda r: (r['id'],r['version'],r['digest'])
    _require(sorted(refs,key=key) == sorted(lock['pack_refs'],key=key),'LOCK_PACK_MISMATCH')
    order = dependency_order([r['manifest'] for r in releases])
    requirements, origins, pack_authors = {}, {}, set()
    for release in releases:
        pack_authors.add(release['author_id'])
        for requirement in release['requirements']:
            name = requirement['id']
            _require(name not in requirements or requirements[name] == requirement,'REQUIREMENT_CONFLICT')
            requirements[name] = requirement
            origins.setdefault(name,[]).append(release['pack_digest'])
    return dict(lock=lock, lock_digest=c.digest(envelope), requirements=[requirements[k] for k in sorted(requirements)],
                origins=origins, pack_authors=sorted(pack_authors), selection_author_id=request['actor_id'],
                dependency_order=order, profile_digest=lock['profile_digest'], operational_approval=False)


def _profile(lock, profile_registry, trust, revoked, now, min_revision=1):
    _positive(min_revision)
    _require(isinstance(profile_registry,profiles.ProjectProfileRegistry),'PROFILE_AUTHORITY_REQUIRED')
    _require((profile_registry.tenant_id,profile_registry.project_id) == (lock['tenant_id'],lock['project_id']),'SCOPE_MISMATCH')
    live_trust = _clone(trust)
    for key in revoked['key_ids']:
        if key in live_trust['keys']:
            live_trust['keys'][key]['revoked'] = True
    current = profiles.ProjectProfileRegistry(profile_registry.root,live_trust,checkpoint=profile_registry.checkpoint())
    active = current.active(lock['profile_ref']['id'],now,min_revision=min_revision,expected_profile_digest=lock['profile_digest'])
    profile = active['profile']
    expected = dict(kind='project_profile',id=profile['id'],version=str(profile['revision']),digest=c.digest(profile))
    _require(lock['profile_ref'] == expected,'PROFILE_CHANGED')
    _require(c.digest(active['approval_record']) not in revoked['approval_digests'],'PROFILE_APPROVAL_REVOKED')
    _within(lock,active['approval_record']['payload'])
    return active


@_guard
def verify_lock(envelope, trust, tenant_id, project_id, now, *, revocations, profile_registry,
                min_sequence=1, min_revocation_epoch=1, min_pack_sequences=None, min_profile_revision=1,
                expected_revocation_digest=None):
    envelope, trust = _clone(envelope), _clone(trust)
    revoked = verify_revocations(revocations,trust,tenant_id,project_id,now,min_epoch=min_revocation_epoch,expected_digest=expected_revocation_digest)
    result = _lock(envelope,trust,tenant_id,project_id,now,revoked,min_sequence,min_pack_sequences)
    active = _profile(result['lock'],profile_registry,trust,revoked,now,min_profile_revision)
    result.update(profile=active['profile'], profile_author_id=active['author_id'], revocation_epoch=revoked['epoch'])
    return result


class RulePackRegistry:
    """One project-local append-only authority; external checkpoints detect rollback."""

    @classmethod
    @_guard
    def create(cls, root, tenant_id, project_id, trust):
        root = security.safe_path(root)
        security.identifier(tenant_id)
        security.identifier(project_id)
        _require(not root.exists(),'PACK_STORE_EXISTS')
        root.mkdir(mode=0o700)
        (root/'events').mkdir(mode=0o700)
        fd = os.open(root/'.lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.close(fd)
        profiles._write_new(root/'registry.json',dict(format='govcode-rule-packs-v1',context=security.CONTEXT,
            tenant_id=tenant_id,project_id=project_id,registry_id=uuid.uuid4().hex,operational_approval=False))
        return cls(root,trust)

    @_guard
    def __init__(self, root, trust, *, checkpoint=None):
        self.root = security.safe_path(root)
        _require(self.root.is_dir() and security.safe_path(self.root/'events').is_dir(),'PACK_STORE_MISSING')
        self.trust = _clone(trust)
        _require(self.trust.get('context') == security.CONTEXT,'TRUST_INVALID')
        self.metadata = security.read_json(self.root/'registry.json')
        m = self.metadata
        _require(set(m) == {'format','context','tenant_id','project_id','registry_id','operational_approval'},'PACK_STORE_INVALID')
        _require(m['format']=='govcode-rule-packs-v1' and m['context']==security.CONTEXT and m['operational_approval'] is False,'PACK_STORE_INVALID')
        for key in ('tenant_id','project_id','registry_id'):
            security.identifier(m[key])
        self.tenant_id,self.project_id = m['tenant_id'],m['project_id']
        self.anchor = _clone(checkpoint) if checkpoint is not None else None
        if self.anchor is not None:
            a = self.anchor
            _require(set(a)=={'sequence','head_digest','tenant_id','project_id','registry_id'},'CHECKPOINT_INVALID')
            _require(type(a['sequence']) is int and 0 <= a['sequence'] <= MAX_EVENTS,'CHECKPOINT_INVALID')
            _require(type(a['head_digest']) is str and len(a['head_digest'])==64 and all(x in '0123456789abcdef' for x in a['head_digest']),'CHECKPOINT_INVALID')
            _require(all(a[k]==m[k] for k in ('tenant_id','project_id','registry_id')),'CHECKPOINT_SCOPE_MISMATCH')
        with self._locked():
            self._read()

    @contextmanager
    def _locked(self):
        try:
            import fcntl
        except ImportError:
            raise PackError('PACK_LOCK_UNAVAILABLE') from None
        fd = os.open(security.safe_path(self.root/'.lock'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'PATH_UNSAFE')
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _base(self, kind, key_id, now, sequence):
        return dict(kind=kind,schema_version='1',context=security.CONTEXT,tenant_id=self.tenant_id,
            project_id=self.project_id,operational_approval=False,actor_id=self.trust['keys'][key_id]['actor_id'],
            event_id=uuid.uuid4().hex,created_at=now,expected_sequence=sequence)

    def _current_feed(self, state, now):
        return verify_revocations(state['feed'],self.trust,self.tenant_id,self.project_id,now,
                                  expected_digest=c.digest(state['feed']))

    def _dependencies(self, state, manifest, now, revoked):
        found,visiting = {},set()
        def visit(ref):
            key = ref['id'],ref['version']
            _require(key not in visiting,'DEPENDENCY_CYCLE')
            if key in found:
                return
            record = state['records'].get(key)
            _require(record is not None and record['state']=='published','DEPENDENCY_UNPUBLISHED')
            visiting.add(key)
            value = _release(record['release'],self.trust,self.tenant_id,self.project_id,now,revoked)
            _require(ref == value['pack_ref'],'DEPENDENCY_DIGEST_MISMATCH')
            for dep in value['manifest']['dependencies']:
                visit(dep)
            visiting.remove(key)
            found[key] = value['manifest']
            _require(len(found)<=63,'PACK_LIMIT')
        for ref in manifest['dependencies']:
            visit(ref)
        dependency_order([manifest,*found.values()])

    def _reduce(self, state, envelope, received_at):
        raw = envelope.get('payload',{})
        kind = raw.get('kind')
        action = raw.get('action')
        if kind == 'rule_pack_action':
            role = {'draft':'author','submit':'author','approve':'approver','reject':'approver','retire':'operator','revoke':'operator'}.get(action)
            _require(role is not None,'PACK_ACTION_INVALID')
        else:
            _require(kind in ('rule_pack_release','rule_pack_revocations','project_pack_lock_release'),'PACK_PROTOCOL_INVALID')
            role = 'operator'
        value = _signed(envelope,self.trust,role,kind,self.tenant_id,self.project_id,received_at)
        _require(value['event_id'] not in state['seen'],'EVENT_REPLAY')
        _require(value['expected_sequence']==state['sequence'],'SEQUENCE_CONFLICT')
        if state['last_created'] is not None:
            _require(c.timestamp(value['created_at']) >= c.timestamp(state['last_created']),'EVENT_TIME_ORDER')
        if state['feed'] is not None:
            _not_revoked(envelope,state['feed']['payload'])
        if kind == 'rule_pack_action':
            key = value['pack_id'],value['version']
            if action == 'draft':
                _require(key not in state['records'],'PACK_VERSION_IMMUTABLE')
                content = validate_pack(value['manifest'],value['requirements'])
                manifest = content['manifest']
                _require((manifest['pack_id'],manifest['version'])==key and c.digest(content)==value['pack_digest'],'PACK_SUBJECT_MISMATCH')
                _require((manifest['tenant_id'],manifest['project_id'])==(self.tenant_id,self.project_id),'SCOPE_MISMATCH')
                owner = state['owners'].get(key[0],value['actor_id'])
                _require(owner==value['actor_id'],'PACK_AUTHOR_MISMATCH')
                state['owners'][key[0]] = owner
                state['records'][key] = dict(state='draft',author_record=_clone(envelope),submit_record=None,
                    approval_record=None,release=None,pack_digest=value['pack_digest'])
            else:
                _require(key in state['records'],'PACK_UNKNOWN')
                record = state['records'][key]
                _require(record['pack_digest']==value['pack_digest'],'PACK_SUBJECT_MISMATCH')
                allowed = {'submit':{'draft'},'approve':{'review'},'reject':{'review'},
                           'retire':{'approved','published'},'revoke':{'draft','review','approved','rejected','published','retired'}}
                _require(record['state'] in allowed[action],'PACK_TRANSITION_INVALID')
                author = record['author_record']['payload']['actor_id']
                if action == 'submit':
                    _require(value['actor_id']==author,'PACK_AUTHOR_MISMATCH')
                    record['submit_record'] = _clone(envelope)
                if action in ('approve','reject'):
                    _require(value['actor_id']!=author,'SELF_APPROVAL')
                if action == 'approve':
                    draft = record['author_record']['payload']
                    _ready(validate_pack(draft['manifest'],draft['requirements']),received_at)
                    _window(value,received_at)
                    record['approval_record'] = _clone(envelope)
                record['state'] = {'submit':'review','approve':'approved','reject':'rejected','retire':'retired','revoke':'revoked'}[action]
        elif kind == 'rule_pack_release':
            revoked = self._current_feed(state,received_at)
            result = _release(envelope,self.trust,self.tenant_id,self.project_id,received_at,revoked)
            key = result['pack_ref']['id'],result['pack_ref']['version']
            record = state['records'].get(key)
            _require(record is not None and record['state']=='approved','PACK_UNAPPROVED')
            for field in ('author_record','submit_record','approval_record'):
                _require(c.digest(record[field])==c.digest(value[field]),'PACK_PROOF_MISMATCH')
            _require(value['sequence']==state['publication_sequence']+1,'PACK_SEQUENCE_CONFLICT')
            self._dependencies(state,result['manifest'],received_at,revoked)
            record.update(state='published',release=_clone(envelope))
            state['publication_sequence'] = value['sequence']
        elif kind == 'rule_pack_revocations':
            prior = state['feed']['payload'] if state['feed'] is not None else None
            _require(value['epoch']==(prior['epoch']+1 if prior else 1),'REVOCATIONS_ROLLBACK')
            if prior:
                _require(all(set(prior[f]) <= set(value[f]) for f in REVOCATION_FIELDS),'REVOCATIONS_REMOVED')
            retired = {r['pack_digest'] for r in state['records'].values() if r['state'] in ('retired','revoked')}
            _require(retired <= set(value['pack_digests']),'REVOCATIONS_INCOMPLETE')
            verify_revocations(envelope,self.trust,self.tenant_id,self.project_id,received_at,expected_digest=c.digest(envelope))
            state['feed'] = _clone(envelope)
        else:
            revoked = self._current_feed(state,received_at)
            result = _lock(envelope,self.trust,self.tenant_id,self.project_id,received_at,revoked)
            lock = result['lock']
            key = lock['id'],lock['version']
            _require(key not in state['locks'],'LOCK_VERSION_IMMUTABLE')
            _require(lock['sequence']==state['lock_sequence']+1,'LOCK_SEQUENCE_CONFLICT')
            for release in value['pack_releases']:
                ref = release['payload']['pack_ref']
                record = state['records'].get((ref['id'],ref['version']))
                _require(record is not None and record['state']=='published' and c.digest(record['release'])==c.digest(release),'LOCK_PACK_UNPUBLISHED')
            state['locks'][key] = _clone(envelope)
            state['lock_sequence'] = lock['sequence']
        state['seen'].add(value['event_id'])
        state['sequence'] += 1
        state['last_created'] = value['created_at']

    def _read(self):
        _require(security.read_json(self.root/'registry.json')==self.metadata,'PACK_METADATA_CHANGED')
        state = dict(records={},owners={},locks={},feed=None,publication_sequence=0,lock_sequence=0,
                     seen=set(),sequence=0,last_created=None,head=c.digest(self.metadata),bytes=0)
        heads = [state['head']]
        files = sorted(security.safe_path(self.root/'events').iterdir())
        _require(len(files)<=MAX_EVENTS,'PACK_HISTORY_LIMIT')
        last_received = None
        for number,path in enumerate(files,1):
            _require(path.name==f'{number:08}.json','PACK_HISTORY_INVALID')
            event = security.read_json(path)
            state['bytes'] += len(security.canonical(event))
            _require(state['bytes']<=MAX_HISTORY_BYTES,'PACK_HISTORY_LIMIT')
            _require(set(event)=={'sequence','previous_digest','received_at','signed_action','event_digest'},'PACK_HISTORY_INVALID')
            _require(type(event['sequence']) is int and event['sequence']==number and event['previous_digest']==state['head'],'PACK_HASH_CHAIN_INVALID')
            _require(event['event_digest']==c.digest({k:v for k,v in event.items() if k!='event_digest'}),'PACK_HASH_CHAIN_INVALID')
            if last_received is not None:
                _require(c.timestamp(event['received_at'])>=c.timestamp(last_received),'EVENT_TIME_ORDER')
            self._reduce(state,event['signed_action'],event['received_at'])
            state['head'],last_received = event['event_digest'],event['received_at']
            heads.append(state['head'])
        if self.anchor is not None:
            _require(state['sequence']>=self.anchor['sequence'] and heads[self.anchor['sequence']]==self.anchor['head_digest'],'PACK_ROLLBACK')
        state['last_received'] = last_received
        return state

    def _append(self, state, envelope, now):
        _require(state['sequence']<MAX_EVENTS,'PACK_HISTORY_LIMIT')
        if state['last_received'] is not None:
            _require(c.timestamp(now)>=c.timestamp(state['last_received']),'EVENT_TIME_ORDER')
        previous = state['head']
        self._reduce(state,envelope,now)
        event = dict(sequence=state['sequence'],previous_digest=previous,received_at=now,signed_action=envelope)
        event['event_digest'] = c.digest(event)
        _require(state['bytes']+len(security.canonical(event))<=MAX_HISTORY_BYTES,'PACK_HISTORY_LIMIT')
        profiles._write_new(self.root/'events'/f'{state["sequence"]:08}.json',event)

    @_guard
    def apply(self, signed_action, now):
        envelope = _clone(signed_action)
        _require(envelope.get('payload',{}).get('kind')=='rule_pack_action','PACK_ACTION_REQUIRED')
        with self._locked():
            state = self._read()
            self._append(state,envelope,now)
            p = envelope['payload']
            record = state['records'][(p['pack_id'],p['version'])]
            return dict(pack_id=p['pack_id'],version=p['version'],state=record['state'],
                        pack_digest=record['pack_digest'],operational_approval=False)

    @_guard
    def publish(self, pack_id, version, private_path, key_id, *, now, not_before, expires_at, expected_sequence):
        with self._locked():
            state = self._read()
            record = state['records'].get((pack_id,version))
            _require(record is not None and record['state']=='approved','PACK_UNAPPROVED')
            draft = record['author_record']['payload']
            manifest = draft['manifest']
            value = self._base('rule_pack_release',key_id,now,expected_sequence)
            value.update(pack_ref=dict(kind='rule_pack_manifest',id=pack_id,version=version,digest=c.digest(manifest)),
                pack_digest=record['pack_digest'],sequence=state['publication_sequence']+1,
                not_before=not_before,expires_at=expires_at,
                **{f:record[f] for f in ('author_record','submit_record','approval_record')})
            envelope = security.sign(value,private_path,key_id)
            self._append(state,envelope,now)
            return _clone(envelope)

    @_guard
    def issue_revocations(self, private_path, key_id, *, now, expires_at, expected_sequence, **changes):
        _require(set(changes)<=set(REVOCATION_FIELDS),'REVOCATIONS_FIELDS_INVALID')
        with self._locked():
            state = self._read()
            prior = state['feed']['payload'] if state['feed'] else None
            value = self._base('rule_pack_revocations',key_id,now,expected_sequence)
            value.update(epoch=prior['epoch']+1 if prior else 1,not_before=now,expires_at=expires_at)
            for field in REVOCATION_FIELDS:
                supplied = changes.get(field,[])
                _require(type(supplied) is list,'REVOCATIONS_FIELDS_INVALID')
                value[field] = sorted(set(supplied) | set(prior[field] if prior else []))
            value['pack_digests'] = sorted(set(value['pack_digests']) | {r['pack_digest'] for r in state['records'].values() if r['state'] in ('retired','revoked')})
            envelope = security.sign(value,private_path,key_id)
            self._append(state,envelope,now)
            return _clone(envelope)

    @_guard
    def publish_lock(self, selection, review, releases, profile_registry, private_path, key_id, *, now, expected_sequence):
        selection,review,releases = _clone(selection),_clone(review),_clone(releases)
        with self._locked():
            state = self._read()
            value = self._base('project_pack_lock_release',key_id,now,expected_sequence)
            value.update(lock=selection['payload']['lock'],selection_record=selection,review_record=review,pack_releases=releases)
            envelope = security.sign(value,private_path,key_id)
            verify_lock(envelope,self.trust,self.tenant_id,self.project_id,now,revocations=state['feed'],profile_registry=profile_registry,
                        expected_revocation_digest=c.digest(state['feed']))
            self._append(state,envelope,now)
            return _clone(envelope)

    @_guard
    def get(self, pack_id, version):
        security.identifier(pack_id)
        security.identifier(version)
        with self._locked():
            record = self._read()['records'].get((pack_id,version))
            _require(record is not None,'PACK_UNKNOWN')
            return dict(pack_id=pack_id,version=version,state=record['state'],pack_digest=record['pack_digest'],
                        publication_sequence=record['release']['payload']['sequence'] if record['release'] else None,
                        operational_approval=False)

    @_guard
    def checkpoint(self):
        with self._locked():
            state = self._read()
            return dict(sequence=state['sequence'],head_digest=state['head'],tenant_id=self.tenant_id,
                        project_id=self.project_id,registry_id=self.metadata['registry_id'])
