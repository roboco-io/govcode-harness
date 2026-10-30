"""Loopback-only synthetic reference desk; admin-configured identities, no registration."""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from . import governance, security
from .evidence_store import EvidenceStore, StoreError

MAX_BODY = 65536
UI = Path(__file__).with_name('ui')


class ControlError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


def now():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ControlError('JSON_DUPLICATE_KEY')
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        security.canonical(value)
        if type(value) is not dict: raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError): raise ControlError('JSON_INVALID') from None


def fields(value, required, optional=()):
    if not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise ControlError('FIELDS_INVALID')


class Desk:
    def __init__(self, config):
        self.config = json.loads(security.canonical(config))
        if config.get('context') != security.CONTEXT or config.get('operational_approval') is not False:
            raise ControlError('CONFIG_INVALID')
        config = self.config
        self.trust, self.scopes = config['trust'], {}
        for scope in config['scopes']:
            identity = (scope['tenant_id'], scope['project_id'])
            if identity in self.scopes: raise ControlError('CONFIG_INVALID')
            for item in identity: security.identifier(item)
            reg = governance.PolicyRegistry(scope['registry_root'], self.trust)
            signer = scope['operator_signer']
            store = EvidenceStore(scope['store_root'], self.trust, **signer)
            if (reg.tenant_id, reg.project_id) != identity or (store.tenant_id, store.project_id) != identity:
                raise ControlError('CONFIG_SCOPE_INVALID')
            probe = self.sign(signer, identity, {'kind': 'control_probe'})
            security.verify(probe, self.trust, 'operator', *identity)
            root = security.safe_path(scope['control_root'])
            root.mkdir(mode=0o700, parents=False, exist_ok=True)
            self.scopes[identity] = dict(scope, control_root=str(root))
        self.principals = config['principals']
        seen = set()
        for principal in self.principals:
            identity = (principal['tenant_id'], principal['project_id'])
            key = self.trust['keys'][principal['key_id']]
            token_hash = principal['token_sha256']
            if (not re.fullmatch('[a-f0-9]{64}', token_hash) or token_hash in seen or identity not in self.scopes
                or key['actor_id'] != principal['actor_id'] or key['revoked'] is not False
                or (key['tenant_id'], key['project_id']) != identity or not principal['roles']
                or not set(principal['roles']) <= set(key['roles']) & security.ROLES):
                raise ControlError('CONFIG_PRINCIPAL_INVALID')
            seen.add(token_hash)
            for role in principal['roles']:
                security.verify(self.sign(principal, identity, {'kind': 'control_probe'}), self.trust, role, *identity)

        from .project.control import ProjectService
        self.project_service = ProjectService(self, config.get("project_contexts", []))

    def sign(self, signer, identity, extra):
        actor = self.trust['keys'][signer['key_id']]['actor_id']
        payload = dict(context=security.CONTEXT, tenant_id=identity[0], project_id=identity[1], actor_id=actor)
        payload.update(extra)
        return security.sign(payload, signer['private_path'], signer['key_id'])

    def authenticate(self, token):
        candidate = hashlib.sha256(token.encode('utf-8')).hexdigest()
        found = None
        for principal in self.principals:
            if hmac.compare_digest(candidate, principal['token_sha256']): found = principal
        if found is None: raise ControlError('AUTH_REQUIRED', 401)
        key = self.trust['keys'][found['key_id']]
        if key['revoked'] is not False: raise ControlError('AUTH_REQUIRED', 401)
        return found

    def reject_scope(self, value, identity):
        if type(value) is dict:
            for key, item in value.items():
                if key in ('tenant_id', 'project_id') and item != identity[('tenant_id', 'project_id').index(key)]:
                    raise ControlError('SCOPE_FORBIDDEN', 403)
                if key in ('actor_id', 'roles', 'key_id', 'private_path', 'token_sha256', 'path'):
                    raise ControlError('IDENTITY_FIELDS_FORBIDDEN', 403)
                self.reject_scope(item, identity)
        elif type(value) is list:
            for item in value: self.reject_scope(item, identity)

    def registry(self, scope):
        return governance.PolicyRegistry(scope['registry_root'], self.trust)

    def records(self, scope):
        registry = self.registry(scope)
        return [dict(policy_id=k[0], version=k[1], policy=v['policy'], policy_digest=v['policy_digest'], state=v['state'],
                     author=v['author_record']['payload']['actor_id']) for k, v in registry._states.items()]

    def public_runs(self, scope):
        result = []
        for run in scope.get('runs', []):
            summary = {k: run[k] for k in ('id', 'outcome', 'manifest_digest') if k in run}
            summary['findings'] = [{k: f[k] for k in ('id', 'category', 'severity', 'location') if k in f} for f in run.get('findings', [])]
            result.append(summary)
        return result

    def exception_context(self, scope, claims, policy):
        selected = [r for r in scope.get('runs', []) if r.get('id') == claims.get('run_id')]
        if len(selected) != 1: raise ControlError('RUN_NOT_REGISTERED', 403)
        run = selected[0]
        if (run.get('tenant_id'), run.get('project_id')) != (scope['tenant_id'], scope['project_id']):
            raise ControlError('RUN_SCOPE_FORBIDDEN', 403)
        fingerprints = {}
        for finding in run.get('findings', []):
            finding_id = security.identifier(finding['id'])
            if finding_id in fingerprints: raise ControlError('FINDING_REGISTRY_INVALID')
            fingerprints[finding_id] = governance.finding_digest(run, finding, policy)
        requested = claims.get('finding_ids')
        if type(requested) is not list or not requested or len(set(requested)) != len(requested) or not set(requested) <= set(fingerprints):
            raise ControlError('FINDING_SCOPE_FORBIDDEN', 403)
        return dict(commit_sha=run['commit_sha'], tool_digest=run['tool_digest'], finding_digests=fingerprints,
                    revocations=scope.get('revocations'))

    def persist(self, scope, kind, envelope):
        name = uuid.uuid4().hex
        path = security.safe_path(Path(scope['control_root']) / f'{kind}-{name}.json')
        governance._write_new(path, envelope)
        return name

    def exceptions(self, scope):
        result = []
        for path in sorted(security.safe_path(scope['control_root']).glob('exception-*.json')):
            envelope = security.read_json(path)
            claims = security.verify(envelope, self.trust, 'author', scope['tenant_id'], scope['project_id'])
            result.append({'id': path.stem.removeprefix('exception-'), 'request': claims,
                           'approved': False})
            approval_path = path.parent / f'approval-{path.stem.removeprefix("exception-")}.json'
            if approval_path.exists():
                policy = next((r['policy'] for r in self.records(scope) if r['policy_id'] == claims['policy_id'] and r['version'] == claims['version']), None)
                approval = security.read_json(approval_path)
                # Validate at the recorded approval time; expired requests remain historical records.
                context = self.exception_context(scope, claims, policy)
                governance.validate_exception(approval, self.trust, policy, list(context['finding_digests']), approval['payload']['created_at'], **context)
                if approval['payload']['request'] != envelope: raise ControlError('EXCEPTION_RECORD_INVALID')
                result[-1]['approved'] = True
        return result

    def handle(self, method, route, principal, body):
        identity = principal['tenant_id'], principal['project_id']
        scope = self.scopes[identity]
        self.reject_scope(body, identity)
        if route == '/api/projects' or route.startswith('/api/projects/'):
            from .project.assessment import AssessmentError
            try:
                return self.project_service.handle(method, route, principal, body, now())
            except AssessmentError as error:
                raise ControlError(error.code, 403 if error.code in ('SELF_APPROVAL', 'ROLE_REQUIRED', 'SCOPE_MISMATCH') else 400) from None
        role_routes = {'/api/policies/draft': 'author', '/api/policies/submit': 'author',
                       '/api/policies/approve': 'approver', '/api/bundles/issue': 'operator',
                       '/api/exceptions/request': 'author', '/api/exceptions/approve': 'approver',
                       '/api/evidence/hold': 'operator'}
        if method == 'POST' and route in role_routes and role_routes[route] not in principal['roles']:
            raise ControlError('ROLE_REQUIRED', 403)
        if method == 'GET' and route == '/api/overview':
            records = self.records(scope)
            return dict(tenant_id=identity[0], project_id=identity[1], actor=principal['actor_id'], roles=principal['roles'],
                        context=security.CONTEXT, operational_approval=False, review=sum(r['state'] == 'review' for r in records),
                        runs=self.public_runs(scope), policies=len(records))
        if method == 'GET' and route == '/api/runs':
            return self.public_runs(scope)
        if method == 'GET' and route == '/api/policies': return self.records(scope)
        if method == 'POST' and route.startswith('/api/policies/') and route in role_routes:
            action = route.rsplit('/', 1)[1]
            if action == 'draft': fields(body, ('policy',), ('obligations',)); extra = dict(policy=body['policy'], obligations=body.get('obligations', []))
            else:
                fields(body, ('policy_id', 'version', 'policy_digest'))
                extra = dict(body)
            envelope = self.sign(principal, identity, dict(action=action, event_id=uuid.uuid4().hex, created_at=now(), **extra))
            return self.registry(scope).apply(envelope, now())
        if method == 'POST' and route == '/api/bundles/issue':
            fields(body, ('policy_refs', 'not_before', 'expires_at', 'sequence'))
            previous = [security.verify(security.read_json(p), self.trust, 'operator', *identity)['sequence'] for p in Path(scope['control_root']).glob('bundle-*.json')]
            if type(body['sequence']) is not int or body['sequence'] <= max(previous, default=0): raise ControlError('BUNDLE_ROLLBACK')
            bundle = self.registry(scope).issue_bundle(body['policy_refs'], principal['private_path'], principal['key_id'], body['not_before'], body['expires_at'], body['sequence'])
            reference = self.persist(scope, 'bundle', bundle)
            return {'id': reference, 'bundle': bundle, 'operational_approval': False}
        if method == 'GET' and route == '/api/exceptions': return self.exceptions(scope)
        if method == 'POST' and route == '/api/exceptions/request':
            fields(body, ('run_id', 'policy_id', 'version', 'policy_digest', 'finding_ids', 'compensating_control', 'expires_at'))
            records = [r for r in self.records(scope) if r['policy_id'] == body['policy_id'] and r['version'] == body['version']]
            if not records or records[0]['policy_digest'] != body['policy_digest'] or records[0]['policy']['basis_kind'] != 'example_policy' or records[0]['state'] != 'approved': raise ControlError('EXCEPTION_POLICY_INVALID')
            if not body['compensating_control'].strip() or governance._time(body['expires_at']) <= governance._time(now()): raise ControlError('EXCEPTION_INVALID')
            context = self.exception_context(scope, body, records[0]['policy'])
            bindings = dict(commit_sha=context['commit_sha'], tool_digest=context['tool_digest'], finding_digests={fid: context['finding_digests'][fid] for fid in body['finding_ids']})
            request = self.sign(principal, identity, dict(kind='exception_request', event_id=uuid.uuid4().hex, created_at=now(), **body, **bindings))
            return {'id': self.persist(scope, 'exception', request), 'state': 'review'}
        if method == 'POST' and route == '/api/exceptions/approve':
            fields(body, ('id',)); security.identifier(body['id'])
            if not re.fullmatch('[a-f0-9]{32}', body['id']): raise ControlError('RECORD_NOT_FOUND', 404)
            path = Path(scope['control_root']) / f'exception-{body["id"]}.json'
            if not path.exists(): raise ControlError('RECORD_NOT_FOUND', 404)
            request = security.read_json(path)
            approval = self.sign(principal, identity, dict(kind='exception_approval', event_id=uuid.uuid4().hex, created_at=now(), request=request))
            claims = request['payload']
            record = next((r for r in self.records(scope) if r['policy_id'] == claims['policy_id'] and r['version'] == claims['version']), None)
            if record is None or record['state'] != 'approved': raise ControlError('POLICY_NOT_APPROVED')
            policy = record['policy']
            context = self.exception_context(scope, claims, policy)
            governance.validate_exception(approval, self.trust, policy, list(context['finding_digests']), now(), **context)
            governance._write_new(path.parent / f'approval-{body["id"]}.json', approval)
            return {'id': body['id'], 'state': 'approved', 'operational_approval': False}
        if method == 'GET' and route == '/api/evidence':
            store = EvidenceStore(scope['store_root'], self.trust, **scope['operator_signer'])
            return [dict(id=item, hold=entry['hold'], tombstone=entry['tombstone'], outcome=entry['metadata']['original_outcome']) for item, entry in store.state.items()]
        if (method == 'GET' and route.startswith('/api/evidence/')) or (method == 'POST' and route == '/api/evidence/hold'):
            action = 'read' if method == 'GET' else 'set_hold'
            role = 'auditor' if action == 'read' else 'operator'
            if role not in principal['roles']: raise ControlError('ROLE_REQUIRED', 403)
            if action == 'set_hold': fields(body, ('id', 'enabled'))
            item = route.rsplit('/', 1)[1] if action == 'read' else body['id']
            security.identifier(item)
            store = EvidenceStore(scope['store_root'], self.trust, **scope['operator_signer'])
            if item not in store.state or store.state[item]['tombstone']: raise ControlError('RECORD_NOT_FOUND', 404)
            authorization = self.sign(principal, identity, dict(kind='store_authorization', action=action, archive_id=item, event_id=uuid.uuid4().hex, time=now()))
            if action == 'read':
                result = store.read(item, authorization)
                return {'metadata': result['metadata'], 'projection': decode(result['artifacts']['projection.json']), 'integrity_verified': True, 'operational_approval': False, 'verification_scope': 'historical_signature_and_digests_only; no current tool rerun'}
            store.set_hold(item, body['enabled'], authorization)
            return {'id': item, 'hold': body['enabled']}
        raise ControlError('NOT_FOUND', 404)


def create_server(config, port=0):
    """Return an unstarted HTTPServer bound only to IPv4 loopback."""
    desk = Desk(config)
    class Handler(BaseHTTPRequestHandler):
        server_version = 'GovCodeReference'
        def log_message(self, *_): pass
        def respond(self, status, body, content_type='application/json; charset=utf-8'):
            raw = security.canonical(body) if content_type.startswith('application/json') else body
            self.send_response(status)
            for key, value in {'Content-Type': content_type, 'Content-Length': str(len(raw)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}.items(): self.send_header(key, value)
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self): self.dispatch('GET')
        def do_POST(self): self.dispatch('POST')
        def dispatch(self, method):
            self.close_connection = True
            try:
                expected = f'127.0.0.1:{self.server.server_port}'
                if len(self.headers.get_all('Host', [])) != 1 or self.headers.get('Host') != expected: raise ControlError('HOST_FORBIDDEN', 403)
                if len(self.headers.get_all('Origin', [])) > 1 or self.headers.get('Origin') not in (None, f'http://{expected}'): raise ControlError('ORIGIN_FORBIDDEN', 403)
                if self.headers.get('Transfer-Encoding') is not None: raise ControlError('FRAMING_INVALID')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) > 1 or (lengths and not re.fullmatch('[0-9]+', lengths[0])): raise ControlError('FRAMING_INVALID')
                length = int(lengths[0]) if lengths else 0
                if length > MAX_BODY: raise ControlError('BODY_LIMIT', 413)
                parsed = urlsplit(self.path)
                if parsed.scheme or parsed.netloc or parsed.fragment: raise ControlError('URL_INVALID')
                assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
                assets.update({'/project.html': ('project.html', 'text/html; charset=utf-8'), '/project.js': ('project.js', 'text/javascript; charset=utf-8')})
                if method == 'GET' and parsed.path in assets and not parsed.query:
                    name, mime = assets[parsed.path]; return self.respond(200, (UI / name).read_bytes(), mime)
                if not parsed.path.startswith('/api/'): raise ControlError('NOT_FOUND', 404)
                auth = self.headers.get_all('Authorization', [])
                if len(auth) != 1 or not auth[0].startswith('Bearer ') or len(auth[0]) > 1024: raise ControlError('AUTH_REQUIRED', 401)
                principal = desk.authenticate(auth[0][7:])
                query = parse_qs(parsed.query, keep_blank_values=True)
                identity = principal['tenant_id'], principal['project_id']
                for key, values in query.items():
                    if key in ('tenant_id', 'project_id') and any(v != identity[('tenant_id', 'project_id').index(key)] for v in values): raise ControlError('SCOPE_FORBIDDEN', 403)
                if query: raise ControlError('QUERY_UNSUPPORTED')
                if method == 'POST':
                    if not lengths or self.headers.get('Content-Type') != 'application/json': raise ControlError('JSON_REQUIRED')
                    self.connection.settimeout(5)
                    raw = self.rfile.read(length)
                    if len(raw) != length: raise ControlError('BODY_INCOMPLETE')
                    body = decode(raw)
                else:
                    if length: raise ControlError('BODY_UNEXPECTED')
                    body = {}
                result = desk.handle(method, parsed.path, principal, body)
                self.respond(200, result)
            except ControlError as error: self.respond(error.status, {'error': error.code})
            except (security.SecurityError, governance.GovernanceError, StoreError) as error:
                self.respond(403 if error.code in ('SELF_APPROVAL', 'ROLE_REQUIRED', 'SCOPE_MISMATCH', 'AUTHOR_MISMATCH') else 400, {'error': error.code})
            except Exception: self.respond(400, {'error': 'REQUEST_INVALID'})
    server = HTTPServer(('127.0.0.1', port), Handler)
    server.desk = desk
    return server


def serve(config_path, port=8766):
    server = create_server(security.read_json(config_path), port)
    print(f'Local synthetic reference: http://127.0.0.1:{server.server_port} operational_approval=false', flush=True)
    try: server.serve_forever()
    finally: server.server_close()
