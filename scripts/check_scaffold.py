"""Validate authored contracts and fixtures; this is not a GovCode detector."""
from pathlib import Path
import copy
import hashlib
import json
import re
import runpy

from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / 'packages/contracts/catalog.schema.json'
schema = json.loads(SCHEMA_PATH.read_text())
for contract_path in sorted((ROOT / 'packages/contracts').glob('*.schema.json')):
    Draft7Validator.check_schema(json.loads(contract_path.read_text()))
validator = Draft7Validator(schema)
entities = {}
files = []
authored_roots = ['regulations', 'policies/examples', 'policies/local-demo', 'examples/complaints-api']
json_paths = [path for base in authored_roots for path in (ROOT / base).rglob('*.json')]
for path in sorted(json_paths):
    value = json.loads(path.read_text())
    assert validator.is_valid(value), f'Invalid schema fixture: {path.relative_to(ROOT)}'
    assert value['id'] not in entities, f'Duplicate ID: {value["id"]}'
    entities[value['id']] = value
    files.append(path)

def require(entity_id, kind):
    value = entities[entity_id]
    assert value['kind'] == kind, (entity_id, kind)
    return value

def pinned(ref, kind):
    value = require(ref['id'], kind)
    assert value['version'] == ref['version'], ref
    return value

for value in entities.values():
    kind = value['kind']
    if kind == 'obligation':
        require(value['source_id'], 'source')
    elif kind == 'control':
        for key in value['obligation_ids']:
            require(key, 'obligation')
    elif kind == 'policy':
        require(value['control_id'], 'control')
        assert value['basis_kind'] == 'example_policy'
        assert value['enabled'] is False and value['lifecycle'] == 'draft'
    elif kind == 'policy_bundle':
        for field, target in [('policy_refs','policy'), ('control_refs','control'), ('obligation_refs','obligation')]:
            for ref in value[field]:
                pinned(ref, target)
    elif kind == 'run' and value['parent_run_id']:
        parent = require(value['parent_run_id'], 'run')
        assert parent['id'] != value['id']
        assert parent['tenant_id'] == value['tenant_id']
        assert parent['project_id'] == value['project_id']
    elif kind == 'finding':
        require(value['run_id'], 'run')
        location = value['location']
        lines = (ROOT / location['path']).read_text().splitlines()
        assert 1 <= location['line'] <= len(lines)
        assert 'logger.info' in lines[location['line']-1]
    elif kind == 'decision':
        require(value['run_id'], 'run')
        if value['outcome'] in {'allow', 'deny'}:
            assert value['policy_refs'], 'Policy-derived decision requires a resolved policy'
        for ref in value['policy_refs']:
            pinned(ref, 'policy')
        for key in value['finding_ids']:
            assert require(key, 'finding')['run_id'] == value['run_id']
    elif kind == 'evidence':
        run = require(value['run_id'], 'run')
        assert require(value['decision_id'], 'decision')['run_id'] == value['run_id']
        assert value['parent_run_id'] == run['parent_run_id']
        assert value['provenance_kind'] == 'example'
        assert value['signature_status'] == 'not_signed' and value['receipt_status'] == 'pending'
        for artifact in value['artifacts']:
            raw = (ROOT / artifact['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == artifact['sha256'], artifact['path']
        envelope_fields = {'manifest_digest', 'signature_status', 'receipt_status'}
        payload = {k:v for k,v in value.items() if k not in envelope_fields}
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',',':')).encode()
        assert hashlib.sha256(canonical).hexdigest() == value['manifest_digest']

link_count = 0
markdown_paths = [ROOT / 'README.md', ROOT / 'AGENTS.md']
for base in ['docs', 'apps', 'deploy', 'packages', 'policies', 'regulations', 'examples', 'tests']:
    markdown_paths.extend((ROOT / base).rglob('*.md'))
for path in sorted(markdown_paths):
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', path.read_text()):
        if target.startswith(('https://','http://','#')):
            continue
        target_path = (path.parent / target.split('#')[0]).resolve()
        assert target_path.is_relative_to(ROOT), (path, target)
        assert target_path.exists(), (path, target)
        link_count += 1

# Reject malformed contracts without changing the checked-in samples.
bad = []
value = copy.deepcopy(require('DECISION-AFTER-EXAMPLE','decision'))
value['outcome'] = 'probably_safe'
bad.append(value)
value = copy.deepcopy(require('FINDING-EXAMPLE','finding'))
value['raw_request_body'] = 'MUST_NOT_BE_STORED'
bad.append(value)
value = copy.deepcopy(require('FINDING-EXAMPLE','finding'))
value['location']['path'] = '../outside.py'
bad.append(value)
value = copy.deepcopy(require('POL-EX-LOG-001','policy'))
del value['kind']
bad.append(value)
for outcome in ['allow', 'deny']:
    value = copy.deepcopy(require('DECISION-NO-POLICY-EXAMPLE', 'decision'))
    value['outcome'] = outcome
    bad.append(value)
value = copy.deepcopy(require('RUN-REFERENCE-CONTEXT-EXAMPLE', 'run'))
value['reference_context']['operational_approval'] = True
bad.append(value)
value = copy.deepcopy(require('RUN-REFERENCE-CONTEXT-EXAMPLE', 'run'))
value['reference_context']['context'] = 'institution_approved'
bad.append(value)
for value in bad:
    assert not validator.is_valid(value), 'Malformed fixture accepted'

# This checks only the authored before/after fixture behavior, not detector recall.
class Logger:
    def __init__(self):
        self.calls = []
    def info(self, *args, **kwargs):
        self.calls.append((args, kwargs))

class Audit:
    def __init__(self):
        self.calls = []
    def record_event(self, *args, **kwargs):
        self.calls.append((args, kwargs))

body = {'complaint_text':'SYNTHETIC_PRIVATE_SENTINEL'}
outputs, logs, audits = [], [], []
for name in ['before', 'after']:
    namespace = runpy.run_path(str(ROOT / f'examples/complaints-api/{name}.py'))
    logger, audit = Logger(), Audit()
    outputs.append(namespace['submit_complaint'](body, 'opaque-server-id', logger, audit))
    logs.append(repr(logger.calls))
    audits.append(audit.calls)
assert outputs[0] == outputs[1]
assert 'SYNTHETIC_PRIVATE_SENTINEL' in logs[0]
assert 'SYNTHETIC_PRIVATE_SENTINEL' not in logs[1]
assert audits[0] == audits[1] and len(audits[1]) == 1

print(f'PASS: Draft-07 schema; {len(files)} entity fixtures; references; {link_count} local links; artifact and manifest digests')
print(f'PASS: {len(bad)} malformed contracts rejected; before/after response, app-log minimization and audit-call preservation')
print('OUTSIDE THIS STATIC CHECK: runtime detector/API/gate tests; operational signatures, storage and legal applicability')
