"""Read-only Git snapshot scanning and unsigned, local demonstration evidence.

No scanned source is imported or executed. Only the authored constant fixture in
``demo`` is executed for its synthetic regression check.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from . import __version__

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / 'policies/local-demo/POL-LOCAL-DEMO-LOG-001.json'
EXIT_CODES = {'allow': 0, 'deny': 2, 'review_required': 3, 'error': 4}
FORMAT = 'govcode-local-evidence-v1'
MAX_PARENT_LINKS = 16
MAX_FILES = 100
MAX_TOTAL = 2_000_000
MAX_BLOB = 256_000
BEFORE_SOURCE = '''def submit_complaint(request_body, request_id, logger, audit):
    logger.info("complaint=%s", request_body)
    audit.record_event("complaint_received", request_id=request_id)
    return {"status": "received", "request_id": request_id}
'''
AFTER_SOURCE = '''def submit_complaint(request_body, request_id, logger, audit):
    logger.info("complaint_received", extra={"request_id": request_id, "operation": "complaint_submit", "result_code": "received"})
    audit.record_event("complaint_received", request_id=request_id)
    return {"status": "received", "request_id": request_id}
'''

class HarnessError(Exception):
    """Carries only a public, non-sensitive error classification."""
    def __init__(self, code='RUNTIME_ERROR'):
        self.code = code
        super().__init__(code)

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def _safe_path(path):
    path = Path(os.path.abspath(os.fspath(path)))
    # macOS exposes OS-owned aliases; normalize only those exact prefixes,
    # then reject every user-controlled symlink in the remaining path.
    if sys.platform == 'darwin':
        for alias, real in [('/var', '/private/var'), ('/tmp', '/private/tmp'), ('/etc', '/private/etc')]:
            prefix = Path(alias)
            if path == prefix or prefix in path.parents:
                path = Path(real) / path.relative_to(prefix)
                break
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise HarnessError('SYMLINK_PATH')
    return path

def _new_directory(path):
    path = _safe_path(path)
    if path.exists():
        raise HarnessError('OUTPUT_EXISTS')
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=False)
    except OSError:
        raise HarnessError('OUTPUT_CREATE_FAILED') from None
    return _safe_path(path)

def _git(repo, *args):
    from .snapshot import SnapshotError, run_git
    try:
        return run_git(repo, *args)
    except SnapshotError as error:
        raise HarnessError(error.code) from None


def _repo(path, *, clean=True):
    path = _safe_path(path)
    try:
        top = _safe_path(_git(path, 'rev-parse', '--show-toplevel').decode().strip())
        gitdir = _safe_path(_git(path, 'rev-parse', '--absolute-git-dir').decode().strip())
    except (UnicodeError, OSError):
        raise HarnessError('REPOSITORY_INVALID') from None
    if path != top or not gitdir.is_dir():
        raise HarnessError('REPOSITORY_ROOT_REQUIRED')
    if clean:
        _ensure_clean(path)
    return path

def _ensure_clean(repo):
    # Do not call `git status`: repository clean filters can execute commands.
    commit = _head(repo)
    if _git(repo, 'diff-index', '--cached', '--raw', '-z', '--no-ext-diff', '--no-textconv', commit, '--'):
        raise HarnessError('DIRTY_WORKTREE')
    inventory, _, _ = _snapshot(repo, commit)
    expected = {item['path']:item['sha256'] for item in inventory}
    actual = set()
    for directory, dirs, files in os.walk(repo, followlinks=False):
        directory = Path(directory)
        if directory == repo:
            dirs[:] = [name for name in dirs if name != '.git']
            files = [name for name in files if name != '.git']
        for name in dirs:
            if (directory / name).is_symlink():
                raise HarnessError('SYMLINK_PATH')
        for name in files:
            path = _safe_path(directory / name)
            relative = path.relative_to(repo).as_posix()
            actual.add(relative)
            if relative not in expected or not path.is_file() or path.stat().st_size > MAX_BLOB:
                raise HarnessError('DIRTY_WORKTREE')
            if digest(path.read_bytes()) != expected[relative]:
                raise HarnessError('DIRTY_WORKTREE')
    if actual != set(expected):
        raise HarnessError('DIRTY_WORKTREE')

def _head(repo):
    sha = _git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    if not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise HarnessError('COMMIT_INVALID')
    return sha

def _context(tenant_id=None, project_id=None):
    if tenant_id is None and project_id is None:
        return None
    if not all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', v) for v in (tenant_id, project_id)):
        raise HarnessError('CONTEXT_INVALID')
    return (tenant_id, project_id)


def _context_object(context):
    return {'context':'synthetic_reference', 'tenant_id':context[0], 'project_id':context[1], 'operational_approval':False}


def _recorded_context(run, execution):
    marker = run.get('reference_context')
    if marker is None and 'reference_context' not in execution:
        if (run.get('tenant_id'), run.get('project_id')) != ('TENANT-LOCAL-DEMO', 'PROJECT-LOCAL-DEMO'):
            raise HarnessError('CONTEXT_MISMATCH')
        return None
    context = _context(run.get('tenant_id'), run.get('project_id'))
    if marker != _context_object(context) or execution.get('reference_context') != marker:
        raise HarnessError('CONTEXT_MISMATCH')
    return context


def _profile(context=None):
    try:
        raw = _safe_path(PROFILE_PATH).read_bytes()
        policy = json.loads(raw)
    except (OSError, ValueError):
        raise HarnessError('POLICY_INVALID') from None
    required = {'kind', 'id', 'version', 'control_id', 'basis_kind', 'lifecycle', 'enabled',
                'scope', 'condition', 'effect', 'evidence_requirements'}
    if (set(policy) != required or policy['kind'] != 'policy' or
        policy['id'] != 'POL-LOCAL-DEMO-LOG-001' or policy['version'] != '0.1.0' or
        policy['control_id'] != 'CTRL-LOG-001' or policy['basis_kind'] != 'example_policy' or
        policy['lifecycle'] != 'draft' or policy['enabled'] is not False or
        policy['scope'] != {'tenant_id':'TENANT-LOCAL-DEMO', 'project_id':'PROJECT-LOCAL-DEMO', 'languages':['python'], 'stage':'merge'} or
        policy['condition'] != {'field':'finding.category', 'operator':'eq', 'value':'pii_logging_risk'} or
        policy['effect'] != 'deny' or policy['evidence_requirements'] != ['run_provenance', 'decision', 'coverage', 'storage_receipt']):
        raise HarnessError('POLICY_INVALID')
    if context is not None:
        policy = {**policy, 'scope':{**policy['scope'], 'tenant_id':context[0], 'project_id':context[1]}}
    return policy

def _tool_digest():
    entries = []
    root = _safe_path(Path(__file__).parent)
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if '__pycache__' in relative.parts:
            continue
        if path.is_symlink():
            raise HarnessError('PATH_UNSAFE')
        is_resource = ((relative.parts[0] == 'contracts' and path.suffix == '.json') or
                       (relative.parts[0] == 'document_assets' and path.suffix == '.md'))
        if path.is_file() and (path.suffix == '.py' or is_resource):
            entries.append({'name':relative.as_posix(), 'sha256':digest(_safe_path(path).read_bytes())})
    interpreter = {'implementation':sys.implementation.name, 'version':list(sys.version_info)}
    return digest(canonical({'interpreter':interpreter, 'sources':entries}))

def _validate_commit(repo, commit):
    from .snapshot import SnapshotError, validate_commit
    try:
        return validate_commit(repo, commit, git=_git)
    except SnapshotError as error:
        raise HarnessError(error.code) from None


def _collect_snapshot(repo, commit):
    from .snapshot import SnapshotError, collect
    try:
        return collect(repo, commit, git=_git, max_files=MAX_FILES, max_blob=MAX_BLOB, max_total=MAX_TOTAL)
    except SnapshotError as error:
        raise HarnessError(error.code) from None


def _snapshot(repo, commit):
    collected = _collect_snapshot(repo, commit)
    return collected['inventory'], collected['sources'], collected['issues']


def _input_scope(commit, input_mode):
    if input_mode not in {'strict_head','commit_snapshot'}:
        raise HarnessError('INPUT_SCOPE_INVALID')
    return {'mode':input_mode, 'commit_sha':commit, 'worktree_checked':input_mode == 'strict_head'}


def _read_input_scope(execution, commit):
    scope = execution.get('input_scope')
    if not isinstance(scope,dict) or set(scope) != {'mode','commit_sha','worktree_checked'}:
        raise HarnessError('INPUT_SCOPE_INVALID')
    if scope != _input_scope(commit, scope.get('mode')) or type(scope['worktree_checked']) is not bool:
        raise HarnessError('INPUT_SCOPE_INVALID')
    return scope['mode']


def _iron_laws_analysis(sources):
    try:
        from .iron_laws_adapter import analyze
        return analyze(sources)
    except Exception:
        raise HarnessError('IRON_LAWS_ADAPTER_ERROR') from None


def _validated_iron_result(result, sources):
    """Only the declared adapter metadata and redacted report may reach evidence."""
    try:
        if not isinstance(result, dict) or set(result) != {'tool','outcome','findings','issues','report'}:
            raise ValueError()
        tool = result['tool']
        base_keys = {'name','version','source_commit','profile','config_sha256','status'}
        extra_keys = {'environment_sha256','artifact_sha256','interpreter_sha256','interpreter_version','lock_sha256','build_lock_sha256'}
        if not isinstance(tool, dict) or set(tool) not in (base_keys, base_keys | extra_keys):
            raise ValueError()
        if (tool['name'] != 'iron-laws' or tool['version'] != '1.11.2' or
            tool['source_commit'] != '2a820e8cd7ade4c3060381198ed13bf3e6b43146' or
            tool['profile'] != 'AI-112-v2-python-poc' or tool['status'] not in {'verified','unavailable'}):
            raise ValueError()
        for key in set(tool) & {'config_sha256','environment_sha256','artifact_sha256','interpreter_sha256','lock_sha256','build_lock_sha256'}:
            if not isinstance(tool[key],str) or not re.fullmatch('[a-f0-9]{64}',tool[key]):
                raise ValueError()
        if 'interpreter_version' in tool and (not isinstance(tool['interpreter_version'],str) or
            not re.fullmatch(r'Python [0-9]+\.[0-9]+\.[0-9]+[a-z0-9+.]*',tool['interpreter_version'])):
            raise ValueError()
        if result['outcome'] not in EXIT_CODES:
            raise ValueError()
        if result['outcome'] != 'error' and (tool['status'] != 'verified' or set(tool) != base_keys | extra_keys):
            raise ValueError()
        paths = {path:len(source.splitlines()) for path,source in sources}
        if not isinstance(result['findings'],list) or len(result['findings']) > 10000:
            raise ValueError()
        for finding in result['findings']:
            if (not isinstance(finding,dict) or set(finding) != {'path','line','severity','rule_id','category','data_classes'} or
                finding['path'] not in paths or type(finding['line']) is not int or not 1 <= finding['line'] <= paths[finding['path']] or
                finding['severity'] not in {'low','medium','high','critical'} or
                finding['category'] not in {'pii_logging_risk','external_code_risk'} or
                not isinstance(finding['rule_id'],str) or not re.fullmatch(r'[A-Z]+-\d{3}',finding['rule_id']) or
                not isinstance(finding['data_classes'],list) or
                any(value not in {'request_body','phone','address','national_identifier','free_text','potential_sensitive_data','source_code'} for value in finding['data_classes'])):
                raise ValueError()
        if not isinstance(result['issues'],list) or len(result['issues']) > 10000:
            raise ValueError()
        for issue in result['issues']:
            if (not isinstance(issue,dict) or set(issue) != {'path','line','code'} or
                issue['path'] not in {'.',*paths} or type(issue['line']) is not int or issue['line'] < 1 or
                not isinstance(issue['code'],str) or not re.fullmatch('[A-Z][A-Z0-9_]{0,80}',issue['code'])):
                raise ValueError()
        if result['outcome'] == 'allow' and (result['findings'] or result['issues']):
            raise ValueError()
        report = result['report']
        simple = {'format','profile','status','findings','issues'}
        complete = simple | {'config_sha256','schema_version','files_analyzed','verification','outcome'}
        if (not isinstance(report,dict) or set(report) not in (simple,complete) or
            report['format'] != 'govcode-iron-laws-sanitized-v1' or report['profile'] != tool['profile'] or
            report['findings'] != result['findings'] or report['issues'] != result['issues']):
            raise ValueError()
        if set(report) == simple:
            if result['outcome'] != 'error' or report['status'] != 'error':
                raise ValueError()
        elif (report['config_sha256'] != tool['config_sha256'] or report['schema_version'] != '1.8' or
              report['status'] != 'complete' or report['verification'] != 'upstream-structural-consistency' or
              report['files_analyzed'] != sorted(paths) or report['outcome'] != result['outcome']):
            raise ValueError()
        # Round trip rejects non-JSON objects and non-finite values; makes a private snapshot.
        return json.loads(canonical(result))
    except (KeyError,TypeError,ValueError,RecursionError):
        raise HarnessError('IRON_LAWS_RESULT_INVALID') from None


def _external_policy(context=None):
    policy = _profile(context)
    return {**policy, 'id':'POL-LOCAL-DEMO-IRON-LAWS-001', 'control_id':'CTRL-EXTERNAL-001',
            'condition':{'field':'finding.category','operator':'eq','value':'external_code_risk'}}


def _detector_profile(execution):
    if 'detectors' not in execution:
        return False
    if execution['detectors'] != ['python-local-flow','iron-laws']:
        raise HarnessError('DETECTOR_PROFILE_INVALID')
    return True


def _analysis(repo, commit, with_iron_laws=False, input_mode='strict_head'):
    from .detector import analyze
    from .snapshot import manifest
    collected = _collect_snapshot(repo, commit)
    inventory, sources, issues = collected['inventory'], collected['sources'], list(collected['issues'])
    snapshot_manifest = manifest(collected)
    findings = []
    parsed = True
    for name, source in sources:
        result = analyze(source, name)
        parsed = parsed and result['parsed']
        for item in result['findings']:
            findings.append({'path':name, **item})
        for item in result['issues']:
            issues.append({'path':name, **item})
    external = None
    if with_iron_laws:
        external = _validated_iron_result(_iron_laws_analysis(sources), sources)
        for item in external['findings']:
            findings.append({**item, 'detector_id':'iron-laws','detector_version':external['tool']['version']})
        issues.extend(external['issues'])
    findings.sort(key=lambda f:(f['path'], f['line'], f['category'], f.get('detector_id','python-local-flow'), f.get('rule_id','')))
    issues.sort(key=lambda f:(f['path'], f['line'], f['code']))
    if not parsed or any(i['code'] == 'SOURCE_ENCODING_ERROR' for i in issues) or (external and external['outcome'] == 'error'):
        outcome = 'error'
    elif issues or (external and external['outcome'] == 'review_required'):
        outcome = 'review_required'
    elif findings or (external and external['outcome'] == 'deny'):
        outcome = 'deny'
    else:
        outcome = 'allow'
    result = {'inventory':inventory, 'findings':findings, 'issues':issues, 'parsed':parsed,
              'outcome':outcome, 'supported_files':len(sources),
              'snapshot':snapshot_manifest, 'input_mode':input_mode}
    if external is not None:
        result['iron_laws'] = external
    return result

def _objects(repo, commit, analysis, run_id, started, parent_run_id=None, context=None):
    policy = _profile(context)
    pref = [{'id':policy['id'], 'version':policy['version']}]
    external = analysis.get('iron_laws')
    bundle_digest = digest(canonical(policy))
    tool_digest = _tool_digest()
    tool_version = __version__
    if external is not None:
        extra_policy = _external_policy(context)
        pref.append({'id':extra_policy['id'],'version':extra_policy['version']})
        bundle_digest = digest(canonical({'policies':[policy,extra_policy],'detectors':['python-local-flow','iron-laws']}))
        tool_digest = digest(canonical({'harness':tool_digest,'iron_laws':external['tool']}))
        tool_version += '+iron-laws'
    tool_digest = digest(canonical({'tool':tool_digest, 'input_scope':_input_scope(commit,analysis.get('input_mode','strict_head'))}))
    if context is not None:
        tool_digest = digest(canonical({'tool':tool_digest, 'reference_context':_context_object(context)}))
    run = {'kind':'run', 'id':run_id, 'tenant_id':'TENANT-LOCAL-DEMO', 'project_id':'PROJECT-LOCAL-DEMO',
           'commit_sha':commit, 'tree_digest':digest(canonical(analysis['inventory'])),
           'bundle_digest':bundle_digest, 'tool_version':tool_version, 'tool_digest':tool_digest,
           'status':'completed', 'parent_run_id':parent_run_id, 'started_at':started}
    if context is not None:
        run.update(tenant_id=context[0], project_id=context[1], reference_context=_context_object(context))
    findings = []
    for i, finding in enumerate(analysis['findings'], 1):
        findings.append({'kind':'finding', 'id':f'FINDING-{run_id}-{i}', 'run_id':run_id,
            'detector_id':finding.get('detector_id','python-local-flow'), 'detector_version':finding.get('detector_version',__version__), 'category':finding['category'],
            'severity':finding['severity'], 'confidence':0.8,
            'location':{'path':finding['path'], 'line':finding['line']},
            'data_classes':finding['data_classes'] or ['source_code'], 'coverage':'supported'})
    codes = {'allow':'REQUIRED_LOCAL_CHECKS_PASSED', 'deny':'PII_LOGGING_RISK',
             'review_required':'ANALYSIS_REQUIRES_REVIEW', 'error':'ANALYSIS_ERROR'}
    decision = {'kind':'decision', 'id':f'DECISION-{run_id}', 'run_id':run_id,
        'outcome':analysis['outcome'], 'reason_codes':[codes[analysis['outcome']]],
        'policy_refs':pref, 'finding_ids':[f['id'] for f in findings], 'exception_ids':[]}
    if external is not None and analysis['outcome'] == 'deny' and external['findings']:
        decision['reason_codes'] = ['IRON_LAWS_RISK'] + (['PII_LOGGING_RISK'] if any(f.get('detector_id') != 'iron-laws' for f in analysis['findings']) else [])
    return run, decision, findings, policy

def _write(path, value):
    try:
        with path.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(value) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, TypeError, ValueError):
        raise HarnessError('EVIDENCE_WRITE_FAILED') from None

def _read(path):
    path = _safe_path(path)
    try:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise HarnessError('EVIDENCE_INVALID')
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise HarnessError('EVIDENCE_INVALID')
        return value
    except (OSError, ValueError):
        raise HarnessError('EVIDENCE_INVALID') from None

def _seal(output):
    """Write or refresh the unsigned envelope. This is NOT an authenticity proof."""
    output = _safe_path(output)
    run, decision = _read(output / 'run.json'), _read(output / 'decision.json')
    artifact_names = sorted(p.name for p in output.iterdir() if p.name not in {'evidence.json', 'manifest.json', 'receipt.json'})
    artifacts = []
    for name in artifact_names:
        path = _safe_path(output / name)
        if not path.is_file():
            raise HarnessError('EVIDENCE_INVALID')
        artifacts.append({'path':name, 'sha256':digest(path.read_bytes()), 'media_type':'application/json'})
    manifest = {'format':FORMAT, 'mode':'local_demo', 'run_id':run['id'], 'evidence_id':f'EVIDENCE-{run["id"]}',
        'decision_id':decision['id'], 'parent_run_id':run['parent_run_id'], 'artifacts':artifacts}
    manifest_digest = digest(canonical(manifest))
    evidence = {'kind':'evidence', 'id':manifest['evidence_id'], 'run_id':run['id'],
        'parent_run_id':run['parent_run_id'], 'decision_id':decision['id'], 'provenance_kind':'execution',
        'artifacts':artifacts, 'manifest_digest':manifest_digest, 'signature_status':'not_signed',
        'receipt_status':'stored', 'retention_policy_id':None}
    # Used for initial sealing; test tamper probes may explicitly remove old envelopes first.
    for name, value in [('manifest.json', manifest), ('evidence.json', evidence)]:
        p = output / name
        if p.exists():
            _safe_path(p).unlink()
        _write(p, value)
    receipt = {'format':FORMAT, 'run_id':run['id'], 'manifest_digest':manifest_digest,
        'evidence_digest':digest((output / 'evidence.json').read_bytes()), 'status':'stored',
        'storage':'local-filesystem-unsigned'}
    if (output / 'receipt.json').exists():
        _safe_path(output / 'receipt.json').unlink()
    _write(output / 'receipt.json', receipt)
    try:
        fd = os.open(output, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise HarnessError('EVIDENCE_WRITE_FAILED') from None

def _capture_evidence(output):
    from .evidence_snapshot import capture, SnapshotError
    try:return capture(_safe_path(output))
    except SnapshotError:raise HarnessError('EVIDENCE_INVALID') from None


def _verify(repo, output, *, current=True, depth=0, expected_commit=None, expected_context=None, seen_paths=(), seen_run_ids=(), _snapshot=None, _views=None):
    if depth > MAX_PARENT_LINKS:
        raise HarnessError('PARENT_CHAIN_UNSUPPORTED')
    output = _safe_path(output)
    if str(output) in seen_paths:
        raise HarnessError('PARENT_CYCLE')
    seen_paths = (*seen_paths, str(output))
    view = _snapshot if _snapshot is not None else _capture_evidence(output)
    if _views is None:_views = {}
    _views[str(output)] = view
    run = view.read('run.json')
    if run.get('id') in seen_run_ids:
        raise HarnessError('PARENT_RUN_REPEATED')
    seen_run_ids = (*seen_run_ids, run.get('id'))
    if not re.fullmatch(r'RUN-[a-f0-9]{32}', run.get('id', '')):
        raise HarnessError('EVIDENCE_INVALID')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', run.get('started_at', '')):
        raise HarnessError('EVIDENCE_INVALID')
    commit = run.get('commit_sha', '')
    execution = view.read('execution.json')
    context = _recorded_context(run, execution)
    if expected_context is not None and context != expected_context:
        raise HarnessError('CONTEXT_MISMATCH')
    input_mode = _read_input_scope(execution, commit)
    if expected_commit is not None:
        if input_mode != 'commit_snapshot':
            raise HarnessError('INPUT_MODE_MISMATCH')
        if commit != _validate_commit(repo,expected_commit):
            raise HarnessError('EXPECTED_COMMIT_MISMATCH')
    elif current and commit != _head(repo):
        raise HarnessError('STALE_HEAD')
    with_iron_laws = _detector_profile(execution)
    analysis = _analysis(repo, commit, with_iron_laws=with_iron_laws, input_mode=input_mode)
    if (set(execution) != ({'mode', 'institutional_approval', 'policy_activation', 'repository_id', 'parent','input_scope'} | ({'detectors'} if with_iron_laws else set()) | ({'reference_context'} if context else set())) or
        execution['mode'] != 'local_demo' or execution['institutional_approval'] is not False or
        execution['policy_activation'] != 'explicit-local-demo' or execution['repository_id'] != digest(str(repo).encode())):
        raise HarnessError('EXECUTION_INVALID')
    parent_id = None
    parent_ref = execution['parent']
    if parent_ref is not None:
        if not isinstance(parent_ref, dict) or set(parent_ref) != {'directory','manifest_digest'}:
            raise HarnessError('PARENT_INVALID')
        parent_dir = _safe_path(parent_ref['directory'])
        if parent_dir == output:
            raise HarnessError('PARENT_INVALID')
        parent = _verify(repo, parent_dir, current=False, depth=depth + 1, expected_context=context, seen_paths=seen_paths, seen_run_ids=seen_run_ids, _views=_views)
        if _recorded_context(_views[str(parent_dir)].read('run.json'), _views[str(parent_dir)].read('execution.json')) != context:
            raise HarnessError('CONTEXT_MISMATCH')
        if parent['input_mode'] != input_mode:
            raise HarnessError('PARENT_INPUT_MODE_MISMATCH')
        if _detector_profile(_views[str(parent_dir)].read('execution.json')) != with_iron_laws:
            raise HarnessError('PARENT_DETECTOR_PROFILE_MISMATCH')
        if parent['outcome'] != 'deny' or parent['manifest_digest'] != parent_ref['manifest_digest']:
            raise HarnessError('PARENT_INVALID')
        if parent['commit_sha'] == commit:
            raise HarnessError('NEW_COMMIT_REQUIRED')
        _git(repo, 'merge-base', '--is-ancestor', parent['commit_sha'], commit)
        parent_id = parent['run_id']
    expected_run, expected_decision, findings, policy = _objects(repo, commit, analysis, run['id'], run['started_at'], parent_id, context)
    if run != expected_run or view.read('decision.json') != expected_decision or view.read('policy.json') != policy:
        raise HarnessError('SEMANTIC_MISMATCH')
    expected_coverage = {'scope':'all_tracked_files', 'inventory':analysis['inventory'],
                         'supported_files':analysis['supported_files'], 'issues':analysis['issues'], 'parsed':analysis['parsed']}
    if view.read('coverage.json') != expected_coverage:
        raise HarnessError('SEMANTIC_MISMATCH')
    if view.read('snapshot.json') != analysis['snapshot']:
        raise HarnessError('SNAPSHOT_SEMANTIC_MISMATCH')
    names = {'run.json', 'decision.json', 'policy.json', 'coverage.json', 'execution.json','snapshot.json'}
    if with_iron_laws:
        names.update({'iron-laws.json','iron-laws-policy.json'})
        if view.read('iron-laws.json') != analysis['iron_laws'] or view.read('iron-laws-policy.json') != _external_policy(context):
            raise HarnessError('IRON_LAWS_SEMANTIC_MISMATCH')
    for i, finding in enumerate(findings, 1):
        name = f'finding-{i:04d}.json'
        names.add(name)
        if view.read(name) != finding:
            raise HarnessError('SEMANTIC_MISMATCH')
    expected_names = names | {'evidence.json', 'manifest.json', 'receipt.json'}
    if set(view.files) != expected_names:
        raise HarnessError('EVIDENCE_FILE_SET_INVALID')
    artifacts = [{'path':name, 'sha256':digest(view.raw(name)), 'media_type':'application/json'} for name in sorted(names)]
    manifest = {'format':FORMAT, 'mode':'local_demo', 'run_id':run['id'], 'evidence_id':f'EVIDENCE-{run["id"]}',
                'decision_id':expected_decision['id'], 'parent_run_id':parent_id, 'artifacts':artifacts}
    manifest_digest = digest(canonical(manifest))
    evidence = {'kind':'evidence', 'id':manifest['evidence_id'], 'run_id':run['id'], 'parent_run_id':parent_id,
                'decision_id':expected_decision['id'], 'provenance_kind':'execution', 'artifacts':artifacts,
                'manifest_digest':manifest_digest, 'signature_status':'not_signed', 'receipt_status':'stored', 'retention_policy_id':None}
    receipt = {'format':FORMAT, 'run_id':run['id'], 'manifest_digest':manifest_digest,
               'evidence_digest':digest(view.raw('evidence.json')), 'status':'stored', 'storage':'local-filesystem-unsigned'}
    if (view.read('manifest.json') != manifest or view.read('evidence.json') != evidence or
        view.read('receipt.json') != receipt):
        raise HarnessError('INTEGRITY_MISMATCH')
    return {'mode':'local_demo', 'run_id':run['id'], 'outcome':analysis['outcome'],
            'exit_code':EXIT_CODES[analysis['outcome']], 'commit_sha':commit,
            'manifest_digest':manifest_digest, 'signature_status':'not_signed',
            'input_mode':input_mode, 'scope':'all_tracked_files_at_commit',
            'worktree_checked':input_mode == 'strict_head', 'head_matches_commit':commit == _head(repo)}

def _verify_captured(repo, evidence, *, local_demo=False, commit=None, tenant_id=None, project_id=None, _snapshot=None):
    if not local_demo:
        raise HarnessError('LOCAL_DEMO_FLAG_REQUIRED')
    try:
        context = _context(tenant_id, project_id)
        repo = _repo(repo, clean=False)
        view = _snapshot if _snapshot is not None else _capture_evidence(evidence)
        run = view.read('run.json')
        execution = view.read('execution.json')
        input_mode = _read_input_scope(execution, run.get('commit_sha'))
        if commit is not None:
            _validate_commit(repo, commit)
            if input_mode != 'commit_snapshot':
                raise HarnessError('INPUT_MODE_MISMATCH')
        if input_mode == 'strict_head':
            _ensure_clean(repo)
        result = _verify(repo, evidence, expected_commit=commit, expected_context=context, _snapshot=view)
        if commit is None and result['commit_sha'] != _head(repo):
            raise HarnessError('STALE_HEAD')
        if input_mode == 'strict_head':
            _ensure_clean(repo)
        observed_head = _head(repo)
        if commit is None and result['commit_sha'] != observed_head:
            raise HarnessError('STALE_HEAD')
        result['head_matches_commit'] = result['commit_sha'] == observed_head
        return result
    except HarnessError:
        raise
    except (KeyError, TypeError, ValueError, OSError, RecursionError):
        raise HarnessError('EVIDENCE_INVALID') from None


def verify(repo, evidence, *, local_demo=False, commit=None, tenant_id=None, project_id=None):
    return _verify_captured(repo,evidence,local_demo=local_demo,commit=commit,
        tenant_id=tenant_id,project_id=project_id)


def scan(repo, output, *, parent=None, local_demo=False, with_iron_laws=False, commit=None, tenant_id=None, project_id=None):
    if not local_demo:
        raise HarnessError('LOCAL_DEMO_FLAG_REQUIRED')
    try:
        context = _context(tenant_id, project_id)
        input_mode = 'commit_snapshot' if commit is not None else 'strict_head'
        repo = _repo(repo, clean=commit is None)
        pinned_commit = _validate_commit(repo,commit) if commit is not None else _head(repo)
        output = _safe_path(output)
        if output == repo or repo in output.parents:
            raise HarnessError('OUTPUT_MUST_BE_OUTSIDE_SOURCE_REPOSITORY')
        if output.exists():
            raise HarnessError('OUTPUT_EXISTS')
        requested_commit = commit
        commit = pinned_commit
        analysis = _analysis(repo, commit, with_iron_laws=with_iron_laws, input_mode=input_mode)
        parent_ref, parent_id = None, None
        if parent is not None:
            parent_dir = _safe_path(parent)
            parent_views = {}
            previous = _verify(repo, parent_dir, current=False, depth=1, expected_context=context, _views=parent_views)
            if _recorded_context(parent_views[str(parent_dir)].read('run.json'), parent_views[str(parent_dir)].read('execution.json')) != context:
                raise HarnessError('CONTEXT_MISMATCH')
            if previous['input_mode'] != input_mode:
                raise HarnessError('PARENT_INPUT_MODE_MISMATCH')
            if _detector_profile(parent_views[str(parent_dir)].read('execution.json')) != with_iron_laws:
                raise HarnessError('PARENT_DETECTOR_PROFILE_MISMATCH')
            if previous['outcome'] != 'deny':
                raise HarnessError('PARENT_MUST_BE_DENIED_RUN')
            if previous['commit_sha'] == commit:
                raise HarnessError('NEW_COMMIT_REQUIRED')
            _git(repo, 'merge-base', '--is-ancestor', previous['commit_sha'], commit)
            parent_id = previous['run_id']
            parent_ref = {'directory':str(parent_dir), 'manifest_digest':previous['manifest_digest']}
        run_id = 'RUN-' + uuid.uuid4().hex
        started = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        run, decision, findings, policy = _objects(repo, commit, analysis, run_id, started, parent_id, context)
        output = _new_directory(output)
        _write(output / 'run.json', run)
        _write(output / 'decision.json', decision)
        _write(output / 'policy.json', policy)
        _write(output / 'snapshot.json', analysis['snapshot'])
        _write(output / 'coverage.json', {'scope':'all_tracked_files', 'inventory':analysis['inventory'],
            'supported_files':analysis['supported_files'], 'issues':analysis['issues'], 'parsed':analysis['parsed']})
        execution = {'mode':'local_demo', 'institutional_approval':False,
            'policy_activation':'explicit-local-demo', 'repository_id':digest(str(repo).encode()), 'parent':parent_ref,
            'input_scope':_input_scope(commit,input_mode)}
        if context is not None:
            execution['reference_context'] = _context_object(context)
        if with_iron_laws:
            execution['detectors'] = ['python-local-flow','iron-laws']
            _write(output / 'iron-laws.json', analysis['iron_laws'])
            _write(output / 'iron-laws-policy.json', _external_policy(context))
        _write(output / 'execution.json', execution)
        for i, finding in enumerate(findings, 1):
            _write(output / f'finding-{i:04d}.json', finding)
        _seal(output)
        # Re-read, re-analyze, and validate receipt before exposing allow.
        return verify(repo, output, local_demo=True, commit=requested_commit, tenant_id=tenant_id, project_id=project_id)
    except HarnessError:
        raise
    except (KeyError, TypeError, ValueError, OSError, RecursionError):
        raise HarnessError('RUNTIME_ERROR') from None

class _CaptureLogger:
    def __init__(self): self.calls = []
    def info(self, *args, **kwargs): self.calls.append((args, kwargs))

class _CaptureAudit:
    def __init__(self): self.calls = []
    def record_event(self, *args, **kwargs): self.calls.append((args, kwargs))

def regression():
    """Only trusted, authored constant templates execute, never Git content."""
    outputs, logs, audits = [], [], []
    marker = 'SYNTHETIC_PRIVATE_SENTINEL'
    for template in [BEFORE_SOURCE, AFTER_SOURCE]:
        namespace = {'__builtins__':{}}
        exec(compile(template, '<authored-synthetic-template>', 'exec'), namespace)
        logger, audit = _CaptureLogger(), _CaptureAudit()
        outputs.append(namespace['submit_complaint']({'complaint_text':marker}, 'opaque-server-id', logger, audit))
        logs.append(repr(logger.calls))
        audits.append(audit.calls)
    checks = {'response_preserved':outputs[0] == outputs[1],
              'audit_preserved':audits[0] == audits[1] and len(audits[1]) == 1,
              'body_removed_from_app_log':marker in logs[0] and marker not in logs[1]}
    if not all(checks.values()):
        raise HarnessError('REGRESSION_FAILED')
    return checks

def demo(output, *, with_iron_laws=False):
    output = _new_directory(output)
    repo = output / 'repository'
    repo.mkdir(mode=0o700)
    _git(repo, 'init', '-b', 'main')
    (repo / 'complaints.py').write_text(BEFORE_SOURCE)
    _git(repo, 'add', '--', 'complaints.py')
    _git(repo, 'commit', '-m', 'Synthetic risky logging fixture')
    before = scan(repo, output / 'before', local_demo=True, with_iron_laws=with_iron_laws)
    if before['outcome'] != 'deny':
        raise HarnessError('DEMO_EXPECTED_DENY')
    # Narrow repair: only the just-created constant fixture is eligible.
    if (repo / 'complaints.py').read_text() != BEFORE_SOURCE:
        raise HarnessError('REPAIR_PRECONDITION_FAILED')
    (repo / 'complaints.py').write_text(AFTER_SOURCE)
    _git(repo, 'add', '--', 'complaints.py')
    _git(repo, 'commit', '-m', 'Replace raw complaint logging with allowlisted fields')
    after = scan(repo, output / 'after', parent=output / 'before', local_demo=True, with_iron_laws=with_iron_laws)
    if after['outcome'] != 'allow':
        raise HarnessError('DEMO_EXPECTED_ALLOW')
    report = {'mode':'local_demo', 'before':before, 'after':after, 'regression':regression(),
              'signature_status':'not_signed', 'operational_approval':False}
    _write(output / 'demo-result.json', report)
    return report
