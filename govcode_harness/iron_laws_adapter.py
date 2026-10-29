"""Optional, isolated Iron Laws CLI adapter; never executes scanned sources.

The frozen PoC profile runs AI-112 v2 only. It is an auxiliary logging pattern
check, not a general taint analyzer or a compliance certification.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / '.runtime/iron-laws-poc'
INTEGRATION = ROOT / 'integrations/iron-laws'
COMMIT = '2a820e8cd7ade4c3060381198ed13bf3e6b43146'
VERSION = '1.11.2'
TIMEOUT = 30
MAX_OUTPUT = 2_000_000
CONFIG = b'enabled_rules: [AI-112]\nfail_on: LOW\nexcludes: []\nlimits:\n  max_workers: 1\n  max_wall_seconds: 15\n'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


class AdapterError(Exception):
    pass


def _base_tool():
    return {'name':'iron-laws','version':VERSION,'source_commit':COMMIT,
            'profile':'AI-112-v2-python-poc','config_sha256':digest(CONFIG),'status':'unavailable'}


def _confined_environment(path):
    if path.parent != RUNTIME or not re.fullmatch(r'env-[a-f0-9]{32}', path.name):
        raise AdapterError('IRON_ENVIRONMENT_INVALID')
    for ancestor in [path, *path.parents]:
        if ancestor.is_symlink():
            raise AdapterError('IRON_ENVIRONMENT_INVALID')
    if not path.is_dir():
        raise AdapterError('IRON_TOOL_MISSING')
    return path


def _environment():
    pointer = RUNTIME / 'active.json'
    if pointer.is_symlink():
        raise AdapterError('IRON_ENVIRONMENT_INVALID')
    try:
        if pointer.stat().st_size > 256: raise ValueError()
        value = json.loads(pointer.read_bytes())
        if set(value) != {'environment'} or not isinstance(value['environment'],str): raise ValueError()
        return _confined_environment(RUNTIME / value['environment'])
    except FileNotFoundError:
        raise AdapterError('IRON_TOOL_MISSING') from None
    except (OSError, TypeError, ValueError):
        raise AdapterError('IRON_ENVIRONMENT_INVALID') from None


def measure_identity(environment=None):
    """Recompute installed bytes without importing third-party dependencies."""
    environment = _environment() if environment is None else _confined_environment(environment)
    python = environment / 'bin/python'
    if not python.is_file():
        raise AdapterError('IRON_TOOL_MISSING')
    roots = list((environment / 'lib').glob('python*/site-packages'))
    if len(roots) != 1:
        raise AdapterError('IRON_IDENTITY_INVALID')
    for directory in [environment/'bin',environment/'lib',*roots,roots[0].parent]:
        if directory.is_symlink(): raise AdapterError('IRON_ENVIRONMENT_INVALID')
    entries = [['@installation_id', environment.name],
               ['@pyvenv.cfg', digest((environment / 'pyvenv.cfg').read_bytes())]]
    for path in sorted(roots[0].rglob('*')):
        if path.is_symlink():
            raise AdapterError('IRON_IDENTITY_INVALID')
        if path.is_file():
            entries.append([path.relative_to(roots[0]).as_posix(), digest(path.read_bytes())])
    metadata = roots[0] / 'iron_laws-1.11.2.dist-info/METADATA'
    if not metadata.is_file() or '\nVersion: 1.11.2\n' not in metadata.read_text():
        raise AdapterError('IRON_VERSION_DRIFT')
    tool = _base_tool()
    tool.update(status='verified', environment_sha256=digest(canonical(entries)),
                artifact_sha256=digest(canonical([e for e in entries if e[0].startswith(('iron_laws/','iron_laws-'))])),
                interpreter_sha256=digest(python.resolve().read_bytes()),
                interpreter_version=_invoke(['--version'],ROOT,environment)[1].decode().strip(),
                lock_sha256=digest((INTEGRATION / 'requirements.lock').read_bytes()),
                build_lock_sha256=digest((INTEGRATION / 'build.lock').read_bytes()))
    return tool


def _identity(environment=None):
    environment = _environment() if environment is None else _confined_environment(environment)
    actual = measure_identity(environment)
    baseline=environment / 'identity.json'
    if baseline.is_symlink(): raise AdapterError('IRON_ENVIRONMENT_INVALID')
    expected = json.loads(baseline.read_bytes())
    if actual != expected:
        raise AdapterError('IRON_IDENTITY_DRIFT')
    return actual


def _invoke(args, cwd, environment=None):
    environment = _environment() if environment is None else _confined_environment(environment)
    python = environment / "bin/python"
    # No inherited Python/Git/LLM settings, user home, shell or target hooks.
    env = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
           'HOME':str(cwd),'XDG_CONFIG_HOME':str(cwd), 'PYTHONDONTWRITEBYTECODE':'1',
           'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull}
    process = subprocess.Popen([str(python),'-I','-B',*(['-S'] if args == ['--version'] else []),*args],cwd=cwd,env=env,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    buffers = {process.stdout:bytearray(),process.stderr:bytearray()}
    selector = selectors.DefaultSelector()
    for stream in buffers: selector.register(stream,selectors.EVENT_READ)
    deadline = time.monotonic()+TIMEOUT
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired('iron-laws',TIMEOUT)
            for key,_ in selector.select(min(.2,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk: selector.unregister(key.fileobj);continue
                buffers[key.fileobj].extend(chunk)
                if sum(map(len,buffers.values())) > MAX_OUTPUT:
                    raise AdapterError('IRON_OUTPUT_LIMIT')
        code=process.wait(timeout=max(.01,deadline-time.monotonic()))
        return code,bytes(buffers[process.stdout]),bytes(buffers[process.stderr])
    finally:
        selector.close()
        # Descendants may still own the pipes after the group leader exits.
        # This group belongs to this invocation (start_new_session=True).
        import signal
        try:
            os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close();process.stderr.close()


def _failure(code,tool=None):
    issues=[{'path':'.','line':1,'code':code}]
    report={'format':'govcode-iron-laws-sanitized-v1','profile':'AI-112-v2-python-poc',
            'status':'error','findings':[],'issues':issues}
    return {'tool':tool or _base_tool(),'outcome':'error','findings':[], 'issues':issues,'report':report}


def _normalize(raw, returncode, paths):
    """Strict allow-list projection: no messages, snippets or raw report hashes."""
    try:
        if returncode not in (0,1): raise AdapterError('IRON_INVOCATION_FAILED')
        if raw['schema_version'] != '1.8': raise ValueError()
        summary, execution, metadata = raw['summary'],raw['execution'],raw['metadata']
        violations, diagnostics = raw['violations'],raw['diagnostics']
        coverage=metadata['file_coverage'];counts=coverage['counts']
        if (summary['scan_status'] != 'complete' or execution['scan_status'] != 'complete'
            or execution['tool_version'] != VERSION or execution['files_scanned'] != len(paths)
            or summary['total_files_scanned'] != len(paths) or not paths
            or execution['files_skipped'] or execution['error_diagnostics'] or execution['cross_file_limit_hits']
            or coverage['listed'] != len(paths) or counts.get('analyzed') != len(paths)
            or any(v for k,v in counts.items() if k != 'analyzed') or coverage['unexplained']):
            raise AdapterError('IRON_COVERAGE_INCOMPLETE')
        if not isinstance(violations,list) or not isinstance(diagnostics,list): raise ValueError()
        if summary['total_violations'] != len(violations): raise ValueError()
        if metadata.get('suppressions'): raise AdapterError('IRON_SUPPRESSION_REVIEW')
        findings=[]
        review_finding=False
        for item in violations:
            path,line,rule=item['file_path'],item['line_number'],item['rule_id']
            if path not in paths or type(line) is not int or not 1 <= line <= paths[path]: raise ValueError()
            if not re.fullmatch(r'[A-Z]+-\d{3}',rule): raise ValueError()
            if item['severity'] not in ('CRITICAL','HIGH','MEDIUM','LOW'): raise ValueError()
            if item['confidence'] not in ('CONFIRMED','REVIEW'): raise ValueError()
            review_finding = review_finding or item['confidence']=='REVIEW'
            findings.append({'path':path,'line':line,'severity':item['severity'].lower(),'rule_id':rule,
                             'category':'pii_logging_risk' if rule=='AI-112' else 'external_code_risk',
                             'data_classes':['potential_sensitive_data'] if rule=='AI-112' else []})
        findings.sort(key=lambda f:(f['path'],f['line'],f['rule_id'],f['severity']))
        issues=[]
        for item in diagnostics:
            if item['severity']=='error': raise AdapterError('IRON_COVERAGE_INCOMPLETE')
            issues.append({'path':'.','line':1,'code':'IRON_DIAGNOSTIC_REVIEW'})
        review=(returncode==1 and not findings) or bool(summary['gate_exceeded']) or bool(summary['unverified_rule_language_pairs']) or bool(issues)
        review = review or bool(summary.get('analysis_unknown_rate')) or summary.get('contract_status') not in (None,'met')
        if type(summary['is_passed']) is not bool: raise ValueError()
        if not findings and not summary['is_passed']: review=True
        review = review or review_finding
        outcome='review_required' if review else 'deny' if findings else 'allow'
        if review and not issues: issues=[{'path':'.','line':1,'code':'IRON_TRUST_REVIEW'}]
        report={'format':'govcode-iron-laws-sanitized-v1','profile':'AI-112-v2-python-poc',
                'config_sha256':digest(CONFIG),'schema_version':'1.8','status':'complete',
                'files_analyzed':sorted(paths),'verification':'upstream-structural-consistency',
                'findings':findings,'issues':issues,'outcome':outcome}
        return {'tool':_base_tool(),'outcome':outcome,'findings':findings,'issues':issues,'report':report}
    except AdapterError as error: return _failure(str(error))
    except (KeyError,TypeError,ValueError): return _failure('IRON_REPORT_INVALID')


def analyze(sources):
    tool=_base_tool()
    try:
        if not isinstance(sources,list) or not 1 <= len(sources) <= 100: raise AdapterError('IRON_SOURCE_INVALID')
        paths={};total=0
        for name,source in sources:
            if (not isinstance(name,str) or not isinstance(source,str) or len(name)>240
                or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]*\.py',name)
                or any(p in ('','.','..','.git') or p.startswith('.') for p in name.split('/')) or name in paths):
                raise AdapterError('IRON_SOURCE_INVALID')
            size=len(source.encode());total+=size
            if size>256_000 or total>2_000_000: raise AdapterError('IRON_SOURCE_INVALID')
            paths[name]=max(1,len(source.splitlines()))
        environment=_environment()
        tool=_identity(environment)
        with tempfile.TemporaryDirectory(prefix='govcode-iron-',dir=RUNTIME) as directory:
            home=Path(directory); stage=home/'source';stage.mkdir(mode=0o700)
            for name,source in sources:
                target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(source,encoding='utf-8');target.chmod(0o600)
            config=home/'config.yml';config.write_bytes(CONFIG)
            manifest=home/'files.txt';manifest.write_text('\n'.join(sorted(paths))+'\n')
            # JSON stdout is bounded while streaming; raw report only exists in private temp space.
            code,stdout,_=_invoke(['-c','from iron_laws import main; main()','audit',str(stage),'--config',str(config),'--format','json',
                                  '--build-manifest','file:'+str(manifest),'--require-full-coverage'],home,environment)
            if code not in (0,1): return _failure('IRON_INVOCATION_FAILED',tool)
            raw=json.loads(stdout)
            raw_path=home/'report.json';raw_path.write_bytes(stdout);raw_path.chmod(0o600)
            check,verified,_=_invoke(['-c','from iron_laws import main; main()','evidence','verify',str(raw_path),'--checkout',str(stage),'--json'],home,environment)
            verification=json.loads(verified)
            if check or verification.get('ok') is not True or verification.get('undeterminable') is not False:
                return _failure('IRON_REPORT_UNVERIFIED',tool)
            result=_normalize(raw,code,paths); result['tool']=tool
            if _identity(environment)!=tool: return _failure('IRON_IDENTITY_DRIFT',tool)
            return result
    except AdapterError as error: return _failure(str(error),tool)
    except subprocess.TimeoutExpired: return _failure('IRON_TIMEOUT',tool)
    except (OSError,ValueError,TypeError): return _failure('IRON_RUNTIME_ERROR',tool)
