"""Independently signed, synthetic sandbox repair verification.

The original repository is read only. Candidate source stays in the private
sandbox; receipts contain metadata only. Arbitrary project tests never run.
"""
from datetime import datetime,timezone
import ast
import functools
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import sysconfig
import time
import tempfile

from . import security,snapshot,runtime,detector
from .model_gateway import validate_proposal,proposal_digest,ModelError

class PatchError(Exception):
    def __init__(self,code):self.code=code;super().__init__(code)

def _public(function):
    @functools.wraps(function)
    def guarded(*args,**kwargs):
        try:return function(*args,**kwargs)
        except PatchError:raise
        except (ModelError,security.SecurityError,snapshot.SnapshotError,runtime.HarnessError) as error:raise PatchError(error.code) from None
        except (OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError):raise PatchError('PATCH_ERROR') from None
    return guarded

def _safe(path):
    try:return runtime._safe_path(path)
    except runtime.HarnessError as e:raise PatchError(e.code) from None

def _time(value):
    try:
        parsed=datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        return parsed
    except Exception:raise PatchError('APPROVAL_TIME_INVALID') from None

def _approval(envelope,trust,proposal,tenant,project):
    try:payload=security.verify(envelope,trust,'approver',tenant,project)
    except security.SecurityError as e:raise PatchError(e.code) from None
    expected={'kind','context','tenant_id','project_id','actor_id','proposal_digest','base_commit','run_id','paths','created_at','expires_at','event_id'}
    if set(payload)!=expected or payload['kind']!='patch_approval':raise PatchError('APPROVAL_INVALID')
    try:security.identifier(payload['event_id'])
    except security.SecurityError:raise PatchError('APPROVAL_INVALID') from None
    now=datetime.now(timezone.utc);created=_time(payload['created_at']);expires=_time(payload['expires_at'])
    if not created<=now<expires or expires<=created or (expires-created).total_seconds()>86400:raise PatchError('APPROVAL_EXPIRED')
    if payload['proposal_digest']!=proposal_digest(proposal) or payload['base_commit']!=proposal['commit_sha'] or payload['run_id']!=proposal['run_id']:raise PatchError('APPROVAL_BINDING_MISMATCH')
    if payload['paths']!=sorted(c['path'] for c in proposal['changes']):raise PatchError('APPROVAL_PATHS_MISMATCH')
    for key in trust['keys'].values():
        if key.get('actor_id')==payload['actor_id'] and key.get('tenant_id')==tenant and key.get('project_id')==project and 'author' in key.get('roles',[]):raise PatchError('INDEPENDENT_APPROVER_REQUIRED')
    return payload

def _pin(repo,proposal):
    try:
        runtime._repo(repo)
        if runtime._head(repo)!=proposal['commit_sha']:raise PatchError('BASE_COMMIT_CHANGED')
        data=snapshot.collect(repo,proposal['commit_sha'])
    except (runtime.HarnessError,snapshot.SnapshotError) as e:raise PatchError(e.code) from None
    files={f['path']:f['sha256'] for f in data['files']}
    for change in proposal['changes']:
        if files.get(change['path'])!=change['base_sha256']:raise PatchError('BASE_DIGEST_CHANGED')
        path=_safe(repo/change['path'])
        try:
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=change['base_sha256']:raise PatchError('BASE_WORKTREE_CHANGED')
        except OSError:raise PatchError('BASE_WORKTREE_CHANGED') from None
    return data

def _supported_candidate(source):
    """Bounded reference API subset; no arbitrary top-level or resource work."""
    try:
        tree=ast.parse(source)
        nodes=list(ast.walk(tree))
        if len(nodes)>160 or len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):return False
        function=tree.body[0]
        if function.name!='submit_complaint' or function.decorator_list or function.returns or function.type_comment:return False
        args=function.args
        if [a.arg for a in args.args]!=['request_body','request_id','logger','audit'] or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or args.defaults:return False
        if any(a.annotation for a in args.args):return False
        if not 1<=len(function.body)<=8 or any(not isinstance(n,(ast.Expr,ast.Return)) for n in function.body):return False
        allowed=(ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Expr,ast.Return,ast.Call,ast.Attribute,ast.Name,ast.Load,ast.Constant,ast.Dict,ast.keyword)
        for node in nodes:
            if not isinstance(node,allowed):return False
            if isinstance(node,ast.Constant) and (type(node.value) not in (str,int,bool,type(None)) or len(str(node.value))>512):return False
            if isinstance(node,ast.Name) and node.id not in {'request_body','request_id','logger','audit'}:return False
            if isinstance(node,ast.Attribute) and not (isinstance(node.value,ast.Name) and (node.value.id,node.attr) in {('logger','info'),('audit','record_event')}):return False
            if isinstance(node,ast.Call) and (not isinstance(node.func,ast.Attribute) or any(k.arg is None for k in node.keywords)):return False
        return True
    except (SyntaxError,ValueError,TypeError,RecursionError):return False

def _quote(path):
    # Scheme literals, not shell escaping. Paths are trusted resolved roots.
    return json.dumps(str(Path(path).resolve()))

def sandbox_profile(directory):
    """Deny network and host data; allow only explicit runtime/system roots."""
    directory=Path(directory).resolve()
    executable=Path(sys.executable).resolve()
    stdlib=Path(sysconfig.get_path('stdlib')).resolve()
    roots={stdlib,executable.parent.parent/'lib',Path('/System/Library'),Path('/usr/lib')}
    reads=' '.join('(subpath '+_quote(p)+')' for p in sorted(roots,key=str))
    return '\n'.join(['(version 1)','(deny default)','(allow sysctl-read)',
        '(allow process-exec (literal '+_quote(executable)+'))',
        '(allow file-read* '+reads+' (literal '+_quote(executable)+') (literal "/dev/null") (literal "/dev/urandom"))',
        # dyld needs the root directory itself, never its descendants. Owned
        # canary tests prove sibling file reads/writes and network remain denied.
        '(allow file-read-data (literal "/"))',
        '(allow file-read-metadata)',
        '(allow file-read* file-write* (subpath '+_quote(directory)+'))'])

# This fixed harness runs only after a clean static check. Candidate namespaces
# have no importer, filesystem API, subprocess API or ambient environment.
_CHILD = r'''
import json,sys
source=open(sys.argv[1],encoding='utf-8').read()
class Logger:
 def __init__(self):self.calls=[]
 def info(self,*args,**kwargs):self.calls.append((args,kwargs))
class Audit:
 def __init__(self):self.calls=[]
 def record_event(self,*args,**kwargs):self.calls.append((args,kwargs))
namespace={'__builtins__':{'str':str,'dict':dict,'len':len,'int':int,'bool':bool}}
exec(compile(source,'<private-candidate>','exec'),namespace)
logger,audit=Logger(),Audit()
marker='SYNTHETIC_PRIVATE_SENTINEL'
result=namespace['submit_complaint']({'complaint_text':marker},'opaque-server-id',logger,audit)
checks={'functional':result=={'status':'received','request_id':'opaque-server-id'},'audit':audit.calls==[(('complaint_received',),{'request_id':'opaque-server-id'})],'privacy':bool(logger.calls) and marker not in repr(logger.calls),'isolation':True}
print(json.dumps(checks,sort_keys=True))
'''

def _limits():
    resource.setrlimit(resource.RLIMIT_CPU,(3,3))
    resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_NPROC,(16,16))
    # macOS rejects DATA/AS/RSS caps; the parent also enforces a sampled RSS
    # ceiling. Non-macOS implementations use a hard address-space limit.
    if sys.platform!='darwin':resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))

def _run_isolated(directory,code,args=(),timeout=6):
    """No fallback to ordinary execution when OS isolation is unavailable."""
    if sys.platform!='darwin' or not Path('/usr/bin/sandbox-exec').is_file():return {'error':'ISOLATION_UNAVAILABLE'}
    proc=None
    try:
        command=['/usr/bin/sandbox-exec','-p',sandbox_profile(directory),str(Path(sys.executable).resolve()),'-I','-S','-B','-c',code,*map(str,args)]
        env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(directory),'TMPDIR':str(directory)}
        proc=subprocess.Popen(command,cwd=directory,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=_limits)
        deadline=time.monotonic()+timeout;raw=bytearray();total=0
        with selectors.DefaultSelector() as selector:
            for stream in (proc.stdout,proc.stderr):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic()>=deadline:return {'error':'ISOLATION_TIMEOUT'}
                if proc.poll() is None:
                    usage=subprocess.run(['/bin/ps','-p',str(proc.pid),'-o','rss='],capture_output=True,timeout=1,env={'PATH':'/usr/bin:/bin'})
                    if usage.returncode==0 and usage.stdout.strip() and int(usage.stdout.strip())>256*1024:return {'error':'ISOLATION_MEMORY_LIMIT'}
                for key,_ in selector.select(min(.1,max(.001,deadline-time.monotonic()))):
                    chunk=os.read(key.fileobj.fileno(),4096)
                    if not chunk:selector.unregister(key.fileobj);continue
                    total+=len(chunk)
                    if total>8192:return {'error':'ISOLATION_OUTPUT_LIMIT'}
                    if key.fileobj is proc.stdout:raw.extend(chunk)
            if proc.wait(timeout=max(.001,deadline-time.monotonic())):return {'error':'ISOLATED_CHILD_FAILED'}
        return {'raw':bytes(raw)}
    except (OSError,subprocess.SubprocessError,ValueError):return {'error':'ISOLATION_UNAVAILABLE'}
    finally:
        if proc is not None:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            for stream in (proc.stdout,proc.stderr):
                if stream:stream.close()
            proc.wait()

def isolated_checks(directory):
    result=_run_isolated(directory,_CHILD,[Path(directory)/'complaints.py'])
    if 'error' in result:return result
    try:
        checks=json.loads(result['raw'])
        if set(checks)!={'functional','audit','privacy','isolation'} or any(type(v) is not bool for v in checks.values()):raise ValueError()
        return checks
    except Exception:return {'error':'ISOLATION_RESULT_INVALID'}

@_public
def apply_proposal(repo,proposal,approval,trust,output,*,tenant_id,project_id,executor=None):
    """Return a source-free receipt; injected executors are always mock checks."""
    try:proposal=validate_proposal(proposal)
    except ModelError as e:raise PatchError(e.code) from None
    if proposal['tenant_id']!=tenant_id or proposal['project_id']!=project_id:raise PatchError('SCOPE_MISMATCH')
    repo=_safe(repo);output=_safe(output)
    if output==repo or repo in output.parents or output in repo.parents:raise PatchError('OUTPUT_SCOPE_INVALID')
    if output.exists():raise PatchError('OUTPUT_EXISTS')
    payload=_approval(approval,trust,proposal,tenant_id,project_id)
    data=_pin(repo,proposal)
    if not output.parent.is_dir():raise PatchError('OUTPUT_PARENT_REQUIRED')
    ledger=_safe(Path(tempfile.gettempdir())/('govcode-patch-approvals-'+str(os.getuid())))
    ledger.mkdir(mode=0o700,exist_ok=True)
    if not ledger.is_dir() or ledger.stat().st_uid!=os.getuid() or ledger.stat().st_mode & 0o077:raise PatchError('REPLAY_STORE_UNSAFE')
    signer=trust['keys'][approval['key_id']]['public_key']
    replay_key=hashlib.sha256(security.canonical([tenant_id,project_id,payload['actor_id'],signer,payload['event_id']])).hexdigest()
    try:
        fd=os.open(ledger/replay_key,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    except FileExistsError:raise PatchError('APPROVAL_REPLAY') from None
    output.mkdir(mode=0o700,exist_ok=False)
    receipt={'format':'govcode-patch-receipt-v1','context':security.CONTEXT,'tenant_id':tenant_id,'project_id':project_id,'run_id':proposal['run_id'],'proposal_digest':proposal_digest(proposal),'model':proposal['model'],'base_commit':proposal['commit_sha'],'candidate_commit':None,'approval_digest':hashlib.sha256(security.canonical(approval)).hexdigest(),'paths':[c['path'] for c in proposal['changes']],'checks':{'static':False,'functional':False,'audit':False,'privacy':False,'isolation':False},'sandbox_verified':False,'executor':'mock' if executor else 'os_sandbox','memory_limit_mode':'parent_sampled_rss_256MiB','verdict':'undeterminable','operational_approval':False}
    def finish(reason=None):
        _pin(repo,proposal)
        if reason:receipt['reason_code']=reason
        path=output/'receipt.json'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(security.canonical(receipt))
        return json.loads(security.canonical(receipt))
    # Only the explicit complaint API reference contract is executable.
    if data['issues'] or [f['path'] for f in data['files']]!=['complaints.py'] or receipt['paths']!=['complaints.py']:return finish('PROJECT_CONTRACT_UNSUPPORTED')
    sandbox=output/'sandbox';sandbox.mkdir(mode=0o700)
    for name,source in data['sources']:
        (sandbox/name).write_text(source,encoding='utf-8');os.chmod(sandbox/name,0o600)
    snapshot.run_git(sandbox,'init','-b','main')
    snapshot.run_git(sandbox,'add','--','complaints.py');snapshot.run_git(sandbox,'commit','-m','Synthetic pinned reference base')
    for c in proposal['changes']:(sandbox/c['path']).write_text(c['new_content'],encoding='utf-8')
    if not _supported_candidate(proposal['changes'][0]['new_content']):return finish('CANDIDATE_CONTRACT_UNSUPPORTED')
    analysis=detector.analyze(proposal['changes'][0]['new_content'],'complaints.py')
    if not analysis['parsed'] or analysis['findings'] or analysis['issues']:
        receipt['verdict']='failed';return finish('STATIC_RECHECK_BLOCKED')
    snapshot.run_git(sandbox,'add','--','complaints.py');snapshot.run_git(sandbox,'commit','--allow-empty','-m','Independently approved synthetic repair')
    candidate=snapshot.run_git(sandbox,'rev-parse','HEAD').decode().strip();receipt['candidate_commit']=candidate
    scan=runtime.scan(sandbox,output/'static-recheck',local_demo=True,tenant_id=tenant_id,project_id=project_id)
    receipt['checks']['static']=scan['outcome']=='allow'
    if not receipt['checks']['static']:
        receipt['verdict']='failed';return finish('STATIC_RECHECK_BLOCKED')
    try:checks=(executor or isolated_checks)(sandbox)
    except Exception:checks={'error':'EXECUTOR_FAILED'}
    if type(checks) is not dict:checks={'error':'EXECUTOR_FAILED'}
    for key in ('functional','audit','privacy','isolation'):receipt['checks'][key]=checks.get(key) is True
    receipt['sandbox_verified']=executor is None and receipt['checks']['isolation'] and 'error' not in checks
    if not receipt['sandbox_verified']:return finish('MOCK_EXECUTOR' if executor else checks.get('error','ISOLATION_UNVERIFIED'))
    receipt['verdict']='verified' if all(receipt['checks'].values()) else 'failed'
    if snapshot.run_git(sandbox,'rev-parse','HEAD').decode().strip()!=candidate or hashlib.sha256((sandbox/'complaints.py').read_bytes()).hexdigest()!=hashlib.sha256(proposal['changes'][0]['new_content'].encode()).hexdigest():raise PatchError('CANDIDATE_CHANGED')
    return finish()
