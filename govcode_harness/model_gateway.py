"""Source-free proposal protocol. Model code is private and never authoritative."""
import hashlib
import http.client
import json
import functools
import re
import socket
import time
from pathlib import PurePosixPath
from urllib.parse import urlsplit
from . import security

MAX_REQUEST = 32000
MAX_RESPONSE = 300000
PROMPT_VERSION = '1'
INSTRUCTIONS = ('Return only govcode-patch-proposal-v1 JSON. Propose a narrow Python logging repair. '
                'Preserve response and audit behavior. No tools, commands, credentials, suppression or test changes. '
                'The request contains metadata only; never invent private source values.')

class ModelError(Exception):
    def __init__(self, code):
        self.code=code
        super().__init__(code)

def _guard(function):
    @functools.wraps(function)
    def guarded(*args,**kwargs):
        try:return function(*args,**kwargs)
        except ModelError:raise
        except (KeyError,TypeError,ValueError,OverflowError,UnicodeError,RecursionError):raise ModelError('FIELDS_INVALID') from None
    return guarded

def _keys(value, keys):
    if type(value) is not dict or set(value)!=set(keys):raise ModelError('FIELDS_INVALID')

def _token(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}',value):raise ModelError('IDENTIFIER_INVALID')
    return value

def _hex(value,size):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{'+str(size)+'}',value):raise ModelError('DIGEST_INVALID')

def source_path(value):
    if type(value) is not str or len(value)>180 or not re.fullmatch(r'[A-Za-z0-9_/-]+\.py',value):raise ModelError('PATH_FORBIDDEN')
    parts=PurePosixPath(value).parts
    if value.startswith('/') or any(p in {'.','..','tests','test','policy','policies','config','configs','skills'} or p.startswith(('.','test_')) for p in parts):raise ModelError('PATH_FORBIDDEN')
    if PurePosixPath(value).name in {'setup.py','conftest.py'}:raise ModelError('PATH_FORBIDDEN')
    return value

def _bounded(value,limit):
    try:raw=security.canonical(value)
    except security.SecurityError:raise ModelError('JSON_INVALID') from None
    if len(raw)>limit:raise ModelError('SIZE_LIMIT')
    return raw

@_guard
def validate_request(request):
    _bounded(request,MAX_REQUEST)
    _keys(request,('context','tenant_id','project_id','run_id','commit_sha','findings','files','safe_log_fields'))
    if request['context']!=security.CONTEXT:raise ModelError('CONTEXT_INVALID')
    for key in ('tenant_id','project_id','run_id'):_token(request[key])
    _hex(request['commit_sha'],40)
    if type(request['files']) is not list or not 1<=len(request['files'])<=20:raise ModelError('FILES_INVALID')
    seen=set()
    for f in request['files']:
        _keys(f,('path','base_sha256'));source_path(f['path']);_hex(f['base_sha256'],64)
        if f['path'] in seen:raise ModelError('PATH_DUPLICATE')
        seen.add(f['path'])
    if type(request['findings']) is not list or len(request['findings'])>100:raise ModelError('FINDINGS_INVALID')
    for f in request['findings']:
        _keys(f,('id','path','line','category','severity'));_token(f['id'])
        if f['path'] not in seen or type(f['line']) is not int or not 1<=f['line']<=100000:raise ModelError('FINDING_INVALID')
        if f['category']!='pii_logging_risk' or f['severity'] not in {'high','critical','medium','low'}:raise ModelError('FINDING_INVALID')
    if type(request['safe_log_fields']) is not list or len(set(request['safe_log_fields']))!=len(request['safe_log_fields']) or set(request['safe_log_fields'])-{'request_id','operation','result_code'}:raise ModelError('LOG_FIELDS_INVALID')
    return json.loads(_bounded(request,MAX_REQUEST))

@_guard
def validate_proposal(proposal, request=None):
    _bounded(proposal,MAX_RESPONSE)
    _keys(proposal,('format','context','tenant_id','project_id','run_id','commit_sha','model','changes'))
    if proposal['format']!='govcode-patch-proposal-v1' or proposal['context']!=security.CONTEXT:raise ModelError('PROPOSAL_INVALID')
    for key in ('tenant_id','project_id','run_id'):_token(proposal[key])
    _hex(proposal['commit_sha'],40)
    _keys(proposal['model'],('id','backend','prompt_version'))
    if type(proposal['model']['id']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}',proposal['model']['id']):raise ModelError('MODEL_INVALID')
    if proposal['model']['backend'] not in {'fixture','ollama'} or proposal['model']['prompt_version']!=PROMPT_VERSION:raise ModelError('MODEL_INVALID')
    if type(proposal['changes']) is not list or not 1<=len(proposal['changes'])<=20:raise ModelError('CHANGES_INVALID')
    seen=set()
    for c in proposal['changes']:
        _keys(c,('path','base_sha256','new_content'));source_path(c['path']);_hex(c['base_sha256'],64)
        if c['path'] in seen:raise ModelError('PATH_DUPLICATE')
        seen.add(c['path'])
        text=c['new_content']
        if type(text) is not str or not text or len(text.encode())>256000:raise ModelError('CONTENT_INVALID')
        # This denylist supplements the source-free input boundary; it is not universal PII detection.
        if re.search(r'(?i)(ignore (?:all |previous |prior )?instructions|system prompt|tool_calls|function_call|<tool|execute (?:shell|command)|noqa|nosec|skipif|pytest\.skip|unittest\.skip|type:\s*ignore|govcode.*(?:ignore|disable)|BEGIN .*PRIVATE KEY|sk-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|https?://|(?:password|api_key|secret|token)\s*=\s*[\x22\x27][^\x22\x27]+)',text):raise ModelError('CONTENT_FORBIDDEN')
    if request:
        for k in ('context','tenant_id','project_id','run_id','commit_sha'):
            if proposal[k]!=request[k]:raise ModelError('SCOPE_MISMATCH')
        files={f['path']:f['base_sha256'] for f in request['files']}
        if any(files.get(c['path'])!=c['base_sha256'] for c in proposal['changes']):raise ModelError('BASE_MISMATCH')
    return json.loads(_bounded(proposal,MAX_RESPONSE))

def proposal_digest(proposal):return hashlib.sha256(_bounded(validate_proposal(proposal),MAX_RESPONSE)).hexdigest()

def _loads(raw):
    def pairs(items):
        value={}
        for k,v in items:
            if k in value:raise ModelError('JSON_DUPLICATE_KEY')
            value[k]=v
        return value
    try:return json.loads(raw,object_pairs_hook=pairs)
    except ModelError:raise
    except Exception:raise ModelError('RESPONSE_INVALID') from None

class FixtureProvider:
    backend='fixture'
    model_id='fixture'
    def __init__(self,proposal):self.proposal=proposal
    def complete(self,request_json,instructions):return _bounded(self.proposal,MAX_RESPONSE)

class _DeadlineSocket(socket.socket):
    def recv_into(self,*args,**kwargs):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError()
        self.settimeout(remaining)
        return super().recv_into(*args,**kwargs)

class OllamaProvider:
    backend='ollama'
    def __init__(self,endpoint,model,approved=False,timeout=5):
        if approved is not True:raise ModelError('TRANSMISSION_DISABLED')
        if type(model) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}',model):raise ModelError('MODEL_INVALID')
        self.model_id=model
        try:
            u=urlsplit(endpoint)
            if u.scheme!='http' or u.hostname not in {'127.0.0.1','::1'} or u.username or u.password or u.path not in {'','/'} or u.query or u.fragment:raise ValueError()
            self.host=u.hostname;self.port=u.port if u.port is not None else 11434
            if not 1<=self.port<=65535:raise ValueError()
        except Exception:raise ModelError('ENDPOINT_FORBIDDEN') from None
        if type(timeout) not in (int,float) or not 0<timeout<=30:raise ModelError('TIMEOUT_INVALID')
        self.timeout=timeout
    def complete(self,request_json,instructions):
        deadline=time.monotonic()+self.timeout
        def connect(address,timeout,source_address=None):
            raw=socket.create_connection(address,timeout,source_address)
            wrapped=_DeadlineSocket(raw.family,raw.type,raw.proto,fileno=raw.detach())
            wrapped.deadline=deadline
            wrapped.settimeout(max(.001,deadline-time.monotonic()))
            return wrapped
        conn=http.client.HTTPConnection(self.host,self.port,timeout=self.timeout)
        conn._create_connection=connect
        body=_bounded({'model':self.model_id,'messages':[{'role':'system','content':instructions},{'role':'user','content':request_json.decode()}],'format':'json','stream':False},MAX_RESPONSE)
        try:
            conn.request('POST','/api/chat',body,{'Content-Type':'application/json'})
            response=conn.getresponse()
            if response.status!=200:raise ModelError('PROVIDER_HTTP_ERROR')
            raw=response.read(MAX_RESPONSE+1)
            if len(raw)>MAX_RESPONSE:raise ModelError('SIZE_LIMIT')
            envelope=_loads(raw)
            allowed={'model','created_at','message','done','done_reason','total_duration','load_duration','prompt_eval_count','prompt_eval_duration','eval_count','eval_duration','logprobs'}
            if type(envelope) is not dict or set(envelope)-allowed or envelope.get('done') is not True:raise ModelError('RESPONSE_INVALID')
            message=envelope['message']
            if set(message)-{'role','content'} or message.get('role')!='assistant':raise ModelError('RESPONSE_INVALID')
            return message['content']
        except ModelError:raise
        except TimeoutError:raise ModelError('PROVIDER_TIMEOUT') from None
        except Exception:raise ModelError('PROVIDER_FAILED') from None
        finally:conn.close()

def propose(request,provider):
    request=validate_request(request)
    if type(provider) not in (FixtureProvider,OllamaProvider):raise ModelError('PROVIDER_FORBIDDEN')
    raw=provider.complete(_bounded(request,MAX_REQUEST),INSTRUCTIONS)
    if type(raw) not in (str,bytes) or len(raw)>MAX_RESPONSE:raise ModelError('SIZE_LIMIT')
    proposal=validate_proposal(_loads(raw),request)
    if proposal['model']!={'id':provider.model_id,'backend':provider.backend,'prompt_version':PROMPT_VERSION}:raise ModelError('MODEL_MISMATCH')
    return proposal
