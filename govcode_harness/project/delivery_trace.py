"""Bounded document/trace inspection. Structural success is never fulfillment."""
from collections import deque
import hashlib
import json
from pathlib import PurePosixPath
import re

from .. import security
from . import contracts as c

CHECKS=('trace_integrity','artifact_structure','result_binding')
RANK={'pass':0,'fail':1,'review_required':2,'error':3}
SHA=re.compile(r'[a-f0-9]{64}')
COMMIT=re.compile(r'[a-f0-9]{40}')
INDEX_KEYS={'kind','schema_version','context','tenant_id','project_id','operational_approval','artifacts','requirements','traces'}
MANIFEST_KEYS={'format','tenant_id','project_id','commit_sha','index_path','index_digest','index_canonical_digest','inventory','artifacts','total_bytes','worktree_checked','operational_approval'}
ATTESTATION_KEYS={'kind','schema_version','context','tenant_id','project_id','operational_approval','actor_id','event_id','created_at','not_before','expires_at','commit_sha','artifact_manifest_digest','requirement_ref','result_artifact_ref','check_id','adapter_id','tool_digest','result'}


class DeliveryTraceError(ValueError):
    def __init__(self,code='ARTIFACT_INSPECTION_INVALID'):
        self.code=code
        super().__init__(code)


def _require(condition,code='ARTIFACT_CAPTURE_INVALID'):
    if not condition:raise DeliveryTraceError(code)


def _clone(value):
    return json.loads(security.canonical(value))


def _ref(value):
    return dict(kind=value['kind'],id=value['id'],version=value['version'],digest=c.digest(value))


def _scope(value,scope):
    return (value['tenant_id'],value['project_id'])==scope


def _path(value):
    return (type(value) is str and bool(value) and not value.startswith('/') and '\\' not in value
            and not re.match(r'^[A-Za-z]:',value) and all(p not in ('','.','..','.git') for p in value.split('/'))
            and not any(ord(ch)<32 or ord(ch)==127 for ch in value))


def _capture(collected):
    """Recheck detached private capture; it is not a signed source of authority."""
    _require(type(collected) is dict and set(collected)=={'manifest','index','contents'})
    manifest,index=_clone(collected['manifest']),_clone(collected['index'])
    contents=collected['contents']
    _require(set(manifest)==MANIFEST_KEYS and set(index)==INDEX_KEYS)
    _require(manifest['format']=='govcode-project-artifact-snapshot-v1')
    _require(type(manifest['commit_sha']) is str and COMMIT.fullmatch(manifest['commit_sha']) is not None)
    _require(manifest['worktree_checked'] is False and manifest['operational_approval'] is False)
    _require(index['kind']=='project_artifact_index' and index['schema_version']=='1' and index['context']==security.CONTEXT and index['operational_approval'] is False)
    scope=(manifest['tenant_id'],manifest['project_id'])
    for name in scope:security.identifier(name)
    _require(_scope(index,scope))
    _require(manifest['index_canonical_digest']==c.digest(index),'INDEX_CAPTURE_MISMATCH')
    _require(_path(manifest['index_path']) and PurePosixPath(manifest['index_path']).suffix.lower()=='.json')
    for field,limit in [('requirements',1000),('artifacts',100),('traces',10000)]:
        _require(type(index[field]) is list and len(index[field])<=limit)
    _require(bool(index['requirements']) and bool(index['artifacts']))
    reqs=[c.validate(v) for v in index['requirements']]
    arts=[c.validate(v) for v in index['artifacts']]
    traces=[c.validate(v) for v in index['traces']]
    _require(all(v['kind']==kind and _scope(v,scope) for kind,values in [('requirement_spec',reqs),('artifact_ref',arts),('trace_link',traces)] for v in values))
    names=[v['id'] for v in reqs+arts]
    _require(len(names)==len(set(names)),'ARTIFACT_ID_DUPLICATE')
    _require(len({v['id'] for v in traces})==len(traces),'TRACE_ID_DUPLICATE')
    paths=[v['relative_path'] for v in arts]
    _require(len(paths)==len(set(paths)) and all(_path(p) for p in paths) and manifest['index_path'] not in paths)
    _require(type(contents) is dict and set(contents)=={a['id'] for a in arts})
    _require(type(manifest['inventory']) is list and len(manifest['inventory'])<=100)
    inv={}
    for row in manifest['inventory']:
        _require(type(row) is dict and set(row)=={'path','sha256','size_bytes'})
        _require(_path(row['path']) and row['path'] not in inv)
        _require(type(row['sha256']) is str and SHA.fullmatch(row['sha256']) is not None)
        _require(type(row['size_bytes']) is int and 0<=row['size_bytes']<=256000)
        inv[row['path']]=row
    _require(type(manifest['total_bytes']) is int and manifest['total_bytes']==sum(v['size_bytes'] for v in inv.values()) and manifest['total_bytes']<=2000000)
    _require(manifest['index_path'] in inv and inv[manifest['index_path']]['sha256']==manifest['index_digest'])
    _require(type(manifest['artifacts']) is list and len(manifest['artifacts'])==len(arts))
    rows={}
    for row in manifest['artifacts']:
        _require(type(row) is dict and set(row)=={'artifact_ref','format','status','reason_codes'})
        art=row['artifact_ref'];_require(type(art) is dict and art.get('id') not in rows)
        _require(row['format'] in ('json','markdown','unsupported') and row['status'] in ('captured','unsupported','encoding_error'))
        _require(type(row['reason_codes']) is list and all(type(v) is str for v in row['reason_codes']))
        rows[art['id']]=row
    for art in arts:
        name,path=art['id'],art['relative_path']
        _require(name in rows and rows[name]['artifact_ref']==art)
        raw=contents[name]
        _require(type(raw) is bytes and len(raw)<=256000)
        _require(hashlib.sha256(raw).hexdigest()==art['content_digest'],'ARTIFACT_CAPTURE_MISMATCH')
        _require(path in inv and inv[path]['sha256']==art['content_digest'] and inv[path]['size_bytes']==len(raw))
        suffix=PurePosixPath(path).suffix.lower()
        fmt={'.md':'markdown','.json':'json'}.get(suffix,'unsupported')
        try:raw.decode('utf-8');valid_utf8=True
        except UnicodeError:valid_utf8=False
        status='unsupported' if fmt=='unsupported' else ('captured' if valid_utf8 else 'encoding_error')
        _require(rows[name]['format']==fmt and rows[name]['status']==status,'ARTIFACT_CLASSIFICATION_MISMATCH')
    return manifest,index,{k:bytes(v) for k,v in contents.items()},reqs,arts,traces,rows


def _markdown(text):
    """Recognize a deliberately narrow Markdown heading structure, no HTML execution."""
    levels=[];fence=None;html=False
    for line in text.splitlines():
        start=re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$',line)
        if start:
            token=start.group(1)
            if fence is None:fence=(token[0],len(token))
            elif token[0]==fence[0] and len(token)>=fence[1] and not start.group(2).strip():fence=None
            continue
        if fence is not None:continue
        if re.search(r'<(?:!--|/?[A-Za-z][A-Za-z0-9-]*(?:\s|/?>|$))',line):html=True
        heading=re.match(r'^ {0,3}(#{1,6})[ \t]+\S',line)
        if heading:levels.append(len(heading.group(1)))
    valid=bool(levels) and levels[0]==1 and levels.count(1)==1 and all(right<=left+1 for left,right in zip(levels,levels[1:])) and fence is None
    return valid,html


def inspect(collected,*,now,expected_requirements=None,result_receipts=(),trust=None,allowed_result_tools=None):
    """Inspect a private capture and optional caller-owned authorities, not a gate.

    Callers must recapture and reverify signed pack/profile inputs for later stages.
    This unsigned report cannot substitute for those original inputs.
    """
    try:
        current=c.timestamp(now)
        manifest,index,contents,reqs,arts,traces,rows=_capture(collected)
        if expected_requirements is not None:
            _require(type(expected_requirements) in (list,tuple) and 0<len(expected_requirements)<=1000,'REQUIREMENT_AUTHORITY_MISMATCH')
            expected=[c.validate(r) for r in _clone(list(expected_requirements))]
            _require(all(r['kind']=='requirement_spec' and _scope(r,(manifest['tenant_id'],manifest['project_id'])) for r in expected),'REQUIREMENT_AUTHORITY_MISMATCH')
            _require(len(expected)==len(reqs) and {r['id']:r for r in expected}=={r['id']:r for r in reqs} and len({r['id'] for r in expected})==len(expected),'REQUIREMENT_AUTHORITY_MISMATCH')
    except DeliveryTraceError:raise
    except (security.SecurityError,c.ContractError) as error:raise DeliveryTraceError(error.code) from None
    except Exception:raise DeliveryTraceError() from None
    statuses={name:'pass' for name in CHECKS};findings=[]
    def mark(check,status,code,name=None):
        if RANK[status]>RANK[statuses[check]]:statuses[check]=status
        row=dict(check_id=check,code=code)
        if name is not None:row['entity_id']=name
        if row not in findings:findings.append(row)
    entities={v['id']:v for v in reqs+arts}
    refs={k:_ref(v) for k,v in entities.items()}
    edges={k:set() for k in entities};deps={k:set() for k in entities};seen_edges=set()
    allowed={('requirement_spec','design'):'implements',('design','test_plan'):'verifies',('test_plan','test_result'):'reports',('test_result','review_record'):'reviews'}
    def entity_kind(value):return value.get('artifact_kind',value['kind'])
    for link in traces:
        left,right=link['from_ref'],link['to_ref']
        a,b=left['id'],right['id']
        if a not in entities or b not in entities or left!=refs.get(a) or right!=refs.get(b):
            mark('trace_integrity','error','TRACE_REFERENCE_INVALID',link['id']);continue
        signature=(a,b,link['relation'])
        if signature in seen_edges:mark('trace_integrity','error','TRACE_EDGE_DUPLICATE',link['id']);continue
        seen_edges.add(signature)
        leftkind,rightkind=entity_kind(entities[a]),entity_kind(entities[b])
        if link['relation']=='depends_on':
            if leftkind!=rightkind:mark('trace_integrity','error','TRACE_RELATION_INVALID',link['id'])
            else:deps[a].add(b)
        elif allowed.get((leftkind,rightkind))!=link['relation']:
            mark('trace_integrity','error','TRACE_RELATION_INVALID',link['id'])
        else:edges[a].add(b)
    indegree={k:0 for k in deps}
    for targets in deps.values():
        for name in targets:indegree[name]+=1
    queue=deque(k for k,v in indegree.items() if not v);visited=0
    while queue:
        name=queue.popleft();visited+=1
        for target in deps[name]:
            indegree[target]-=1
            if indegree[target]==0:queue.append(target)
    if visited!=len(deps):mark('trace_integrity','error','TRACE_DEPENDENCY_CYCLE')
    # A required artifact must participate in a whole forward chain, rather than
    # borrowing completion from an unrelated branch of the same requirement.
    reverse_edges={name:set() for name in entities}
    for source,targets in edges.items():
        for target in targets:reverse_edges[target].add(source)
    reaches_review={name for name,value in entities.items() if value.get('artifact_kind')=='review_record'}
    queue=deque(reaches_review)
    while queue:
        for source in reverse_edges[queue.popleft()]:
            if source not in reaches_review:reaches_review.add(source);queue.append(source)
    reachable={}
    for req in reqs:
        found=set();queue=deque([req['id']])
        while queue:
            for target in edges[queue.popleft()]:
                if target not in found:found.add(target);queue.append(target)
        reachable[req['id']]=found
        if not any(entities[name].get('artifact_kind')=='review_record' for name in found):mark('trace_integrity','fail','TRACE_CHAIN_INCOMPLETE',req['id'])
        for name in req['required_artifacts']:
            if name not in found or name not in entities or entities[name]['kind']!='artifact_ref':
                mark('trace_integrity','fail','REQUIRED_ARTIFACT_MISSING',req['id'])
            elif name not in reaches_review:
                mark('trace_integrity','fail','REQUIRED_ARTIFACT_TRACE_INCOMPLETE',req['id'])
    for art in arts:
        name=art['id'];row=rows[name];raw=contents[name]
        if row['status']!='captured':mark('artifact_structure','review_required','ARTIFACT_UNSUPPORTED' if row['status']=='unsupported' else 'ARTIFACT_ENCODING_UNSUPPORTED',name);continue
        text=raw.decode('utf-8')
        if not text.strip():mark('artifact_structure','fail','ARTIFACT_EMPTY',name);continue
        if row['format']=='markdown':
            valid,html=_markdown(text)
            if not valid:mark('artifact_structure','fail','MARKDOWN_STRUCTURE_INVALID',name)
            if html:mark('artifact_structure','review_required','MARKDOWN_HTML_UNSUPPORTED',name)
        else:
            try:
                from .artifact_snapshot import parse_json
                value=parse_json(raw)
                if type(value) not in (dict,list):mark('artifact_structure','fail','JSON_DOCUMENT_STRUCTURE_INVALID',name)
            except Exception:mark('artifact_structure','error','ARTIFACT_JSON_INVALID',name)
    scope=(manifest['tenant_id'],manifest['project_id']);manifest_digest=c.digest(manifest)
    if expected_requirements is None:mark('trace_integrity','review_required','REQUIREMENT_AUTHORITY_NOT_CHECKED')
    tools=None
    if allowed_result_tools is not None:
        try:
            tools=_clone(allowed_result_tools)
            _require(type(tools) is dict and len(tools)<=1000)
            for name,value in tools.items():
                security.identifier(name)
                _require(type(value) is dict and set(value)=={'adapter_id','tool_digest'})
                security.identifier(value['adapter_id'])
                _require(type(value['tool_digest']) is str and SHA.fullmatch(value['tool_digest']) is not None)
        except Exception:
            mark('result_binding','error','RESULT_TOOL_AUTHORITY_INVALID');tools=None
    if trust is not None:
        try:
            trust=_clone(trust)
            _require(type(trust) is dict and trust.get('context')==security.CONTEXT and type(trust.get('keys')) is dict)
        except Exception:mark('result_binding','error','RESULT_TRUST_INVALID');trust=None
    try:
        _require(type(result_receipts) in (tuple,list) and len(result_receipts)<=1000)
        receipts=_clone(list(result_receipts))
    except Exception:
        receipts=[];mark('result_binding','error','RESULT_RECEIPTS_INVALID')
    events=set();pairs=set();verified=set()
    for envelope in receipts:
        name=None
        try:
            _require(type(envelope) is dict and set(envelope)=={'format','key_id','payload','signature'} and envelope['format']=='govcode-signed-v1')
            value=envelope['payload']
            _require(type(value) is dict and set(value)==ATTESTATION_KEYS)
            _require(value['kind']=='artifact_test_attestation' and value['schema_version']=='1' and value['context']==security.CONTEXT and value['operational_approval'] is False)
            _require(_scope(value,scope))
            for key in ('event_id','actor_id','check_id','adapter_id'):security.identifier(value[key])
            _require(value['event_id'] not in events);events.add(value['event_id'])
            _require(value['commit_sha']==manifest['commit_sha'] and value['artifact_manifest_digest']==manifest_digest)
            _require(type(value['tool_digest']) is str and SHA.fullmatch(value['tool_digest']) is not None)
            start,created,end=(c.timestamp(value[f]) for f in ('not_before','created_at','expires_at'))
            _require(start<=created<=current<end)
            requirement=value['requirement_ref'];result=value['result_artifact_ref']
            _require(type(requirement) is dict and type(result) is dict)
            name=requirement.get('id');result_id=result.get('id')
            _require(name in entities and entities[name]['kind']=='requirement_spec' and requirement==refs[name])
            _require(result_id in reachable[name] and result==refs[result_id] and entities[result_id].get('artifact_kind')=='test_result')
            _require(value['check_id'] in entities[name]['check_refs'])
            pair=(name,value['check_id']);_require(pair not in pairs);pairs.add(pair)
            _require(value['result'] in ('pass','fail'))
            if tools is None:mark('result_binding','review_required','RESULT_TOOL_AUTHORITY_NOT_PROVIDED',name)
            else:_require(tools.get(value['check_id'])==dict(adapter_id=value['adapter_id'],tool_digest=value['tool_digest']))
            if trust is None:mark('result_binding','review_required','RESULT_TRUST_NOT_PROVIDED',name)
            else:security.verify(envelope,trust,'operator',*scope)
            if tools is not None and trust is not None:
                verified.add(pair)
                if value['result']=='fail':mark('result_binding','fail','TEST_EXECUTION_FAILED',name)
        except Exception:mark('result_binding','error','TEST_ATTESTATION_INVALID',name if type(name) is str and name in entities else None)
    for req in reqs:
        if not req['check_refs']:mark('result_binding','review_required','NO_TRUSTED_TEST_CHECK',req['id'])
        for name in req['check_refs']:
            if (req['id'],name) not in verified:mark('result_binding','review_required','TEST_ATTESTATION_REQUIRED',req['id'])
    overall=max(statuses.values(),key=RANK.get)
    outcome={'pass':'checks_passed','fail':'defects_found','review_required':'review_required','error':'error'}[overall]
    report=dict(kind='project_artifact_inspection',schema_version='1',context=security.CONTEXT,tenant_id=scope[0],project_id=scope[1],commit_sha=manifest['commit_sha'],input_mode='commit_snapshot',worktree_checked=False,artifact_manifest_digest=manifest_digest,requirements_evaluated=False,operational_approval=False,applicability_evaluated=False,stage_gate_evaluated=False,requirement_authority='matched_external_set' if expected_requirements is not None else 'not_checked',outcome=outcome,checks=[dict(check_id=k,status=statuses[k]) for k in CHECKS],findings=sorted(findings,key=lambda f:(f['check_id'],f.get('entity_id',''),f['code'])),counts=dict(requirements=len(reqs),artifacts=len(arts),traces=len(traces)),next_actions=[dict(entity_id=f.get('entity_id'),action=f['code']) for f in findings])
    security.canonical(report)
    return report
