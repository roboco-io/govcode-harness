"""Portable signed projections of verified, unsigned synthetic local runs.

The operator attests this derived projection, never an institutional approval.
Ancestor projections embed bounded ID/digest links. Sources and filenames are omitted.
"""
import hashlib
import json
import stat
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from . import security

class ArchiveError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def timestamp(value):
    try:
        if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value): raise ValueError()
        return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ')
    except (TypeError,ValueError): raise ArchiveError('TIME_INVALID') from None


def write(path,value):
    raw=security.canonical(value)+b'\n'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def inventory(directory):
    directory=security.safe_path(directory)
    if not directory.is_dir(): raise ArchiveError('PATH_UNSAFE')
    result={}
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file() or path.stat().st_size>security.MAX_BYTES:
            raise ArchiveError('PATH_UNSAFE')
        result[path.name]=digest(path.read_bytes())
    return result


def _decode_metadata(raw):
    def pairs(items):
        value={}
        for key,item in items:
            if key in value: raise ArchiveError('SOURCE_JSON_INVALID')
            value[key]=item
        return value
    try:
        value=json.loads(raw,object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ArchiveError('SOURCE_JSON_INVALID')))
        if type(value) is not dict: raise ArchiveError('SOURCE_JSON_INVALID')
        security.canonical(value)
        return value
    except ArchiveError: raise
    except Exception: raise ArchiveError('SOURCE_JSON_INVALID') from None


def _read_metadata_bytes(directory_fd,name):
    """One bounded regular-file read; the same bytes are hashed and decoded."""
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>security.MAX_BYTES:
            raise ArchiveError('SOURCE_PATH_UNSAFE')
        raw=stream.read(security.MAX_BYTES+1)
    if len(raw)>security.MAX_BYTES: raise ArchiveError('SOURCE_SIZE_LIMIT')
    return raw


def _capture_metadata(directory,expected_manifest_digest,*,decision=False):
    """Capture immutable metadata bytes anchored to the verified manifest graph."""
    directory=security.safe_path(directory)
    directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        manifest=_decode_metadata(_read_metadata_bytes(directory_fd,'manifest.json'))
        manifest_digest=digest(security.canonical(manifest))
        if manifest_digest!=expected_manifest_digest: raise ArchiveError('SOURCE_MANIFEST_CHANGED')
        artifacts={}
        for entry in manifest['artifacts']:
            name=entry['path']
            if type(name) is not str or '/' in name or name in {'.','..'} or name in artifacts:
                raise ArchiveError('SOURCE_MANIFEST_INVALID')
            artifacts[name]=entry['sha256']
        captured={}
        for name in ('run.json','execution.json')+(('decision.json',) if decision else ()):
            raw=_read_metadata_bytes(directory_fd,name)
            if digest(raw)!=artifacts.get(name): raise ArchiveError('SOURCE_ARTIFACT_CHANGED')
            captured[name]=_decode_metadata(raw)
        run=captured['run.json']
        if manifest['run_id']!=run['id'] or manifest['parent_run_id']!=run['parent_run_id']:
            raise ArchiveError('SOURCE_IDENTITY_CHANGED')
        captured['manifest_digest']=manifest_digest
        return captured
    finally:
        os.close(directory_fd)


def _ancestors(evidence, execution, tenant_id, project_id, source_run_id):
    """Follow only hash-anchored execution metadata; never export local paths."""
    ancestors=[]
    seen_ids={source_run_id}; seen_paths={str(evidence)}
    reference=execution['parent']
    while reference is not None:
        if len(ancestors)>=16: raise ArchiveError('PARENT_CHAIN_LIMIT')
        directory=security.safe_path(reference['directory'])
        if str(directory) in seen_paths: raise ArchiveError('PARENT_CYCLE')
        seen_paths.add(str(directory))
        captured=_capture_metadata(directory,reference['manifest_digest'])
        run=captured['run.json']; parent_execution=captured['execution.json']
        if run['id'] in seen_ids: raise ArchiveError('PARENT_CYCLE')
        seen_ids.add(run['id'])
        if run['tenant_id']!=tenant_id or run['project_id']!=project_id: raise ArchiveError('PARENT_SCOPE_MISMATCH')
        next_reference=parent_execution['parent']
        ancestors.append({'run_id':run['id'],'parent_run_id':run['parent_run_id'],
            'commit_sha':run['commit_sha'],'source_manifest_digest':captured['manifest_digest'],
            'tenant_id':tenant_id,'project_id':project_id,
            'parent_manifest_digest':next_reference['manifest_digest'] if next_reference else None})
        reference=next_reference
    return ancestors


def _verify_ancestors(payload, tenant_id, project_id):
    ancestors=payload['ancestors']
    if type(ancestors) is not list or len(ancestors)>16: raise ArchiveError('PARENT_CHAIN_LIMIT')
    expected_id=payload['parent_run_id']; expected_digest=payload['parent_manifest_digest']
    seen={payload['source_run_id']}
    for ancestor in ancestors:
        if type(ancestor) is not dict or set(ancestor)!={'run_id','parent_run_id','commit_sha',
                'source_manifest_digest','tenant_id','project_id','parent_manifest_digest'}:
            raise ArchiveError('PARENT_INVALID')
        if ancestor['tenant_id']!=tenant_id or ancestor['project_id']!=project_id: raise ArchiveError('PARENT_SCOPE_MISMATCH')
        run_id=ancestor['run_id']
        if not isinstance(run_id,str) or not re.fullmatch(r'RUN-[a-f0-9]{32}',run_id): raise ArchiveError('PARENT_INVALID')
        if run_id in seen: raise ArchiveError('PARENT_CYCLE')
        seen.add(run_id)
        if run_id!=expected_id or ancestor['source_manifest_digest']!=expected_digest:
            raise ArchiveError('PARENT_LINK_MISMATCH')
        if not re.fullmatch(r'[a-f0-9]{40}',ancestor['commit_sha']) or not re.fullmatch(r'[a-f0-9]{64}',ancestor['source_manifest_digest']):
            raise ArchiveError('PARENT_INVALID')
        expected_id=ancestor['parent_run_id']; expected_digest=ancestor['parent_manifest_digest']
        if (expected_id is None)!=(expected_digest is None): raise ArchiveError('PARENT_INVALID')
        if expected_id is not None:
            if not re.fullmatch(r'RUN-[a-f0-9]{32}',expected_id) or not re.fullmatch(r'[a-f0-9]{64}',expected_digest):
                raise ArchiveError('PARENT_INVALID')
    if expected_id is not None or expected_digest is not None: raise ArchiveError('PARENT_LINK_MISSING')


def export_bundle(repo,evidence,destination,private_path,key_id,trust,tenant_id,project_id,*,created_at,retain_until,legal_hold=False):
    from . import runtime
    try:
        if timestamp(retain_until)<timestamp(created_at) or type(legal_hold) is not bool:
            raise ArchiveError('RETENTION_INVALID')
        evidence=security.safe_path(evidence)
        initial_run=security.read_json(evidence/'run.json')
        initial_execution=security.read_json(evidence/'execution.json')
        commit=initial_run['commit_sha'] if initial_execution['input_scope']['mode']=='commit_snapshot' else None
        checked=runtime.verify(repo,evidence,local_demo=True,commit=commit,tenant_id=tenant_id,project_id=project_id)
        captured=_capture_metadata(evidence,checked['manifest_digest'],decision=True)
        run=captured['run.json']; execution=captured['execution.json']; decision=captured['decision.json']
        if (run!=initial_run or execution!=initial_execution or run['id']!=checked['run_id'] or
            run['commit_sha']!=checked['commit_sha'] or run['tenant_id']!=tenant_id or run['project_id']!=project_id or
            decision['outcome']!=checked['outcome'] or decision['run_id']!=run['id'] or
            execution['input_scope']['mode']!=checked['input_mode'] or
            execution['input_scope']['commit_sha']!=checked['commit_sha']):
            raise ArchiveError('SOURCE_IDENTITY_CHANGED')
        ancestors=_ancestors(evidence,execution,tenant_id,project_id,run['id'])
        actor=trust['keys'][key_id]['actor_id']
        projection={'kind':'derived_run_projection','source_run_id':run['id'],
            'commit_sha':run['commit_sha'],'parent_run_id':run['parent_run_id'],
            'parent_manifest_digest':execution['parent']['manifest_digest'] if execution['parent'] else None,
            'tool_version':run['tool_version'],'tool_digest':run['tool_digest'],
            'bundle_digest':run['bundle_digest'],'tree_digest':run['tree_digest'],
            'policy_refs':decision['policy_refs'],'original_outcome':checked['outcome'],
            'input_mode':checked['input_mode'],'ancestors':ancestors,
            'parent_representation':'embedded_ancestor_chain_v1',
            'projection_notice':'Whitelisted derived metadata; original unsigned bytes and absolute parent directories omitted.'}
        raw=security.canonical(projection)+b'\n'
        payload={'kind':'evidence_archive','context':security.CONTEXT,'tenant_id':tenant_id,'project_id':project_id,
            'actor_id':actor,'archive_id':'ARCHIVE-'+uuid.uuid4().hex,'created_at':created_at,
            'retain_until':retain_until,'legal_hold':legal_hold,'source_run_id':run['id'],
            'source_manifest_digest':checked['manifest_digest'],'commit_sha':run['commit_sha'],
            'original_outcome':checked['outcome'],'parent_run_id':run['parent_run_id'],
            'parent_manifest_digest':projection['parent_manifest_digest'],
            'ancestors':ancestors,'parent_representation':'embedded_ancestor_chain_v1','release_approval':False,
            'attestation':'operator-derived-export-of-verified-unsigned-synthetic-producer',
            'artifacts':[{'path':'projection.json','sha256':digest(raw)}]}
        envelope=security.sign(payload,private_path,key_id)
        security.verify(envelope,trust,'operator',tenant_id,project_id)
        destination=security.safe_path(destination)
        destination.mkdir(mode=0o700,exist_ok=False)
        try:
            write(destination/'projection.json',projection)
            write(destination/'archive.json',envelope)
            verify_bundle(destination,trust,tenant_id,project_id)
        except Exception:
            shutil.rmtree(destination); raise
        return payload
    except ArchiveError: raise
    except security.SecurityError as exc: raise ArchiveError(exc.code) from None
    except runtime.HarnessError as exc: raise ArchiveError('SOURCE_'+exc.code) from None
    except Exception: raise ArchiveError('ARCHIVE_INVALID') from None


def verify_bundle(directory,trust,tenant_id,project_id):
    try:
        actual=inventory(directory)
        if set(actual)!={'archive.json','projection.json'}: raise ArchiveError('INVENTORY_MISMATCH')
        directory=security.safe_path(directory)
        payload=security.verify(security.read_json(directory/'archive.json'),trust,'operator',tenant_id,project_id)
        required={'kind','context','tenant_id','project_id','actor_id','archive_id','created_at','retain_until',
            'legal_hold','source_run_id','source_manifest_digest','commit_sha','original_outcome','parent_run_id',
            'parent_manifest_digest','ancestors','parent_representation','release_approval','attestation','artifacts'}
        if (set(payload)!=required or payload['kind']!='evidence_archive' or payload['release_approval'] is not False
            or payload['parent_representation']!='embedded_ancestor_chain_v1' or type(payload['legal_hold']) is not bool
            or payload['attestation']!='operator-derived-export-of-verified-unsigned-synthetic-producer'):
            raise ArchiveError('ARCHIVE_INVALID')
        if not re.fullmatch(r'ARCHIVE-[a-f0-9]{32}',payload['archive_id']): raise ArchiveError('ARCHIVE_INVALID')
        if not re.fullmatch(r'RUN-[a-f0-9]{32}',payload['source_run_id']): raise ArchiveError('ARCHIVE_INVALID')
        parent=payload['parent_run_id']
        if parent is not None and (not isinstance(parent,str) or not re.fullmatch(r'RUN-[a-f0-9]{32}',parent) or parent==payload['source_run_id']): raise ArchiveError('PARENT_INVALID')
        if (parent is None) != (payload['parent_manifest_digest'] is None): raise ArchiveError('PARENT_INVALID')
        if parent is not None and not re.fullmatch(r'[a-f0-9]{64}',payload['parent_manifest_digest']): raise ArchiveError('PARENT_INVALID')
        if not re.fullmatch(r'[a-f0-9]{40}',payload['commit_sha']) or not re.fullmatch(r'[a-f0-9]{64}',payload['source_manifest_digest']): raise ArchiveError('ARCHIVE_INVALID')
        _verify_ancestors(payload,tenant_id,project_id)
        if payload['original_outcome'] not in {'allow','deny','review_required','error'}: raise ArchiveError('ARCHIVE_INVALID')
        if timestamp(payload['retain_until'])<timestamp(payload['created_at']): raise ArchiveError('RETENTION_INVALID')
        if payload['artifacts']!=[{'path':'projection.json','sha256':actual['projection.json']}]: raise ArchiveError('DIGEST_MISMATCH')
        projection=security.read_json(directory/'projection.json')
        fields={'kind','source_run_id','commit_sha','parent_run_id','tool_version','tool_digest','bundle_digest',
            'tree_digest','policy_refs','original_outcome','input_mode','parent_manifest_digest','ancestors','parent_representation','projection_notice'}
        if set(projection)!=fields or projection['kind']!='derived_run_projection': raise ArchiveError('PROJECTION_INVALID')
        for name in ('source_run_id','commit_sha','parent_run_id','original_outcome','parent_manifest_digest','ancestors','parent_representation'):
            if projection[name]!=payload[name]: raise ArchiveError('PROJECTION_INVALID')
        return {'kind':'archive_integrity','archive_id':payload['archive_id'],'integrity_verified':True,
            'original_outcome':payload['original_outcome'],'commit_sha':payload['commit_sha'],
            'release_approval':False,'metadata':payload,
            'verification_scope':'historical_signature_and_digests_only; no current tool rerun'}
    except ArchiveError: raise
    except security.SecurityError as exc: raise ArchiveError(exc.code) from None
    except Exception: raise ArchiveError('ARCHIVE_INVALID') from None
