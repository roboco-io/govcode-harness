"""Source-free signed local project evidence. External checkpoints detect rollback.

This reference store is not WORM storage and does not grant operational approval.
"""
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from .. import security
from ..evidence_store import StoreError, checked, utcnow
from . import contracts as c, stage_gate

MAX_EVENTS=1000
MAX_TOTAL=16*1024*1024
_BIND=('candidate_digest','subject_digest','evaluation_digest','commit_sha','stage','tenant_id','project_id')
_COMMON={'schema_version':'1','context':security.CONTEXT,'operational_approval':False}
_AUTH=set(_COMMON)|{'kind','tenant_id','project_id','actor_id','store_id','action','evidence_id','event_id','time','parameters_digest'}
_META=set(_COMMON)|{'kind','tenant_id','project_id','actor_id','release_approval','store_id','evidence_id',
    'candidate_digest','subject_digest','evaluation_digest','artifact_manifest_digest','code_receipt_digest','commit_sha',
    'stage','projection_digest','parent_id','parent_digest','created_at','retain_until','legal_hold'}
_EVENT=set(_COMMON)|{'kind','tenant_id','project_id','actor_id','store_id','sequence','previous_digest','time',
    'action','evidence_id','authorization','parameters','metadata'}
_CONFIG=set(_COMMON)|{'kind','tenant_id','project_id','actor_id','store_id'}
_CHECK={'sequence','head_digest','store_id','tenant_id','project_id'}


def require(condition,code='STORE_INVALID'):
    if not condition:raise StoreError(code)


def _path(value):
    path=security.safe_path(value)
    require('..' not in path.parts,'PATH_UNSAFE')
    path=path.resolve()
    for parent in (path,*path.parents):
        name=unicodedata.normalize('NFKC',parent.name).casefold().rstrip(' .')
        name=''.join(ch for ch in name if unicodedata.category(ch)!='Cf')
        require(name!='.git','PATH_UNSAFE')
    return path


def _json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'JSON_DUPLICATE_KEY');result[key]=value
        return result
    require(len(raw)<=security.MAX_BYTES,'JSON_LIMIT')
    result=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False,'JSON_INVALID'))
    security.canonical(result)
    return result


def _capture(root):
    """Open once, reject links, retain precisely the bytes subsequently verified/copied."""
    root=_path(root);files={};directories=set();total=0
    require(root.is_dir(),'PATH_UNSAFE')
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:
            path=security.safe_path(Path(folder)/name)
            require(path.is_dir(),'PATH_UNSAFE');directories.add(path.relative_to(root).as_posix())
        for name in names:
            path=security.safe_path(Path(folder)/name)
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'PATH_UNSAFE')
                raw=stream.read(security.MAX_BYTES+1)
            require(len(raw)<=security.MAX_BYTES,'JSON_LIMIT')
            total+=len(raw);require(total<=MAX_TOTAL,'STORE_LIMIT')
            files[path.relative_to(root).as_posix()]=raw
    return files,directories


def _write(path,raw):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def _copy(files,directories,target):
    target.mkdir(mode=0o700,exist_ok=False)
    try:
        for directory in sorted(directories,key=lambda p:(p.count('/'),p)):(target/directory).mkdir(mode=0o700)
        for name,raw in files.items():_write(target/name,raw)
    except Exception:
        shutil.rmtree(target);raise


class ProjectEvidenceStore:
    @checked
    def __init__(self,root,trust,*,private_path=None,key_id=None,clock=utcnow,checkpoint=None):
        self.root=_path(root);self.trust=trust;self.private_path=private_path;self.key_id=key_id;self.clock=clock
        self._anchor=checkpoint
        with self._locked():pass

    @classmethod
    @checked
    def create(cls,root,trust,tenant_id,project_id,*,private_path,key_id,clock=utcnow):
        root=_path(root)
        payload=dict(_COMMON,kind='project_evidence_store',tenant_id=tenant_id,project_id=project_id,
            actor_id=trust['keys'][key_id]['actor_id'],store_id='STORE-'+uuid.uuid4().hex)
        envelope=security.sign(payload,private_path,key_id)
        security.verify(envelope,trust,'operator',tenant_id,project_id)
        root.mkdir(mode=0o700,exist_ok=False)
        try:
            (root/'objects').mkdir(mode=0o700);(root/'journal').mkdir(mode=0o700)
            _write(root/'lock',b'');_write(root/'store.json',security.canonical(envelope))
            return cls(root,trust,private_path=private_path,key_id=key_id,clock=clock)
        except Exception:
            shutil.rmtree(root);raise

    @contextmanager
    def _locked(self):
        path=security.safe_path(self.root/'lock')
        fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'PATH_UNSAFE')
            fcntl.flock(fd,fcntl.LOCK_EX);self._load();yield
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

    def _verify(self,envelope,role='operator'):
        return security.verify(envelope,self.trust,role,self.tenant_id,self.project_id)

    def _load(self,captured=None):
        files,dirs=captured if captured is not None else _capture(self.root)
        config=_json(files['store.json']);claims=config['payload']
        self.tenant_id=claims['tenant_id'];self.project_id=claims['project_id']
        self.config=self._verify(config);require(set(self.config)==_CONFIG and self.config['kind']=='project_evidence_store')
        require(all(type(self.config[k]) is type(v) and self.config[k]==v for k,v in _COMMON.items()))
        self.store_id=security.identifier(self.config['store_id'])
        require(files.get('lock')==b'','INVENTORY_MISMATCH')
        journals=sorted(name for name in files if name.startswith('journal/'))
        require(len(journals)<=MAX_EVENTS,'STORE_LIMIT')
        self.state={};self.events=set();self.sequence=0;self.head_digest=None;heads={0:None}
        expected_files={'lock','store.json'};expected_dirs={'objects','journal'}
        for name in journals:
            self.sequence+=1;require(name==f'journal/{self.sequence:012d}.json','JOURNAL_INVALID')
            expected_files.add(name);envelope=_json(files[name]);event=self._verify(envelope)
            require(set(event)==_EVENT and event['kind']=='project_store_event','JOURNAL_INVALID')
            require(all(type(event[k]) is type(v) and event[k]==v for k,v in _COMMON.items()) and event['store_id']==self.store_id and
                type(event['sequence']) is int and event['sequence']==self.sequence and event['previous_digest']==self.head_digest,'JOURNAL_INVALID')
            c.timestamp(event['time']);action=event['action'];item=event['evidence_id'];params=event['parameters']
            if action=='put':
                require(event['authorization'] is None and params=={} and item not in self.state,'JOURNAL_INVALID')
                metadata=event['metadata'];self._metadata(metadata,item)
                require(metadata['created_at']==event['time'],'JOURNAL_INVALID')
                parent=metadata['parent_id']
                if parent is not None:
                    ancestor=self._entry(parent)
                    require(metadata['parent_digest']==c.digest(ancestor['metadata']),'PARENT_INVALID')
                else:require(metadata['parent_digest'] is None,'PARENT_INVALID')
                self.state[item]=dict(metadata=metadata,hold=metadata['legal_hold'],tombstone=False)
            else:
                require(event['metadata'] is None,'JOURNAL_INVALID')
                self._authorization(event['authorization'],action,item,params,event['time'])
                self.events.add(event['authorization']['payload']['event_id'])
                if action=='set_hold':self._entry(item)['hold']=params['enabled']
                elif action=='delete':
                    entry=self._entry(item)
                    require(not entry['hold'] and c.timestamp(event['time'])>=c.timestamp(entry['metadata']['retain_until']),'RETENTION_ACTIVE')
                    self._no_children(item);entry['tombstone']=True
                elif action=='read':self._entry(item)
                else:require(action in ('backup','restore'),'JOURNAL_INVALID')
            self.head_digest=hashlib.sha256(security.canonical(envelope)).hexdigest();heads[self.sequence]=self.head_digest
        self.projections={}
        for item,entry in self.state.items():
            if entry['tombstone']:continue
            prefix='objects/'+item;expected_dirs.add(prefix)
            expected_files.update((prefix+'/metadata.json',prefix+'/projection.json'))
            signed=_json(files[prefix+'/metadata.json']);metadata=self._verify(signed)
            require(metadata==entry['metadata'],'DIGEST_MISMATCH')
            projection=_json(files[prefix+'/projection.json'])
            require(c.digest(projection)==metadata['projection_digest'],'DIGEST_MISMATCH')
            require(projection==self._projection_shape(projection,metadata),'PROJECTION_INVALID')
            self.projections[item]=projection
        require(set(files)==expected_files and dirs==expected_dirs,'INVENTORY_MISMATCH')
        if self._anchor is not None:
            anchor=self._anchor
            require(type(anchor) is dict and set(anchor)==_CHECK and type(anchor['sequence']) is int and anchor['sequence']>=0,'CHECKPOINT_INVALID')
            require(all(anchor[k]==getattr(self,k) for k in ('store_id','tenant_id','project_id')) and
                anchor['sequence']<=self.sequence and heads.get(anchor['sequence'])==anchor['head_digest'],'ROLLBACK_DETECTED')
        self._files=files;self._dirs=dirs;self._anchor=self._checkpoint()

    def _metadata(self,value,item):
        require(type(item) is str and re.fullmatch(r'EVID-[a-f0-9]{32}',item),'EVIDENCE_ID_INVALID')
        require(type(value) is dict and set(value)==_META and value['kind']=='project_evidence_metadata')
        require(all(type(value[k]) is type(v) and value[k]==v for k,v in _COMMON.items()) and value['release_approval'] is False and
            value['evidence_id']==item and value['store_id']==self.store_id and value['tenant_id']==self.tenant_id and value['project_id']==self.project_id,'SCOPE_MISMATCH')
        require(type(value['legal_hold']) is bool,'HOLD_INVALID')
        require(c.timestamp(value['retain_until'])>=c.timestamp(value['created_at']),'RETENTION_INVALID')
        for key in ('candidate_digest','subject_digest','evaluation_digest','artifact_manifest_digest','projection_digest'):
            require(type(value[key]) is str and re.fullmatch('[a-f0-9]{64}',value[key]),'DIGEST_INVALID')
        require(value['code_receipt_digest'] is None or re.fullmatch('[a-f0-9]{64}',value['code_receipt_digest']),'DIGEST_INVALID')
        require(re.fullmatch('[a-f0-9]{40}',value['commit_sha']) and type(value['stage']) is str,'METADATA_INVALID')

    @staticmethod
    def _projection_shape(projection,metadata):
        # Closed projection contains no document, fact, policy, proposal or key data.
        fields=set(_BIND)|{'kind','schema_version','context','operational_approval','release_approval','artifact_manifest_digest',
            'code_receipt_digest','outcome','code_required','counts'}
        require(type(projection) is dict and set(projection)==fields,'PROJECTION_INVALID')
        require(projection['kind']=='project_evidence_projection' and all(type(projection[k]) is type(v) and projection[k]==v for k,v in _COMMON.items()) and
            projection['release_approval'] is False,'PROJECTION_INVALID')
        require(all(projection[k]==metadata[k] for k in (*_BIND,'artifact_manifest_digest','code_receipt_digest')),'PROJECTION_INVALID')
        require(projection['outcome'] in ('ready_for_evidence','review_required','deny') and
            (projection['code_required'] is None or type(projection['code_required']) is bool),'PROJECTION_INVALID')
        require(type(projection['counts']) is dict and set(projection['counts'])<=
            {'total','applicable','not_applicable','pending','current','not_due','satisfied','unsatisfied','review_required','not_evaluated','stale','error'} and
            all(type(n) is int and n>=0 for n in projection['counts'].values()),'PROJECTION_INVALID')
        return projection

    def _entry(self,item):
        require(item in self.state and not self.state[item]['tombstone'],'EVIDENCE_NOT_FOUND')
        return self.state[item]

    def _no_children(self,item):
        require(not any(not e['tombstone'] and e['metadata']['parent_id']==item for e in self.state.values()),'ACTIVE_ANCESTOR')

    def _now(self):
        value=self.clock();c.timestamp(value);return value

    def _authorization(self,envelope,action,item,params,current):
        claims=self._verify(envelope,'auditor' if action=='read' else 'operator')
        require(set(claims)==_AUTH and claims['kind']=='project_store_authorization' and
            all(type(claims[k]) is type(v) and claims[k]==v for k,v in _COMMON.items()) and claims['store_id']==self.store_id and
            claims['action']==action and claims['evidence_id']==item and claims['parameters_digest']==c.digest(params),'AUTHORIZATION_INVALID')
        security.identifier(claims['event_id']);require(claims['event_id'] not in self.events,'AUTHORIZATION_REPLAY')
        require(abs((c.timestamp(claims['time'])-c.timestamp(current)).total_seconds())<=300,'AUTHORIZATION_EXPIRED')
        if action in ('read','delete'):require(params=={},'AUTHORIZATION_INVALID')
        elif action=='set_hold':require(type(params) is dict and set(params)=={'enabled'} and type(params['enabled']) is bool,'HOLD_INVALID')
        else:require(action in ('backup','restore') and item=='STORE' and type(params) is dict and set(params)=={'destination'} and
            type(params['destination']) is str and str(_path(params['destination']))==params['destination'],'AUTHORIZATION_INVALID')

    def _append(self,action,item,authorization=None,parameters=None,metadata=None,current=None):
        require(self.private_path is not None and self.key_id is not None,'SIGNER_REQUIRED')
        require(self.sequence<MAX_EVENTS,'STORE_LIMIT')
        event=dict(_COMMON,kind='project_store_event',tenant_id=self.tenant_id,project_id=self.project_id,
            actor_id=self.trust['keys'][self.key_id]['actor_id'],store_id=self.store_id,sequence=self.sequence+1,
            previous_digest=self.head_digest,time=current or self._now(),action=action,evidence_id=item,
            authorization=authorization,parameters=parameters or {},metadata=metadata)
        envelope=security.sign(event,self.private_path,self.key_id);self._verify(envelope)
        raw=security.canonical(envelope);require(sum(map(len,self._files.values()))+len(raw)<=MAX_TOTAL,'STORE_LIMIT')
        _write(self.root/'journal'/f'{self.sequence+1:012d}.json',raw)

    def _checkpoint(self):
        return dict(sequence=self.sequence,head_digest=self.head_digest,store_id=self.store_id,tenant_id=self.tenant_id,project_id=self.project_id)

    @checked
    def checkpoint(self):
        with self._locked():return self._checkpoint()

    @checked
    def put(self,request,expected_commit,*,retain_until,legal_hold=False,parent_id=None,code_evidence=None,code_context=None,
            expected_subject_digest=None,expected_evaluation_digest=None):
        candidate=stage_gate.prepare(request,expected_commit,code_evidence=code_evidence,code_context=code_context,
            expected_subject_digest=expected_subject_digest,expected_evaluation_digest=expected_evaluation_digest)
        report=candidate.get('assessment')
        require(type(report) is dict and report.get('outcome') in ('ready_for_stage','review_required','deny') and
            candidate['outcome'] in ('ready_for_evidence','review_required','deny'),'ASSESSMENT_INVALID')
        require(c.digest({k:v for k,v in report.items() if k!='evaluation_digest'})==report['evaluation_digest'],'ASSESSMENT_INVALID')
        with self._locked():
            require((candidate['tenant_id'],candidate['project_id'])==(self.tenant_id,self.project_id),'SCOPE_MISMATCH')
            source=security.safe_path(request['repo']).resolve()
            require(self.root!=source and source not in self.root.parents and self.root not in source.parents,'PATH_UNSAFE')
            current=self._now();require(type(legal_hold) is bool,'HOLD_INVALID')
            require(c.timestamp(retain_until)>=c.timestamp(current),'RETENTION_INVALID')
            parent_digest=c.digest(self._entry(parent_id)['metadata']) if parent_id is not None else None
            item='EVID-'+uuid.uuid4().hex
            projection=dict(_COMMON,kind='project_evidence_projection',release_approval=False,
                **{k:candidate[k] for k in _BIND},artifact_manifest_digest=report['artifact_manifest_digest'],
                code_receipt_digest=candidate['code_receipt_digest'],outcome=candidate['outcome'],code_required=candidate['code_required'],counts=report['counts'])
            metadata=dict(_COMMON,kind='project_evidence_metadata',release_approval=False,
                **{k:candidate[k] for k in _BIND},actor_id=self.trust['keys'][self.key_id]['actor_id'],store_id=self.store_id,evidence_id=item,
                artifact_manifest_digest=report['artifact_manifest_digest'],code_receipt_digest=candidate['code_receipt_digest'],
                projection_digest=c.digest(projection),parent_id=parent_id,parent_digest=parent_digest,
                created_at=current,retain_until=retain_until,legal_hold=legal_hold)
            self._metadata(metadata,item);self._projection_shape(projection,metadata)
            signed=security.sign(metadata,self.private_path,self.key_id);self._verify(signed)
            raws={'metadata.json':security.canonical(signed),'projection.json':security.canonical(projection)}
            require(sum(map(len,self._files.values()))+sum(map(len,raws.values()))+4096<=MAX_TOTAL,'STORE_LIMIT')
            dest=self.root/'objects'/item;dest.mkdir(mode=0o700)
            try:
                for name,raw in raws.items():_write(dest/name,raw)
                self._append('put',item,metadata=metadata,current=current)
            except Exception:
                shutil.rmtree(dest);raise
            self._load();return item

    @checked
    def verify_receipt(self,evidence_id,candidate):
        with self._locked():
            metadata=self._entry(evidence_id)['metadata']
            require(type(candidate) is dict and candidate.get('candidate_digest')==c.digest({k:v for k,v in candidate.items() if k!='candidate_digest'}),'CANDIDATE_INVALID')
            require(all(metadata[k]==candidate[k] for k in _BIND) and
                metadata['code_receipt_digest']==candidate['code_receipt_digest'] and
                metadata['artifact_manifest_digest']==candidate['assessment']['artifact_manifest_digest'],'EVIDENCE_CANDIDATE_MISMATCH')
            return dict(metadata)

    @checked
    def read(self,item,authorization):
        with self._locked():
            metadata=self._entry(item)['metadata'];current=self._now();self._authorization(authorization,'read',item,{},current)
            result=dict(metadata=metadata,projection=self.projections[item],integrity_verified=True,release_approval=False)
            self._append('read',item,authorization,current=current);self._load();return result

    @checked
    def set_hold(self,item,enabled,authorization):
        with self._locked():
            self._entry(item);params={'enabled':enabled};current=self._now();self._authorization(authorization,'set_hold',item,params,current)
            self._append('set_hold',item,authorization,parameters=params,current=current);self._load()
            return dict(evidence_id=item,legal_hold=enabled)

    @checked
    def delete(self,item,authorization):
        with self._locked():
            entry=self._entry(item);current=self._now();self._authorization(authorization,'delete',item,{},current)
            require(not entry['hold'],'LEGAL_HOLD');require(c.timestamp(current)>=c.timestamp(entry['metadata']['retain_until']),'RETENTION_ACTIVE')
            self._no_children(item);self._append('delete',item,authorization,current=current)
            shutil.rmtree(self.root/'objects'/item);self._load()
            return dict(evidence_id=item,tombstone=True)

    def _destination(self,destination):
        dest=_path(destination)
        require(dest!=self.root and self.root not in dest.parents and dest not in self.root.parents and not dest.exists(),'PATH_UNSAFE')
        return dest

    @checked
    def backup(self,destination,authorization):
        with self._locked():
            dest=self._destination(destination);params={'destination':str(dest)}
            current=self._now();self._authorization(authorization,'backup','STORE',params,current)
            old_sequence=self.sequence;old_anchor=self._anchor
            self._append('backup','STORE',authorization,parameters=params,current=current)
            try:
                self._load();checkpoint=self._checkpoint()
                manifest=dict(_COMMON,kind='project_store_backup',actor_id=self.trust['keys'][self.key_id]['actor_id'],
                    **checkpoint,files={name:hashlib.sha256(raw).hexdigest() for name,raw in self._files.items()},directories=sorted(self._dirs))
                signed=security.sign(manifest,self.private_path,self.key_id);self._verify(signed)
                files=dict(self._files);files['backup.json']=security.canonical(signed)
                _copy(files,self._dirs,dest);return checkpoint
            except Exception:
                (self.root/'journal'/f'{old_sequence+1:012d}.json').unlink();self._anchor=old_anchor;self._load();raise

    @classmethod
    @checked
    def restore(cls,backup,newroot,trust,tenant_id,project_id,authorization,*,expected_head_digest,minimum_sequence,
            private_path,key_id,clock=utcnow):
        source=_path(backup);target=_path(newroot)
        require(source!=target and source not in target.parents and target not in source.parents and not target.exists(),'PATH_UNSAFE')
        files,dirs=_capture(source);envelope=_json(files.pop('backup.json'))
        payload=security.verify(envelope,trust,'operator',tenant_id,project_id)
        require(set(payload)==set(_COMMON)|_CHECK|{'kind','actor_id','files','directories'} and payload['kind']=='project_store_backup' and
            all(type(payload[k]) is type(v) and payload[k]==v for k,v in _COMMON.items()),'BACKUP_INVALID')
        require(type(expected_head_digest) is str and re.fullmatch('[a-f0-9]{64}',expected_head_digest) and
            type(minimum_sequence) is int and minimum_sequence>0,'ROLLBACK_ANCHOR_REQUIRED')
        require(payload['head_digest']==expected_head_digest and type(payload['sequence']) is int and payload['sequence']>=minimum_sequence,'ROLLBACK_DETECTED')
        require(payload['files']=={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()} and payload['directories']==sorted(dirs),'BACKUP_INVALID')
        # Validate captured bytes before creating anything; never reopen source files.
        probe=object.__new__(cls);probe.root=source;probe.trust=trust;probe.clock=clock;probe._anchor={k:payload[k] for k in _CHECK}
        probe._load((files,dirs))
        require((probe.tenant_id,probe.project_id)==(tenant_id,project_id),'SCOPE_MISMATCH')
        probe._authorization(authorization,'restore','STORE',{'destination':str(target)},probe._now())
        _copy(files,dirs,target)
        try:
            result=cls(target,trust,private_path=private_path,key_id=key_id,clock=clock,checkpoint=probe._checkpoint())
            with result._locked():
                current=result._now();result._authorization(authorization,'restore','STORE',{'destination':str(target)},current)
                result._append('restore','STORE',authorization,parameters={'destination':str(target)},current=current);result._load()
            return result
        except Exception:
            shutil.rmtree(target);raise
