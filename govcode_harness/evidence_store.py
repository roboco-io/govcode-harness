"""Scoped local signed journal and retention reference; no WORM/KMS guarantee.

The owner injects the clock and signing key. Caller-provided `now` is checked
against that clock and cannot override it. Authorization is single-use.
"""
import fcntl
import os
import shutil
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from . import security
from .archive import ArchiveError, digest, timestamp, write, verify_bundle, inventory

class StoreError(Exception):
    def __init__(self,code):
        self.code=code
        super().__init__(code)


def utcnow():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def checked(method):
    def wrapped(*args,**kwargs):
        try: return method(*args,**kwargs)
        except StoreError: raise
        except (ArchiveError,security.SecurityError) as exc: raise StoreError(exc.code) from None
        except Exception: raise StoreError('STORE_INVALID') from None
    return wrapped


class EvidenceStore:
    @checked
    def __init__(self,root,trust,*,private_path=None,key_id=None,clock=utcnow):
        self.root=security.safe_path(root)
        self.trust=trust
        self.private_path=private_path
        self.key_id=key_id
        self.clock=clock
        config=security.read_json(self.root/'store.json')
        claims=config['payload']
        self.tenant_id=claims['tenant_id']; self.project_id=claims['project_id']
        self.config=security.verify(config,trust,'operator',self.tenant_id,self.project_id)
        if set(self.config)!={'kind','context','tenant_id','project_id','actor_id','store_id'} or self.config['kind']!='evidence_store': raise StoreError('STORE_INVALID')
        self._load()

    @classmethod
    @checked
    def create(cls,root,trust,tenant_id,project_id,*,private_path,key_id,clock=utcnow):
        root=security.safe_path(root)
        payload={'kind':'evidence_store','context':security.CONTEXT,'tenant_id':tenant_id,'project_id':project_id,
                 'actor_id':trust['keys'][key_id]['actor_id'],'store_id':'STORE-'+uuid.uuid4().hex}
        envelope=security.sign(payload,private_path,key_id)
        security.verify(envelope,trust,'operator',tenant_id,project_id)
        root.mkdir(mode=0o700,exist_ok=False)
        (root/'objects').mkdir(mode=0o700); (root/'journal').mkdir(mode=0o700)
        write(root/'store.json',envelope)
        fd=os.open(root/'lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
        return cls(root,trust,private_path=private_path,key_id=key_id,clock=clock)

    @contextmanager
    def _locked(self):
        fd=os.open(security.safe_path(self.root/'lock'),os.O_RDWR|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            self._load()
            yield
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)

    def _load(self):
        if {p.name for p in self.root.iterdir()}!={'store.json','objects','journal','lock'}: raise StoreError('INVENTORY_MISMATCH')
        for p in (self.root/'objects',self.root/'journal',self.root/'lock'):
            security.safe_path(p)
        self.state={}; self.events=set(); self.sequence=0; self.head_digest=None
        entries=inventory(self.root/'journal')
        for name in sorted(entries):
            self.sequence+=1
            if name!=f'{self.sequence:012d}.json': raise StoreError('JOURNAL_INVALID')
            envelope=security.read_json(self.root/'journal'/name)
            event=security.verify(envelope,self.trust,'operator',self.tenant_id,self.project_id)
            if (event.get('kind')!='store_event' or event.get('store_id')!=self.config['store_id'] or
                event.get('sequence')!=self.sequence or event.get('previous_digest')!=self.head_digest): raise StoreError('JOURNAL_INVALID')
            timestamp(event['time'])
            authorization=event.get('authorization')
            if authorization is not None:
                action=event['action']
                claims=security.verify(authorization,self.trust,'auditor' if action=='read' else 'operator',self.tenant_id,self.project_id)
                if abs((timestamp(claims['time'])-timestamp(event['time'])).total_seconds())>300: raise StoreError('AUTHORIZATION_EXPIRED')
                if claims.get('kind')!='store_authorization' or claims.get('action')!=action or claims.get('archive_id')!=event['archive_id']: raise StoreError('AUTHORIZATION_INVALID')
                event_id=security.identifier(claims['event_id'])
                if event_id in self.events: raise StoreError('AUTHORIZATION_REPLAY')
                self.events.add(event_id)
            elif event['action']!='put': raise StoreError('JOURNAL_INVALID')
            item=event['archive_id']; action=event['action']
            if action=='put':
                if item in self.state: raise StoreError('JOURNAL_INVALID')
                self.state[item]={'metadata':event['metadata'],'hold':event['metadata']['legal_hold'],'tombstone':False}
            elif action=='set_hold':
                if type(event['enabled']) is not bool: raise StoreError('HOLD_INVALID')
                self._entry(item)['hold']=event['enabled']
            elif action=='delete':
                entry=self._entry(item)
                if entry['hold'] or timestamp(event['time'])<timestamp(entry['metadata']['retain_until']): raise StoreError('RETENTION_ACTIVE')
                entry['tombstone']=True
            elif action not in {'read','backup','restore'}: raise StoreError('JOURNAL_INVALID')
            self.head_digest=digest(security.canonical(envelope))
        expected={item for item,state in self.state.items() if not state['tombstone']}
        actual={p.name for p in (self.root/'objects').iterdir()}
        if actual!=expected: raise StoreError('INVENTORY_MISMATCH')
        for item in expected:
            metadata=verify_bundle(self.root/'objects'/item,self.trust,self.tenant_id,self.project_id)['metadata']
            if metadata!=self.state[item]['metadata']: raise StoreError('DIGEST_MISMATCH')

    def _entry(self,item):
        security.identifier(item)
        if item not in self.state or self.state[item]['tombstone']: raise StoreError('ARCHIVE_NOT_FOUND')
        return self.state[item]

    def _now(self,now=None):
        current=self.clock()
        timestamp(current)
        if now is not None and now!=current: raise StoreError('CLOCK_MISMATCH')
        return current

    def _authorize(self,envelope,action,item,now=None):
        current=self._now(now)
        claims=security.verify(envelope,self.trust,'auditor' if action=='read' else 'operator',self.tenant_id,self.project_id)
        if set(claims)!={'kind','context','tenant_id','project_id','actor_id','action','archive_id','event_id','time'} or claims['kind']!='store_authorization' or claims['action']!=action or claims['archive_id']!=item: raise StoreError('AUTHORIZATION_INVALID')
        event_id=security.identifier(claims['event_id'])
        if event_id in self.events: raise StoreError('AUTHORIZATION_REPLAY')
        if abs((timestamp(claims['time'])-timestamp(current)).total_seconds())>300: raise StoreError('AUTHORIZATION_EXPIRED')
        return current

    def _append(self,action,item,authorization=None,**fields):
        if self.private_path is None or self.key_id is None: raise StoreError('SIGNER_REQUIRED')
        event={'kind':'store_event','context':security.CONTEXT,'tenant_id':self.tenant_id,'project_id':self.project_id,
            'actor_id':self.trust['keys'][self.key_id]['actor_id'],'store_id':self.config['store_id'],
            'sequence':self.sequence+1,'previous_digest':self.head_digest,'time':self._now(),
            'action':action,'archive_id':item,'authorization':authorization,**fields}
        envelope=security.sign(event,self.private_path,self.key_id)
        security.verify(envelope,self.trust,'operator',self.tenant_id,self.project_id)
        write(self.root/'journal'/f'{self.sequence+1:012d}.json',envelope)
        self.sequence+=1; self.head_digest=digest(security.canonical(envelope))
        return event

    @checked
    def put(self,archive_dir):
        with self._locked():
            metadata=verify_bundle(archive_dir,self.trust,self.tenant_id,self.project_id)['metadata']
            item=metadata['archive_id']
            if item in self.state: raise StoreError('ARCHIVE_EXISTS')
            dest=self.root/'objects'/item
            dest.mkdir(mode=0o700)
            try:
                for name in ('archive.json','projection.json'): write(dest/name,security.read_json(Path(archive_dir)/name))
                # Canonical rewrite preserves the canonical producer artifacts.
                verify_bundle(dest,self.trust,self.tenant_id,self.project_id)
                self._append('put',item,metadata=metadata)
            except Exception:
                shutil.rmtree(dest); raise
            return item

    @checked
    def read(self,item,authorization_envelope):
        with self._locked():
            entry=self._entry(item)
            self._authorize(authorization_envelope,'read',item)
            result={'metadata':entry['metadata'],'path':str(self.root/'objects'/item),
                    'artifacts':{name:(self.root/'objects'/item/name).read_bytes() for name in ('archive.json','projection.json')}}
            self._append('read',item,authorization_envelope)
            return result

    @checked
    def set_hold(self,item,enabled,authorization_envelope,now=None):
        with self._locked():
            self._entry(item)
            self._authorize(authorization_envelope,'set_hold',item,now)
            if type(enabled) is not bool: raise StoreError('HOLD_INVALID')
            event=self._append('set_hold',item,authorization_envelope,enabled=enabled)
            return event

    @checked
    def delete(self,item,authorization_envelope,now=None):
        with self._locked():
            entry=self._entry(item)
            current=self._authorize(authorization_envelope,'delete',item,now)
            if entry['hold']: raise StoreError('LEGAL_HOLD')
            if timestamp(current)<timestamp(entry['metadata']['retain_until']): raise StoreError('RETENTION_ACTIVE')
            self._append('delete',item,authorization_envelope)
            shutil.rmtree(security.safe_path(self.root/'objects'/item))
            return {'archive_id':item,'tombstone':True,'head_digest':self.head_digest}

    @checked
    def backup(self,destination,authorization_envelope):
        with self._locked():
            self._authorize(authorization_envelope,'backup','store')
            self._append('backup','store',authorization_envelope)
            destination=security.safe_path(destination)
            if destination == self.root or self.root in destination.parents or destination in self.root.parents:
                raise StoreError('PATH_UNSAFE')
            destination.mkdir(mode=0o700,exist_ok=False)
            try:
                files=self._copy_tree(self.root,destination)
                payload={'kind':'store_backup','context':security.CONTEXT,'tenant_id':self.tenant_id,
                    'project_id':self.project_id,'actor_id':self.trust['keys'][self.key_id]['actor_id'],
                    'store_id':self.config['store_id'],'sequence':self.sequence,'head_digest':self.head_digest,'files':files}
                write(destination/'backup.json',security.sign(payload,self.private_path,self.key_id))
                return payload
            except Exception:
                shutil.rmtree(destination); raise

    @staticmethod
    def _copy_tree(source,destination):
        files=[]
        for folder,dirs,names in os.walk(source,followlinks=False):
            for name in dirs:
                src=security.safe_path(Path(folder)/name)
                (destination/src.relative_to(source)).mkdir(mode=0o700)
            for name in names:
                src=security.safe_path(Path(folder)/name)
                if not src.is_file() or src.stat().st_size>security.MAX_BYTES: raise StoreError('PATH_UNSAFE')
                raw=src.read_bytes()
                rel=src.relative_to(source).as_posix()
                fd=os.open(destination/rel,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream: stream.write(raw)
                files.append({'path':rel,'sha256':digest(raw)})
        return sorted(files,key=lambda x:x['path'])

    @classmethod
    @checked
    def restore(cls,backup,newroot,trust,tenant_id,project_id,authorization,*,expected_head_digest=None,minimum_sequence=None,private_path,key_id,clock=utcnow):
        backup=security.safe_path(backup); newroot=security.safe_path(newroot)
        if backup == newroot or backup in newroot.parents or newroot in backup.parents: raise StoreError('PATH_UNSAFE')
        payload=security.verify(security.read_json(backup/'backup.json'),trust,'operator',tenant_id,project_id)
        if payload.get('kind')!='store_backup': raise StoreError('BACKUP_INVALID')
        if expected_head_digest is None and minimum_sequence is None: raise StoreError('ROLLBACK_ANCHOR_REQUIRED')
        if expected_head_digest is not None and payload['head_digest']!=expected_head_digest: raise StoreError('ROLLBACK_DETECTED')
        if minimum_sequence is not None and (type(minimum_sequence) is not int or payload['sequence']<minimum_sequence): raise StoreError('ROLLBACK_DETECTED')
        expected={entry['path']:entry['sha256'] for entry in payload['files']}
        if len(expected)!=len(payload['files']): raise StoreError('BACKUP_INVALID')
        actual={}; actual_dirs=set()
        for folder,dirs,names in os.walk(backup,followlinks=False):
            for name in dirs:
                directory=security.safe_path(Path(folder)/name)
                actual_dirs.add(directory.relative_to(backup).as_posix())
            for name in names:
                path=security.safe_path(Path(folder)/name)
                if path==backup/'backup.json': continue
                if not path.is_file() or path.stat().st_size>security.MAX_BYTES: raise StoreError('PATH_UNSAFE')
                actual[path.relative_to(backup).as_posix()]=digest(path.read_bytes())
        if actual!=expected: raise StoreError('DIGEST_MISMATCH')
        expected_dirs={'objects','journal'}
        for rel in actual:
            for parent in Path(rel).parents:
                if str(parent)!='.': expected_dirs.add(parent.as_posix())
        if actual_dirs!=expected_dirs: raise StoreError('INVENTORY_MISMATCH')
        # Only actual enumerated files are copied; signed path strings never select source paths.
        newroot.mkdir(mode=0o700,exist_ok=False)
        try:
            (newroot/'objects').mkdir(mode=0o700)
            (newroot/'journal').mkdir(mode=0o700)
            for rel in sorted(actual):
                target=newroot/rel
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream: stream.write((backup/rel).read_bytes())
            store=cls(newroot,trust,private_path=private_path,key_id=key_id,clock=clock)
            if store.tenant_id!=tenant_id or store.project_id!=project_id or store.config['store_id']!=payload['store_id'] or store.sequence!=payload['sequence'] or store.head_digest!=payload['head_digest']: raise StoreError('BACKUP_INVALID')
            with store._locked():
                store._authorize(authorization,'restore','store')
                store._append('restore','store',authorization)
            return store
        except Exception:
            shutil.rmtree(newroot); raise
