"""Explicit local store commands; all authority inputs are caller-protected files."""
import datetime as dt
from pathlib import Path
import uuid

from .. import security
from . import assessment_commands,contracts as c,profile


def add_commands(sub):
    create=sub.add_parser('evidence-create',help='create a private scoped project evidence store')
    for name in ('root','trust','tenant-id','project-id','private-key','key-id'):create.add_argument('--'+name,required=True)
    put=sub.add_parser('evidence-put',help='recompute originals and store source-free project evidence')
    assessment_commands.add_arguments(put)
    for name in ('store','signer-key','signer-id','expected-commit','retain-until'):put.add_argument('--'+name,required=True)
    for name in ('code-evidence','code-context','parent-id'):put.add_argument('--'+name)
    put.add_argument('--legal-hold',action='store_true')
    for action in ('read','hold','delete','backup'):
        parser=sub.add_parser('evidence-'+action,help='authorized project store '+action)
        for name in ('store','trust','authorization','signer-key','signer-id'):parser.add_argument('--'+name,required=True)
        if action=='backup':parser.add_argument('--output',required=True)
        else:parser.add_argument('--evidence-id',required=True)
        if action=='hold':parser.add_argument('--enabled',choices=('true','false'),required=True)
    restore=sub.add_parser('evidence-restore',help='restore a signed backup using protected rollback anchors')
    for name in ('backup','output','trust','tenant-id','project-id','authorization','signer-key','signer-id','expected-head-digest'):
        restore.add_argument('--'+name,required=True)
    restore.add_argument('--minimum-sequence',type=int,required=True)
    authorize=sub.add_parser('evidence-authorize',help='sign a specific scoped store action')
    for name in ('store','trust','private-key','key-id','output'):authorize.add_argument('--'+name,required=True)
    authorize.add_argument('--action',choices=('read','set_hold','delete','backup','restore'),required=True)
    authorize.add_argument('--evidence-id',default='STORE');authorize.add_argument('--destination')
    authorize.add_argument('--enabled',choices=('true','false'))


def load_store(config_path, trust, *, private_path=None,key_id=None):
    from .evidence import ProjectEvidenceStore
    config=security.read_json(config_path)
    if type(config) is not dict or type(config.get('root')) is not str or set(config)-{'root','checkpoint'}:
        raise profile.ProfileError('STORE_CONFIG_INVALID')
    return ProjectEvidenceStore(config['root'],trust,private_path=private_path,key_id=key_id,checkpoint=config.get('checkpoint'))


def execute(args):
    from .evidence import ProjectEvidenceStore,StoreError
    trust=security.read_json(args.trust)
    try:
        if args.command=='evidence-create':
            store=ProjectEvidenceStore.create(args.root,trust,args.tenant_id,args.project_id,private_path=args.private_key,key_id=args.key_id)
            return dict(kind='project_store_created',checkpoint=store.checkpoint(),operational_approval=False)
        if args.command=='evidence-restore':
            store=ProjectEvidenceStore.restore(args.backup,args.output,trust,args.tenant_id,args.project_id,
                security.read_json(args.authorization),expected_head_digest=args.expected_head_digest,
                minimum_sequence=args.minimum_sequence,private_path=args.signer_key,key_id=args.signer_id)
            return dict(kind='project_store_restored',checkpoint=store.checkpoint(),release_approval=False,operational_approval=False)
        if args.command=='evidence-authorize':
            store=load_store(args.store,trust)
            params={}
            if args.action=='set_hold':
                if args.enabled is None:raise profile.ProfileError('AUTHORIZATION_PARAMETERS_REQUIRED')
                params={'enabled':args.enabled=='true'}
            elif args.action in ('backup','restore'):
                if not args.destination:raise profile.ProfileError('AUTHORIZATION_PARAMETERS_REQUIRED')
                params={'destination':str(security.safe_path(args.destination).resolve())}
                if args.evidence_id!='STORE':raise profile.ProfileError('AUTHORIZATION_SCOPE_INVALID')
            elif args.destination is not None or args.enabled is not None:
                raise profile.ProfileError('AUTHORIZATION_PARAMETERS_INVALID')
            now=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            payload=dict(kind='project_store_authorization',schema_version='1',context=security.CONTEXT,
                tenant_id=store.tenant_id,project_id=store.project_id,actor_id=trust['keys'][args.key_id]['actor_id'],
                operational_approval=False,store_id=store.store_id,action=args.action,evidence_id=args.evidence_id,
                event_id=uuid.uuid4().hex,time=now,parameters_digest=c.digest(params))
            envelope=security.sign(payload,args.private_key,args.key_id)
            security.verify(envelope,trust,'auditor' if args.action=='read' else 'operator',store.tenant_id,store.project_id)
            profile._write_new(security.safe_path(args.output),envelope)
            return dict(kind='project_store_authorization_written',authorization_digest=c.digest(envelope),operational_approval=False)
        store=load_store(args.store,trust,private_path=args.signer_key,key_id=args.signer_id)
        if args.command=='evidence-put':
            request=assessment_commands.load_request(args)
            identity=store.put(request,args.expected_commit,retain_until=args.retain_until,legal_hold=args.legal_hold,
                parent_id=args.parent_id,code_evidence=args.code_evidence,
                code_context=security.read_json(args.code_context) if args.code_context else None)
            return dict(kind='project_evidence_stored',evidence_id=identity,checkpoint=store.checkpoint(),operational_approval=False)
        authorization=security.read_json(args.authorization)
        if args.command=='evidence-read':return store.read(args.evidence_id,authorization)
        if args.command=='evidence-hold':return store.set_hold(args.evidence_id,args.enabled=='true',authorization)
        if args.command=='evidence-delete':return store.delete(args.evidence_id,authorization)
        return dict(kind='project_store_backup',checkpoint=store.backup(args.output,authorization),release_approval=False,operational_approval=False)
    except StoreError as error:
        raise profile.ProfileError(error.code) from None
