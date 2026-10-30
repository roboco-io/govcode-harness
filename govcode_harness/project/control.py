"""Scoped project desk. All assessment and signing inputs come from admin config."""
from argparse import Namespace
from contextlib import contextmanager
import datetime as dt
import fcntl
import os
from pathlib import Path
import uuid

from .. import security, governance
from ..control_plane import ControlError, fields
from . import assessment, assessment_commands, contracts as c, packs


class ProjectService:
    def __init__(self, desk, contexts):
        self.desk=desk
        self.contexts={}
        for context in contexts:
            identity=(context['tenant_id'],context['project_id'])
            if identity not in desk.scopes or identity in self.contexts:
                raise ControlError('CONFIG_SCOPE_INVALID')
            args=context['assessment']
            if (args['tenant_id'],args['project_id'])!=identity:
                raise ControlError('CONFIG_SCOPE_INVALID')
            root=security.safe_path(context['control_root'])
            root.mkdir(mode=0o700,parents=False,exist_ok=True)
            if root.stat().st_mode & 0o077: raise ControlError('CONTROL_ROOT_NOT_PRIVATE')
            self.contexts[identity]=dict(context,control_root=str(root))

    @contextmanager
    def locked(self, context):
        path=Path(context['control_root'])/'project-reviews.lock'
        fd=os.open(security.safe_path(path),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            if os.fstat(fd).st_mode & 0o077: raise ControlError('CONTROL_LOCK_NOT_PRIVATE')
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def request(self, context, current):
        args=dict(profile_checkpoint=None,result_tools=None,result_receipt=[],applicability_review=[],artifact_review=[],
            min_sequence=1,min_revocation_epoch=1,min_profile_revision=1)
        args.update(context['assessment'])
        return assessment_commands.load_request(Namespace(**args),trust_override=self.desk.trust,now=current)

    def assess(self, context, current, principal):
        self.principal(principal,None)
        request=self.request(context,current)
        self.principal(principal,request)
        # First verify current originals independently of historical service reviews.
        initial=assessment.assess(**request)
        active=[]
        for path in sorted(Path(context['control_root']).glob('project-review-*.json')):
            proof=security.read_json(path)
            payload=security.verify(proof,self.desk.trust,'approver',context['tenant_id'],context['project_id'])
            # Expiry removes authority, not history. Verify before filtering so
            # tampering and future-dated records cannot disappear from checks.
            if (set(payload)!=assessment.REVIEW_FIELDS or payload['kind']!='project_artifact_review'
                or payload['schema_version']!='1' or payload['operational_approval'] is not False):
                raise ControlError('REVIEW_INVALID')
            created=c.timestamp(payload['created_at']);expires=c.timestamp(payload['expires_at'])
            if not c.timestamp(payload['not_before'])<=created<expires or created>c.timestamp(current):
                raise ControlError('REVIEW_EXPIRED_OR_FUTURE')
            if expires<=c.timestamp(current):
                continue
            if payload.get('subject_digest')==initial['subject_digest']:
                active.append(proof)
        request['reviews']=request['reviews']+active
        return request,assessment.assess(**request)

    def principal(self, principal, request):
        identity=(principal['tenant_id'],principal['project_id'])
        key=self.desk.trust['keys'].get(principal['key_id'],{})
        if (key.get('revoked') is not False or key.get('actor_id')!=principal['actor_id']
            or (key.get('tenant_id'),key.get('project_id'))!=identity
            or not set(principal['roles'])<=set(key.get('roles',[]))):
            raise ControlError('AUTH_REQUIRED',401)
        if not set(principal['roles']) & {'author','approver','operator','auditor'}:
            raise ControlError('ROLE_REQUIRED',403)
        if request is None:return
        revoked=packs.verify_revocations(request['revocations'],self.desk.trust,*identity,request['now'],
            min_epoch=request['min_revocation_epoch'],expected_digest=request['expected_revocation_digest'])
        if principal['key_id'] in revoked['key_ids']:raise ControlError('PRINCIPAL_REVOKED',403)

    def stage(self, context, request):
        bindings=context.get('stage_bindings')
        if bindings is None:
            return dict(outcome='pending',allowed=False,reason_codes=['STAGE_EVIDENCE_REQUIRED'])
        required={'expected_commit','expected_subject_digest','expected_evaluation_digest','evidence_store','evidence_id'}
        try:
            if type(bindings) is not dict or not required<=set(bindings)<=required|{'code_context','code_evidence'}:
                raise ControlError('STAGE_CONFIG_INVALID')
            from .evidence_commands import load_store
            from .stage_gate import evaluate
            store=load_store(bindings['evidence_store'],self.desk.trust)
            receipt=evaluate(request,bindings['expected_commit'],evidence_store=store,evidence_id=bindings['evidence_id'],
                code_evidence=bindings.get('code_evidence'),
                code_context=security.read_json(bindings['code_context']) if bindings.get('code_context') else None,
                expected_subject_digest=bindings['expected_subject_digest'],
                expected_evaluation_digest=bindings['expected_evaluation_digest'])
            return dict(outcome=receipt['outcome'],allowed=receipt['outcome']=='allow',reason_codes=receipt['reason_codes'],
                candidate_digest=receipt['candidate_digest'],evidence_ref=receipt['evidence_ref'])
        except Exception:
            return dict(outcome='error',allowed=False,reason_codes=['STAGE_EVIDENCE_VERIFICATION_FAILED'])

    def public(self, report, principal):
        keys=('tenant_id','project_id','commit_sha','stage','subject_digest','evaluation_digest','counts','outcome',
            'requirements','work_items','profile_ref','profile_digest','lock_digest','artifact_manifest_digest','reason_codes')
        result={key:report[key] for key in keys}
        result.update(context=security.CONTEXT,operational_approval=False,roles=principal['roles'],
            stage_gate=dict(outcome='pending',allowed=False,reason_codes=['STAGE_EVIDENCE_REQUIRED']),
            independent_review_required=True)
        return result

    def handle(self, method, route, principal, body, current):
        identity=principal['tenant_id'],principal['project_id']
        if identity not in self.contexts:raise ControlError('PROJECT_NOT_CONFIGURED',404)
        context=self.contexts[identity]
        if method=='POST' and route=='/api/projects/reviews':
            if 'approver' not in principal['roles']:raise ControlError('ROLE_REQUIRED',403)
            fields(body,('requirement_id','decision','reason_ref','expected_subject_digest'))
            security.identifier(body['requirement_id']);security.identifier(body['reason_ref'])
            if body['decision'] not in ('approved','rejected','review_required'):raise ControlError('REVIEW_DECISION_INVALID')
            with self.locked(context):
                request,report=self.assess(context,current,principal)
                self.principal(principal,request)
                if body['expected_subject_digest']!=report['subject_digest']:raise ControlError('REVIEW_SUBJECT_MISMATCH',409)
                row=next((r for r in report['requirements'] if r['requirement_ref']['id']==body['requirement_id']),None)
                if row is None:raise ControlError('REQUIREMENT_NOT_FOUND',404)
                if row['review_refs']:raise ControlError('REVIEW_DUPLICATE',409)
                expires=(c.timestamp(current)+dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
                event=uuid.uuid4().hex
                proof=self.desk.sign(principal,identity,dict(kind='project_artifact_review',schema_version='1',
                    operational_approval=False,event_id=event,created_at=current,not_before=current,expires_at=expires,
                    subject_digest=report['subject_digest'],requirement_ref=row['requirement_ref'],
                    artifact_digests=row['artifact_digests'],decision=body['decision'],reason_ref=body['reason_ref']))
                # The core enforces actor separation, exact digests and current trust before any write.
                validated=assessment.assess(**dict(request,reviews=request['reviews']+[proof]))
                path=security.safe_path(Path(context['control_root'])/f'project-review-{event}.json')
                governance._write_new(path,proof)
                return dict(id=event,subject_digest=validated['subject_digest'],evaluation_digest=validated['evaluation_digest'],
                    operational_approval=False,state=body['decision'])
        routes={'/api/projects','/api/projects/current','/api/projects/profiles','/api/projects/pack-locks',
            '/api/projects/work-items','/api/projects/evaluations'}
        if method!='GET' or route not in routes:raise ControlError('NOT_FOUND',404)
        with self.locked(context):
            request,report=self.assess(context,current,principal)
            self.principal(principal,request)
            value=self.public(report,principal)
            value['stage_gate']=self.stage(context,request)
            if route.endswith('/profiles'):return dict(profile_ref=value['profile_ref'],stage=value['stage'],profile_digest=value['profile_digest'],operational_approval=False)
            if route.endswith('/pack-locks'):return dict(lock_digest=value['lock_digest'],counts=value['counts'],operational_approval=False)
            if route.endswith('/work-items'):return value['work_items']
            return value
