"""Load caller-protected original inputs; never accept an unsigned report as authority."""
import datetime as dt
from .. import security
from . import profile


def add_arguments(parser):
    for field in ('repo','commit','index','tenant-id','project-id','profile-registry','lock','trust','revocations','expected-revocation-digest'):
        parser.add_argument('--'+field,required=True)
    for field in ('profile-checkpoint','result-tools'):
        parser.add_argument('--'+field)
    for field in ('result-receipt','applicability-review','artifact-review'):
        parser.add_argument('--'+field,action='append',default=[])
    for field in ('min-sequence','min-revocation-epoch','min-profile-revision'):
        parser.add_argument('--'+field,type=int,default=1)


def load_request(args, *, trust_override=None, now=None):
    trust=security.read_json(args.trust) if trust_override is None else trust_override
    registry=profile.ProjectProfileRegistry(args.profile_registry,trust,
        checkpoint=security.read_json(args.profile_checkpoint) if args.profile_checkpoint else None)
    if (registry.tenant_id,registry.project_id)!=(args.tenant_id,args.project_id):
        raise profile.ProfileError('SCOPE_MISMATCH')
    return dict(repo=args.repo,commit=args.commit,index_path=args.index,profile_registry=registry,
        lock=security.read_json(args.lock),trust=trust,
        now=now or dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        revocations=security.read_json(args.revocations),expected_revocation_digest=args.expected_revocation_digest,
        applicability_reviews=[security.read_json(p) for p in args.applicability_review],
        result_receipts=[security.read_json(p) for p in args.result_receipt],
        result_tools=security.read_json(args.result_tools) if args.result_tools else None,
        reviews=[security.read_json(p) for p in args.artifact_review],
        min_sequence=args.min_sequence,min_revocation_epoch=args.min_revocation_epoch,
        min_profile_revision=args.min_profile_revision)


def evaluate_command(args):
    from . import assessment
    try:
        result=assessment.assess(**load_request(args))
        code={'ready_for_stage':0,'deny':2,'review_required':3,'error':4}[result['outcome']]
        if args.command=='plan':
            result=dict(kind='project_work_plan',context=security.CONTEXT,operational_approval=False,
                stage_gate_evaluated=False,subject_digest=result['subject_digest'],
                evaluation_digest=result['evaluation_digest'],counts=result['counts'],
                work_items=result['work_items'],assessment_outcome=result['outcome'])
        return result,code
    except assessment.AssessmentError as error:
        raise profile.ProfileError(error.code) from None
