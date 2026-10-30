"""Private proposal files and public metadata-only CLI acknowledgments."""
import datetime as dt
from .. import security
from . import contracts,profile


def add_commands(sub):
    propose=sub.add_parser('propose-documents',help='sign a bounded private design/trace proposal')
    for field in ('repo','commit','index','changes','trust','tenant-id','project-id','private-key','key-id','expires-at','output'):
        propose.add_argument('--'+field,required=True)
    approve=sub.add_parser('approve-documents',help='independently approve or reject a private proposal')
    for field in ('proposal','trust','private-key','key-id','expires-at','output'):
        approve.add_argument('--'+field,required=True)
    approve.add_argument('--decision',choices=('approve','reject'),default='approve')
    apply=sub.add_parser('apply-documents',help='apply approved document paths in a new private copy')
    for field in ('repo','proposal','approval','trust','output'):
        apply.add_argument('--'+field,required=True)


def execute(args):
    from . import document_proposal as proposals
    now=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    trust=security.read_json(args.trust)
    try:
        if args.command=='propose-documents':
            envelope=proposals.propose(args.repo,args.commit,args.index,security.read_json(args.changes),trust,now,
                tenant_id=args.tenant_id,project_id=args.project_id,private_path=args.private_key,
                key_id=args.key_id,expires_at=args.expires_at)
        elif args.command=='approve-documents':
            envelope=proposals.approve(security.read_json(args.proposal),trust,now,private_path=args.private_key,
                key_id=args.key_id,expires_at=args.expires_at,decision=args.decision)
        else:
            return proposals.apply(args.repo,security.read_json(args.proposal),security.read_json(args.approval),trust,now,output=args.output)
        profile._write_new(security.safe_path(args.output),envelope)
        return dict(kind='project_document_action',action=args.command,envelope_digest=contracts.digest(envelope),
            context=security.CONTEXT,operational_approval=False,requirements_evaluated=False,
            private_document_written=True,requires_independent_review=args.command=='propose-documents')
    except proposals.DocumentProposalError as error:
        raise profile.ProfileError(error.code) from None
