"""Caller-pinned project gate; code and evidence paths are protected inputs."""
from .. import security
from . import assessment_commands,profile


def add_commands(sub):
    parser=sub.add_parser('gate',help='reverify current project stage, code checks and stored evidence')
    assessment_commands.add_arguments(parser)
    for field in ('expected-commit','expected-subject-digest','expected-evaluation-digest'):
        parser.add_argument('--'+field,required=True)
    for field in ('code-evidence','code-context','evidence-store','evidence-id'):
        parser.add_argument('--'+field)


def execute(args):
    from . import stage_gate
    request=assessment_commands.load_request(args)
    store=None
    if args.evidence_store:
        from .evidence import ProjectEvidenceStore
        config=security.read_json(args.evidence_store)
        if type(config) is not dict or 'root' not in config or set(config)-{'root','checkpoint'}:
            raise profile.ProfileError('STORE_CONFIG_INVALID')
        store=ProjectEvidenceStore(config['root'],request['trust'],checkpoint=config.get('checkpoint'))
    result=stage_gate.evaluate(request,args.expected_commit,code_evidence=args.code_evidence,
        code_context=security.read_json(args.code_context) if args.code_context else None,
        expected_subject_digest=args.expected_subject_digest,expected_evaluation_digest=args.expected_evaluation_digest,
        evidence_store=store,evidence_id=args.evidence_id)
    return result,result['exit_code']
