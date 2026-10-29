"""R7-A/D reference entry points; detector execution and project gates remain separate."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys

from . import security, project_contracts as contracts, project_profile as profiles, rule_pack, applicability


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise profiles.ProfileError('INVALID_ARGUMENTS')


def _write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(security.canonical(value))


def profile_demo(output):
    """Actually sign and persist two revisions; never claim requirement fulfillment."""
    root = security.safe_path(output)
    if root.exists():
        raise profiles.ProfileError('OUTPUT_EXISTS')
    root.mkdir(mode=0o700)
    private = root / 'private'
    private.mkdir(mode=0o700)
    current = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now = current.strftime('%Y-%m-%dT%H:%M:%SZ')
    end = (current + dt.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
    scope = dict(tenant_id='TENANT-REFERENCE', project_id='PROJECT-DELIVERY-REFERENCE')
    common = dict(schema_version='1', context=security.CONTEXT, operational_approval=False, **scope)
    keys = {}
    trust = {'context': security.CONTEXT, 'keys': {}}
    for actor, roles in [('profile-author', ['author', 'approver']), ('profile-reviewer', ['approver'])]:
        key = security.generate_keypair(private / actor, actor)
        keys[actor] = key
        trust['keys'][actor] = dict(public_key=key['public_key'], actor_id=actor, roles=roles,
                                   revoked=False, **scope)
    # Dual-role author is intentional: the negative check must reject the same actor.
    source = dict(context=security.CONTEXT, public_web=False, procurement_type='synthetic_fixed_scope')
    _write(root / 'source-example.json', source)
    profile = dict(common, kind='project_profile', id='PROFILE-DELIVERY', revision=1,
        parent_digest=None, jurisdiction='KR', project_type='software_delivery', stage='acceptance',
        owner_ref='profile-author', lifecycle='draft',
        source_refs=[dict(id='SRC-EXAMPLE', version='1', category='example', verification='confirmed',
                          digest=contracts.digest(source))],
        facts={'public_web': dict(state='known', value_type='boolean', value=False, source_ref='SRC-EXAMPLE'),
               'procurement_type': dict(state='unknown', owner_ref='profile-author', reason_ref='TASK-CONFIRM-CONTRACT')})
    registry = profiles.ProjectProfileRegistry.create(root / 'registry', trust=trust, **scope)
    nonce = 0

    def action(name, candidate, actor=None):
        nonlocal nonce
        nonce += 1
        actor = actor or ('profile-reviewer' if name == 'approve' else 'profile-author')
        value = dict(common, actor_id=actor, event_id=f'profile-event-{nonce}', created_at=now,
                     expected_revision=candidate['revision'] - 1 if name == 'revise' else candidate['revision'])
        if name == 'revise':
            value.update(kind='profile_action', action=name, profile=candidate)
        else:
            value.update(profile_id=candidate['id'], revision=candidate['revision'], profile_digest=contracts.digest(candidate))
            if name == 'approve':
                value.update(kind='profile_approval', decision='approve', reason_ref='REVIEW-REFERENCE', not_before=now, expires_at=end)
            else:
                value.update(kind='profile_action', action=name)
        return registry.apply(security.sign(value, keys[actor]['private_path'], actor), now)

    for name in ('revise', 'submit'):
        action(name, profile)
    blocked = False
    try:
        action('approve', profile, 'profile-author')
    except profiles.ProfileError as error:
        if error.code != 'SELF_APPROVAL':
            raise
        blocked = True
    action('approve', profile)
    initial = registry.active(profile['id'], now)
    _write(root / 'profile-v1.json', profile)
    revised = json.loads(security.canonical(profile))
    revised.update(revision=2, parent_digest=contracts.digest(profile))
    revised['facts']['procurement_type'] = dict(state='known', value_type='string',
                                              value=source['procurement_type'], source_ref='SRC-EXAMPLE')
    action('revise', revised)
    draft_kept_active = registry.active(profile['id'], now)['profile']['revision'] == 1
    for name in ('submit', 'approve'):
        action(name, revised)
    _write(root / 'profile-v2.json', revised)
    _write(root / 'public-trust.json', trust)
    _write(root / 'checkpoint.json', registry.checkpoint())
    active = registry.active(profile['id'], now)
    checks = dict(self_approval_blocked=blocked, draft_keeps_previous_approval=draft_kept_active,
                  unknown_preserved=len(initial['information_gaps']) == 1,
                  false_preserved=profiles.read_fact(active['profile'], 'public_web')['value'] is False,
                  revision_two_approved=active['profile']['revision'] == 2,
                  original_revision_immutable=registry.get(profile['id'], 1)['profile'] == profile)
    if not all(checks.values()):
        raise profiles.ProfileError('PROFILE_DEMO_INCOMPLETE')
    result = dict(kind='project_profile_demo', context=security.CONTEXT, operational_approval=False,
                  requirements_evaluated=False, active_revision=2, initial_information_gaps=1, checks=checks)
    _write(root / 'profile-demo-result.json', result)
    return result


def main(argv=None):
    try:
        parser = Parser(prog='python -m govcode_harness project')
        sub = parser.add_subparsers(dest='command', required=True)
        validate = sub.add_parser('validate-profile', help='validate profile facts; no approval or gate decision')
        validate.add_argument('--profile', required=True)
        validate.add_argument('--require-fact', action='append', default=[])
        demo = sub.add_parser('profile-demo', help='create a new private signed profile reference')
        demo.add_argument('--output', required=True)
        pack = sub.add_parser('validate-pack', help='validate declarative pack data; no publication')
        pack.add_argument('--manifest', required=True)
        pack.add_argument('--requirements', required=True)
        pack_demo = sub.add_parser('pack-demo', help='create a signed R7-C/D reference with review and revocation')
        pack_demo.add_argument('--output', required=True)
        assess = sub.add_parser('assess-applicability', help='verify original proofs and resolve applicability only')
        for field in ('profile-registry','lock','trust','revocations','expected-revocation-digest','tenant-id','project-id'):
            assess.add_argument('--'+field, required=True)
        assess.add_argument('--min-sequence',type=int,default=1)
        assess.add_argument('--min-revocation-epoch',type=int,default=1)
        assess.add_argument('--min-profile-revision',type=int,default=1)
        assess.add_argument('--review',action='append',default=[])
        kit = sub.add_parser('document-kit', help='generate AI-friendly design drafts and separate review notes')
        kit.add_argument('--output', required=True)
        kit.add_argument('--context')
        args = parser.parse_args(argv)
        if args.command == 'document-kit':
            from .document_generation import generate
            result = generate(args.output, security.read_json(args.context) if args.context else None)
            code = 0
        elif args.command == 'profile-demo':
            result = profile_demo(args.output)
            code = 0
        elif args.command == 'pack-demo':
            from .rule_pack_reference import demo as run_demo
            result = run_demo(args.output)
            code = 0
        elif args.command == 'validate-pack':
            value = rule_pack.validate_pack(security.read_json(args.manifest),security.read_json(args.requirements))
            result = dict(kind='rule_pack_validation',valid=True,pack_digest=contracts.digest(value),
                          approval_status='not_checked',requirements_evaluated=False,operational_approval=False)
            code = 0
        elif args.command == 'assess-applicability':
            trust = security.read_json(args.trust)
            registry = profiles.ProjectProfileRegistry(args.profile_registry,trust)
            if (registry.tenant_id,registry.project_id) != (args.tenant_id,args.project_id):
                raise profiles.ProfileError('SCOPE_MISMATCH')
            now = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            result = applicability.assess(security.read_json(args.lock),registry,trust,now,
                revocations=security.read_json(args.revocations),expected_revocation_digest=args.expected_revocation_digest,
                min_sequence=args.min_sequence,min_revocation_epoch=args.min_revocation_epoch,min_profile_revision=args.min_profile_revision,
                reviews=[security.read_json(path) for path in args.review])
            code = 3 if result['outcome']=='review_required' else 0
        else:
            profile = contracts.load(args.profile)
            gaps = profiles.information_gaps(profile, args.require_fact)
            result = dict(kind='project_profile_validation', valid=True, profile_id=profile['id'],
                revision=profile['revision'], profile_digest=contracts.digest(profile),
                information_gaps=gaps, approval_status='not_checked', requirements_evaluated=False,
                context=security.CONTEXT, operational_approval=False,
                outcome='review_required' if gaps else 'validated')
            code = 3 if gaps else 0
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return code
    except (profiles.ProfileError, contracts.ContractError, security.SecurityError,
            rule_pack.PackError, applicability.ApplicabilityError) as error:
        print(json.dumps(dict(outcome='error', code=error.code)), file=sys.stderr)
        return 4
    except Exception:
        print(json.dumps(dict(outcome='error', code='PROJECT_COMMAND_FAILED')), file=sys.stderr)
        return 4
