"""CLI integration; trusted pack inputs remain outside the inspected checkout."""
import datetime as dt

from .. import security
from . import packs, profile


def inspect_command(args):
    from . import artifact_snapshot, delivery_trace
    try:
        fields = ('profile_registry', 'lock', 'revocations', 'expected_revocation_digest')
        authority = [getattr(args, name) for name in fields]
        if any(authority) and (not all(authority) or not args.trust):
            raise profile.ProfileError('PACK_AUTHORITY_INCOMPLETE')
        now = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        trust = security.read_json(args.trust) if args.trust else None
        tools = security.read_json(args.result_tools) if args.result_tools else None
        expected = None
        if all(authority):
            registry = profile.ProjectProfileRegistry(args.profile_registry, trust,
                checkpoint=security.read_json(args.profile_checkpoint) if args.profile_checkpoint else None)
            if (registry.tenant_id, registry.project_id) != (args.tenant_id, args.project_id):
                raise profile.ProfileError('SCOPE_MISMATCH')
            feed = security.read_json(args.revocations)
            original_lock = security.read_json(args.lock)
            verified = packs.verify_lock(original_lock, trust, args.tenant_id, args.project_id, now,
                revocations=feed, profile_registry=registry, expected_revocation_digest=args.expected_revocation_digest,
                min_sequence=args.min_sequence, min_revocation_epoch=args.min_revocation_epoch,
                min_profile_revision=args.min_profile_revision)
            expected = verified['requirements']
            # These manifests are read only after original signatures and lock closure verify.
            declared = {}
            for release in original_lock['payload']['pack_releases']:
                manifest = release['payload']['author_record']['payload']['manifest']
                for check in manifest['check_specs']:
                    declared.setdefault(check['id'], set()).add(check['adapter_id'])
            if tools is not None:
                if type(tools) is not dict:
                    raise profile.ProfileError('RESULT_TOOL_AUTHORITY_INVALID')
                for requirement in expected:
                    for name in requirement['check_refs']:
                        if name in tools and (type(tools[name]) is not dict or
                                len(declared.get(name, set())) != 1 or
                                tools[name].get('adapter_id') not in declared[name]):
                            raise profile.ProfileError('PACK_CHECK_ADAPTER_MISMATCH')
            revoked = packs.verify_revocations(feed, trust, args.tenant_id, args.project_id, now,
                expected_digest=args.expected_revocation_digest, min_epoch=args.min_revocation_epoch)
            for key in revoked['key_ids']:
                if key in trust['keys']:
                    trust['keys'][key]['revoked'] = True
        elif args.profile_checkpoint:
            raise profile.ProfileError('PACK_AUTHORITY_INCOMPLETE')
        collected = artifact_snapshot.collect(args.repo, args.commit, args.index,
            tenant_id=args.tenant_id, project_id=args.project_id)
        result = delivery_trace.inspect(collected, now=now, expected_requirements=expected, trust=trust,
            result_receipts=[security.read_json(path) for path in args.result_receipt],
            allowed_result_tools=tools)
        return result, {'checks_passed': 0, 'defects_found': 2, 'review_required': 3, 'error': 4}[result['outcome']]
    except (artifact_snapshot.ArtifactSnapshotError, delivery_trace.DeliveryTraceError) as error:
        raise profile.ProfileError(error.code) from None
