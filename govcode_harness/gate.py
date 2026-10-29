"""Current-commit CI decision over unsigned local demonstration evidence.

The expected commit and required detector profile belong to the trusted caller.
A passing result does not grant institutional or operational approval.
"""
import argparse
import json
import re
from . import runtime


def _result(expected_commit):
    return {'kind': 'ci_gate', 'outcome': 'error', 'exit_code': 4,
            'expected_commit': expected_commit if isinstance(expected_commit, str) and re.fullmatch('[a-f0-9]{40}', expected_commit) else None,
            'checked_commit': None, 'input_mode': None,
            'checks': dict.fromkeys(('expected_commit', 'head', 'profile', 'evidence'), False),
            'operational_approval': False}


def _evaluate_local(repo, evidence, expected_commit, *, with_iron_laws=False, local_demo=False):
    """Fail closed unless receipt, profile, run commit and current HEAD agree."""
    result = _result(expected_commit)
    validated_repo = None
    code = 'GATE_ERROR'
    try:
        if local_demo is not True:
            raise runtime.HarnessError('LOCAL_DEMO_FLAG_REQUIRED')
        if type(with_iron_laws) is not bool:
            raise runtime.HarnessError('PROFILE_INVALID')
        if result['expected_commit'] is None:
            raise runtime.HarnessError('EXPECTED_COMMIT_INVALID')
        validated_repo = runtime._repo(repo, clean=False)
        runtime._validate_commit(validated_repo, expected_commit)
        result['checks']['expected_commit'] = True
        if runtime._head(validated_repo) != expected_commit:
            raise runtime.HarnessError('HEAD_MISMATCH')
        result['checks']['head'] = True
        output = runtime._safe_path(evidence)
        view = runtime._capture_evidence(output)
        run = view.read('run.json')
        if run.get('commit_sha') != expected_commit:
            result['checks']['expected_commit'] = False
            raise runtime.HarnessError('RUN_COMMIT_MISMATCH')
        result['checked_commit'] = expected_commit
        execution = view.read('execution.json')
        mode = runtime._read_input_scope(execution, expected_commit)
        result['input_mode'] = mode
        if runtime._detector_profile(execution) != with_iron_laws:
            raise runtime.HarnessError('PROFILE_MISMATCH')
        result['checks']['profile'] = True
        kwargs = {'commit': expected_commit} if mode == 'commit_snapshot' else {}
        verified = runtime.verify(validated_repo, output, local_demo=True, **kwargs)
        captured = runtime._verify_captured(validated_repo,output,local_demo=True,_snapshot=view,**kwargs)
        if verified['manifest_digest'] != captured['manifest_digest']:
            raise runtime.HarnessError('EVIDENCE_CHANGED')
        if verified.get('commit_sha') != expected_commit:
            result['checks']['expected_commit'] = False
            raise runtime.HarnessError('RUN_COMMIT_MISMATCH')
        outcome = verified.get('outcome')
        if outcome not in runtime.EXIT_CODES or verified.get('exit_code') != runtime.EXIT_CODES[outcome]:
            raise runtime.HarnessError('EVIDENCE_INVALID')
        result['checks']['evidence'] = True
        result.update(outcome=outcome, exit_code=runtime.EXIT_CODES[outcome])
        code = None
    except runtime.HarnessError as error:
        # Never echo exception text or codes supplied by a runtime extension.
        public = {'LOCAL_DEMO_FLAG_REQUIRED', 'PROFILE_INVALID', 'EXPECTED_COMMIT_INVALID',
                  'HEAD_MISMATCH', 'RUN_COMMIT_MISMATCH', 'PROFILE_MISMATCH'}
        code = error.code if error.code in public else 'VERIFICATION_FAILED'
    except Exception:
        code = 'GATE_ERROR'
    finally:
        if validated_repo is not None:
            try:
                if runtime._head(validated_repo) != expected_commit:
                    result['checks']['head'] = False
                    code = 'HEAD_MISMATCH'
            except Exception:
                result['checks']['head'] = False
                code = 'HEAD_CHECK_FAILED'
    if code:
        result.update(outcome='error', exit_code=4, code=code)
    return result


def evaluate(repo, evidence, expected_commit, *, with_iron_laws=False, local_demo=False,
             bundle=None, trust=None, tenant_id=None, project_id=None,
             min_sequence=None, revocations=None, exceptions=None, now=None):
    """Validate trusted authority inputs separately from the immutable raw decision.

    ``now`` is a controlled-clock injection for library tests. The CLI always uses
    the current UTC clock. No policy, trust or scope is inferred from repository input.
    """
    strict = any(v is not None for v in (bundle, trust, tenant_id, project_id, min_sequence, revocations, exceptions))
    result = _evaluate_local(repo, evidence, expected_commit,
                             with_iron_laws=with_iron_laws, local_demo=local_demo)
    if not strict:
        return result
    result.update(kind='reference_ci_gate', context='synthetic_reference',
                  raw_outcome=result['outcome'], raw_exit_code=result['exit_code'],
                  policy_receipt=None)
    try:
        from . import governance
        from datetime import datetime, timezone
        if any(v is None for v in (bundle, trust, tenant_id, project_id, min_sequence)):
            raise runtime.HarnessError('POLICY_CONTEXT_REQUIRED')
        context = runtime._context(tenant_id, project_id)
        when = now if now is not None else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        authority = governance.validate_bundle(bundle, trust, tenant_id, project_id, when,
                                               min_sequence=min_sequence, revocations=revocations)
        output = runtime._safe_path(evidence)
        view = runtime._capture_evidence(output)
        run = view.read('run.json')
        execution = view.read('execution.json')
        if runtime._recorded_context(run, execution) != context:
            raise runtime.HarnessError('CONTEXT_MISMATCH')
        policies = [entry['policy'] for entry in authority['policies']]
        # This reference gate implements only the local Python logging rule.
        if any(p['condition']['value'] != 'pii_logging_risk' or p['scope']['stage'] != 'merge' for p in policies):
            raise runtime.HarnessError('POLICY_UNSUPPORTED')
        if not policies:
            raise runtime.HarnessError('POLICIES_REQUIRED')
        mode = runtime._read_input_scope(execution, expected_commit)
        validated_repo = runtime._repo(repo, clean=False)
        verify_options = dict(local_demo=True,tenant_id=tenant_id,project_id=project_id)
        if mode == 'commit_snapshot':verify_options['commit'] = expected_commit
        checked = runtime._verify_captured(validated_repo,output,_snapshot=view,**verify_options)
        analysis = runtime._analysis(validated_repo, expected_commit,
            with_iron_laws=with_iron_laws, input_mode=mode)
        # Derive exception targets from trusted recomputation, not mutable files.
        fresh_run, _, findings, _ = runtime._objects(validated_repo, expected_commit, analysis,
            run['id'], run['started_at'], run['parent_run_id'], context)
        if fresh_run != run:
            raise runtime.HarnessError('EVIDENCE_CHANGED')
        matched = []
        required = {}
        for policy in policies:
            ids = [f['id'] for f in findings if f['category'] == policy['condition']['value'] and f['detector_id'] == 'python-local-flow']
            matched.append({'id':policy['id'], 'version':policy['version'], 'finding_ids':ids})
            required[(policy['id'], policy['version'])] = set(ids)
        accepted, covered = [], {key:set() for key in required}
        if exceptions is not None and type(exceptions) is not list:
            raise runtime.HarnessError('EXCEPTIONS_INVALID')
        for approval in exceptions or []:
            # A signed exception must validate against exactly one approved version.
            validated = []
            for policy in policies:
                try:
                    ids = governance.validate_exception(approval, trust, policy,
                        list(required[(policy['id'], policy['version'])]), when,
                        revocations=revocations,commit_sha=expected_commit,
                        tool_digest=fresh_run['tool_digest'],finding_digests={
                            f['id']:governance.finding_digest(fresh_run,f,policy) for f in findings
                            if f['id'] in required[(policy['id'],policy['version'])]})
                    validated.append((policy, ids))
                except governance.GovernanceError:
                    pass
            if len(validated) != 1:
                raise runtime.HarnessError('EXCEPTION_INVALID')
            policy, ids = validated[0]
            covered[(policy['id'], policy['version'])].update(ids)
            accepted.append(approval['payload']['event_id'])
        result['policy_receipt'] = {'bundle_digest':authority['bundle_digest'],
            'sequence':authority['sequence'], 'authority_context':runtime._context_object(context),
            'matched_policies':matched, 'exception_ids':sorted(accepted)}
        if result['raw_outcome'] == 'deny':
            known = bool(findings) and all(f['category'] == 'pii_logging_risk' and f['detector_id'] == 'python-local-flow' for f in findings)
            complete = all(required[key] <= covered[key] for key in required)
            if known and complete:
                result.update(outcome='allow', exit_code=0)
        # Recheck after authority and exception work; evidence and HEAD can race.
        final = _evaluate_local(repo, evidence, expected_commit,
            with_iron_laws=with_iron_laws, local_demo=local_demo)
        final_checked = runtime.verify(validated_repo,output,**verify_options)
        if (final['outcome'] != result['raw_outcome'] or final['checks'] != result['checks'] or
            final_checked['manifest_digest'] != checked['manifest_digest'] or
            runtime._head(validated_repo) != expected_commit):
            raise runtime.HarnessError('EVIDENCE_CHANGED')
        # Errors, review, profile/commit failures can never be relaxed.
    except Exception:
        result.update(outcome='error', exit_code=4, code='SIGNED_POLICY_VERIFICATION_FAILED')
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('INVALID_ARGUMENTS')


def main(argv=None):
    parser = _Parser(prog='python3 -m govcode_harness.gate')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--with-iron-laws', action='store_true')
    parser.add_argument('--local-demo', action='store_true')
    parser.add_argument('--bundle')
    parser.add_argument('--trust')
    parser.add_argument('--tenant-id')
    parser.add_argument('--project-id')
    parser.add_argument('--min-sequence', type=int)
    parser.add_argument('--revocations')
    parser.add_argument('--exceptions')
    try:
        args = parser.parse_args(argv)
        signed = {}
        if any(getattr(args, name) is not None for name in ('bundle','trust','tenant_id','project_id','min_sequence','revocations','exceptions')):
            from .security import read_json
            signed = {name:read_json(getattr(args,name)) if getattr(args,name) else None for name in ('bundle','trust','revocations','exceptions')}
            signed.update(tenant_id=args.tenant_id, project_id=args.project_id, min_sequence=args.min_sequence)
        result = evaluate(args.repo, args.evidence, args.expected_commit,
                          with_iron_laws=args.with_iron_laws, local_demo=args.local_demo, **signed)
    except Exception:
        result = _result(None)
        result['code'] = 'INVALID_ARGUMENTS'
    print(json.dumps(result, sort_keys=True))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
