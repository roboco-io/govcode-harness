"""Execute a synthetic document trace repair; no requirement or gate approval."""
import datetime as dt
import hashlib
from pathlib import Path

from .. import security, snapshot
from . import artifact_snapshot, contracts as c, delivery_trace, profile


def reference(value):
    return dict(kind=value['kind'], id=value['id'], version=value['version'], digest=c.digest(value))


def demo(output):
    root = security.safe_path(output)
    if root.exists():
        raise profile.ProfileError('OUTPUT_EXISTS')
    root.mkdir(mode=0o700)
    repo = root / 'repo'
    repo.mkdir(mode=0o700)
    snapshot.run_git(repo, 'init', '-b', 'main')
    common = dict(schema_version='1', context=security.CONTEXT, tenant_id='TENANT-REFERENCE',
                  project_id='PROJECT-ARTIFACT-REFERENCE', operational_approval=False)
    scope = {key: common[key] for key in ('tenant_id', 'project_id')}
    key = security.generate_keypair(root / 'private', 'synthetic-test-operator')
    trust = dict(context=security.CONTEXT, keys={'synthetic-test-operator': dict(actor_id='synthetic-test-operator',
        public_key=key['public_key'], roles=['operator'], revoked=False, **scope)})
    clock = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now = clock.strftime('%Y-%m-%dT%H:%M:%SZ')
    end = (clock + dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    # This is an authored synthetic assertion, not execution of any submitted code.
    actual = sum((1, 1))
    if actual != 2:
        raise profile.ProfileError('SYNTHETIC_TEST_FAILED')
    raw = {'design.md': '# 설계\n\n이 합성 설계는 두 수를 더한다. PRIVATE-CONTENT\n',
           'plan.md': '# 시험 계획\n\n합성 시험은 1과 1을 더한 값이 2인지 확인한다.\n',
           'result.json': security.canonical(dict(context=security.CONTEXT, case='synthetic-addition',
                                                actual=actual, expected=2, result='pass')).decode(),
           'review.md': '# 검토 기록\n\n담당자의 독립 검토가 필요하다.\n'}
    artifacts = []
    for name, kind, identity in [('design.md','design','ART-DESIGN'),('plan.md','test_plan','ART-PLAN'),
                                  ('result.json','test_result','ART-RESULT'),('review.md','review_record','ART-REVIEW')]:
        data = raw[name].encode('utf-8')
        (repo / name).write_bytes(data)
        artifacts.append(dict(common, kind='artifact_ref', id=identity, version='1', artifact_kind=kind,
                              relative_path=name, content_digest=hashlib.sha256(data).hexdigest()))
    requirement = dict(common, kind='requirement_spec', id='REQ-SYNTHETIC', version='1',
        source_ref=dict(id='SRC-SYNTHETIC',version='1',category='example',verification='confirmed',
                        digest=c.digest(dict(example='addition'))),
        source_category='example',source_verification='confirmed',normativity='example',basis_kind='example_policy',
        applicability_expr=dict(op='eq',fact='synthetic_case',value=dict(value_type='boolean',value=True)),
        stages=['verification'],required_artifacts=[a['id'] for a in artifacts],
        check_refs=['CHECK-SYNTHETIC'],review_required=True)
    nodes = [requirement, *artifacts]
    links = [dict(common, kind='trace_link', id='LINK-'+str(i), version='1', from_ref=reference(nodes[i]),
                  to_ref=reference(nodes[i+1]), relation=relation)
             for i, relation in enumerate(('implements','verifies','reports','reviews'))]
    index = dict(common, kind='project_artifact_index', requirements=[requirement], artifacts=artifacts,
                 traces=[link for link in links if link['relation'] != 'reports'])
    def commit(message):
        (repo / 'artifacts.json').write_bytes(security.canonical(index))
        snapshot.run_git(repo, 'add', '--all')
        snapshot.run_git(repo, 'commit', '-m', message)
        return snapshot.run_git(repo, 'rev-parse', 'HEAD').decode().strip()
    before_sha = commit('synthetic missing trace')
    before = artifact_snapshot.collect(repo, before_sha, 'artifacts.json', **scope)
    before_report = delivery_trace.inspect(before, now=now)
    index['traces'] = links
    after_sha = commit('repair synthetic trace')
    after = artifact_snapshot.collect(repo, after_sha, 'artifacts.json', **scope)
    tools = {'CHECK-SYNTHETIC': dict(adapter_id='synthetic.addition', tool_digest=c.digest(dict(adapter='synthetic.addition',version='1')))}
    def receipt(captured, event):
        payload = dict(common, kind='artifact_test_attestation', actor_id='synthetic-test-operator', event_id=event,
            created_at=now,not_before=now,expires_at=end,commit_sha=captured['manifest']['commit_sha'],
            artifact_manifest_digest=c.digest(captured['manifest']),requirement_ref=reference(requirement),
            result_artifact_ref=reference(artifacts[2]),check_id='CHECK-SYNTHETIC',result='pass',**tools['CHECK-SYNTHETIC'])
        return security.sign(payload,key['private_path'],'synthetic-test-operator')
    signed = receipt(after,'RESULT-AFTER')
    after_report = delivery_trace.inspect(after, now=now, trust=trust, result_receipts=[signed], allowed_result_tools=tools)
    stale_rejected = False
    try:
        stale = delivery_trace.inspect(after, now=now, trust=trust,
            result_receipts=[receipt(before,'RESULT-OLD')], allowed_result_tools=tools)
        stale_rejected = stale['outcome'] == 'error'
    except delivery_trace.DeliveryTraceError:
        stale_rejected = True
    def status(report, name):
        return next(item['status'] for item in report['checks'] if item['check_id'] == name)
    trace_codes = {'TRACE_CHAIN_INCOMPLETE', 'REQUIRED_ARTIFACT_MISSING'}
    checks = dict(trace_defect_detected=any(f['code'] in trace_codes for f in before_report['findings']),
        trace_repaired=not any(f['code'] in trace_codes for f in after_report['findings']),
        unsigned_result_not_trusted=status(before_report,'result_binding') != 'pass',
        signed_result_verified=status(after_report,'result_binding') == 'pass',
        old_commit_result_rejected=stale_rejected,
        no_fulfillment_claim=not after_report['requirements_evaluated'] and after_report['outcome']=='review_required')
    if not all(checks.values()):
        raise profile.ProfileError('ARTIFACT_DEMO_INCOMPLETE')
    values = {'before-report.json': before_report,'after-report.json': after_report,'public-trust.json':trust,
              'result-tools.json':tools,'after-result.json':signed}
    for name,value in values.items():
        profile._write_new(root / name, value)
    result = dict(kind='artifact_trace_demo',context=security.CONTEXT,operational_approval=False,
        requirements_evaluated=False,before_commit=before_sha,after_commit=after_sha,checks=checks)
    profile._write_new(root / 'artifact-demo-result.json', result)
    return result
