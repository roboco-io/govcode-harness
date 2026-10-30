"""Independent, contract-authored R7-E acceptance samples using real Git and signatures.

The 24 sample definitions were written without reading the implementation or its
unit tests. Structural success is deliberately not fulfillment or gate approval.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness import security, snapshot
from govcode_harness.project import contracts

CASES = json.loads((Path(__file__).parent / 'fixtures/delivery-trace/acceptance_cases.json').read_text())['cases']
NOW = '2026-10-30T00:30:00Z'
START = '2026-10-30T00:00:00Z'
END = '2026-10-30T01:00:00Z'
SENTINEL = 'PRIVATE_REQUIREMENT_NARRATIVE_54f7'


def ref(value):
    return dict(kind=value['kind'], id=value['id'], version=value['version'], digest=contracts.digest(value))


class IndependentDeliveryTraceAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        snapshot.run_git(self.repo, 'init', '-b', 'main')
        self.key = security.generate_keypair(self.root / 'operator', 'acceptance-operator')
        self.common = dict(schema_version='1', context=security.CONTEXT, tenant_id='ACCEPTANCE-TENANT',
                           project_id='ACCEPTANCE-PROJECT', operational_approval=False)
        self.trust = dict(context=security.CONTEXT, keys={'acceptance-operator':dict(
            public_key=self.key['public_key'],actor_id='acceptance-runner',roles=['operator'],revoked=False,
            tenant_id=self.common['tenant_id'],project_id=self.common['project_id'])})
        self.tools = {'CHECK-A':dict(adapter_id='acceptance-runner', tool_digest='7' * 64)}

    def build(self, scenario):
        documents = {
            'ART-DESIGN': ['design', 'docs/design.md', b'# Design\n\nThe service returns a receipt.\n'],
            'ART-PLAN': ['test_plan', 'docs/plan.md', b'# Test plan\n\nThe tester checks the receipt.\n'],
            'ART-RESULT': ['test_result', 'results/result.json', b'{"passed":true,"count":1}\n'],
            'ART-REVIEW': ['review_record', 'reviews/review.md', b'# Review record\n\nApproval is not asserted here.\n'],
        }
        if scenario == 'korean_paths':
            documents['ART-DESIGN'][1] = '문서/설계.md'
            documents['ART-REVIEW'][1] = '검토/기록.md'
        elif scenario == 'fenced_code_headings':
            documents['ART-DESIGN'][2] = b'# Design\n\n```text\n##### sample code heading\n```\n\n## Boundary\n\nOnly authorized data is returned.\n'
        elif scenario == 'equal_bytes_distinct_artifacts':
            documents['ART-DESIGN'][2] = documents['ART-PLAN'][2] = b'# Document\n\nThe owner checks the service.\n'
        elif scenario == 'sensitive_text_not_reported':
            documents['ART-DESIGN'][2] = ('# Design\n\n' + SENTINEL + '\n').encode()
        elif scenario == 'sequential_markdown_sections':
            documents['ART-DESIGN'][2] = b'# Design\n\n## Interface\n\nThe service accepts a request.\n\n### Error response\n\nThe service returns a safe error.\n\n## Storage\n\nThe owner controls access.\n'
        elif scenario == 'unsupported_required_document':
            documents['ART-DESIGN'][1] = 'docs/design.hwpx'
            documents['ART-DESIGN'][2] = b'PK\x03\x04synthetic unsupported input'
        elif scenario == 'non_utf8_required_document':
            documents['ART-DESIGN'][2] = b'\xff\xfeinvalid'
        elif scenario == 'raw_html_needs_review':
            documents['ART-DESIGN'][2] = b'# Design\n\n<div>Do not execute this HTML.</div>\n'
        elif scenario == 'required_artifact_not_on_requirement_path':
            documents['ART-UNRELATED'] = ['design', 'docs/unrelated.md', b'# Unrelated design\n\nThis is not connected.\n']
        artifacts=[]
        for name,(kind,path,raw) in documents.items():
            artifact=dict(self.common,kind='artifact_ref',id=name,version='1',artifact_kind=kind,
                          relative_path=path,content_digest=hashlib.sha256(raw).hexdigest())
            artifacts.append(artifact)
            target=self.repo/path
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw)
        req=dict(self.common,kind='requirement_spec',id='REQ-ACCEPTANCE',version='1',
                 source_ref=dict(id='SRC-ACCEPTANCE',version='1',category='example',verification='confirmed',digest='4'*64),
                 source_category='example',source_verification='confirmed',normativity='example',basis_kind='example_policy',
                 applicability_expr=dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=True)),
                 stages=['design'],required_artifacts=['ART-DESIGN','ART-PLAN','ART-RESULT','ART-REVIEW'],
                 check_refs=['CHECK-A'],review_required=True)
        if scenario == 'required_artifact_not_on_requirement_path':
            req['required_artifacts'].append('ART-UNRELATED')
        if scenario == 'second_required_check_has_no_receipt':
            req['check_refs'].append('CHECK-B')
            self.tools['CHECK-B']=dict(adapter_id='acceptance-runner',tool_digest='8'*64)
        by_id={a['id']:a for a in artifacts}
        path=[req,by_id['ART-DESIGN'],by_id['ART-PLAN'],by_id['ART-RESULT'],by_id['ART-REVIEW']]
        traces=[dict(self.common,kind='trace_link',id='TRACE-'+str(n),version='1',
                     from_ref=ref(path[n]),to_ref=ref(path[n+1]),relation=relation)
                for n,relation in enumerate(('implements','verifies','reports','reviews'))]
        if scenario == 'missing_plan_link':
            del traces[1]
        elif scenario == 'dangling_artifact_reference':
            traces[1]['to_ref']['id']='ART-NOT-PRESENT'
        elif scenario == 'duplicate_artifact_id':
            artifacts.append(copy.deepcopy(artifacts[0]))
        elif scenario == 'wrong_content_digest':
            artifacts[0]['content_digest']='0'*64
        elif scenario == 'cross_project_artifact':
            artifacts[0]['project_id']='OTHER-PROJECT'
        index=dict(self.common,kind='project_artifact_index',artifacts=artifacts,requirements=[req],traces=traces)
        (self.repo/'artifact-index.json').write_bytes(security.canonical(index))
        if scenario == 'unrelated_tracked_file':
            (self.repo/'ordinary.txt').write_text('Unregistered supporting text.\n')
        snapshot.run_git(self.repo,'add','--all')
        snapshot.run_git(self.repo,'commit','-m','independent synthetic acceptance input')
        commit=snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip()
        if scenario == 'dirty_worktree_is_not_input':
            (self.repo/documents['ART-DESIGN'][1]).write_text('# Changed worktree\n\nThis was not committed.\n')
            (self.repo/'untracked.txt').write_text('This was not committed.\n')
        return index,commit

    def exercise(self, case):
        # Delayed imports let sample authoring remain independent of production arrival.
        from govcode_harness.project import artifact_snapshot,delivery_trace
        index,commit=self.build(case['scenario'])
        try:
            collected=artifact_snapshot.collect(self.repo,commit,'artifact-index.json',
                tenant_id=self.common['tenant_id'],project_id=self.common['project_id'])
            result_artifact=next(a for a in index['artifacts'] if a['id']=='ART-RESULT')
            payload=dict(self.common,kind='artifact_test_attestation',actor_id='acceptance-runner',
                event_id='EXEC-ACCEPTANCE-A',created_at=START,not_before=START,expires_at=END,
                commit_sha='0'*40 if case['scenario']=='receipt_for_another_commit' else commit,
                artifact_manifest_digest=contracts.digest(collected['manifest']),requirement_ref=ref(index['requirements'][0]),
                result_artifact_ref=ref(result_artifact),check_id='CHECK-A',adapter_id='acceptance-runner',
                tool_digest=self.tools['CHECK-A']['tool_digest'],result='pass')
            receipt=security.sign(payload,self.key['private_path'],'acceptance-operator')
            if case['scenario']=='forged_result_signature':
                signature=receipt['signature']
                receipt['signature']=('A' if signature[0]!='A' else 'B')+signature[1:]
            receipts=[] if case['scenario']=='passed_text_without_receipt' else [receipt]
            report=delivery_trace.inspect(collected,now=NOW,
                expected_requirements=None if case['scenario']=='requirement_authority_not_supplied' else copy.deepcopy(index['requirements']),
                result_receipts=receipts,trust=None if case['scenario']=='trusted_key_not_supplied' else self.trust,
                allowed_result_tools=None if case['scenario']=='tool_authority_not_supplied' else self.tools)
        except (artifact_snapshot.ArtifactSnapshotError,delivery_trace.DeliveryTraceError) as error:
            if case['expected']!='not_passed':
                raise
            self.assertTrue(error.code)
            return
        rendered=json.dumps(report,ensure_ascii=False)
        self.assertNotIn(SENTINEL,rendered)
        self.assertFalse(report['requirements_evaluated'])
        self.assertFalse(report['operational_approval'])
        if case['expected']=='not_passed':
            self.assertNotEqual('checks_passed',report['outcome'])
            self.assertTrue(report.get('findings'),report)
        else:
            self.assertEqual(case['expected'],report['outcome'],report)
        if case['scenario']=='dirty_worktree_is_not_input':
            self.assertEqual(commit,report['commit_sha'])
            self.assertFalse(collected['manifest']['worktree_checked'])


def _test(case):
    def run(self):
        self.exercise(case)
    run.__doc__=case['id']+': '+case['scenario']
    return run


for _case in CASES:
    setattr(IndependentDeliveryTraceAcceptance,'test_'+_case['id'].lower()+'_'+_case['scenario'],_test(_case))
