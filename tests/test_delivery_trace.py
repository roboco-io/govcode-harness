"""Independent structural checks never grant requirement fulfillment or approval."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness import security
from govcode_harness.project import contracts as c

NOW='2026-10-30T00:00:00Z'
END='2026-10-30T01:00:00Z'
COMMON=dict(schema_version='1',context=security.CONTEXT,tenant_id='t',project_id='p',operational_approval=False)


def reference(value):
    return dict(kind=value['kind'],id=value['id'],version=value['version'],digest=c.digest(value))


def fixture():
    values=json.loads((Path(__file__).parent/'fixtures/project-compliance/contract-set.example.json').read_text())
    req=copy.deepcopy(next(x for x in values if x['kind']=='requirement_spec'))
    contents={'D':b'# Design\n\nPRIVATE_BODY_SENTINEL\n','P':b'# Test plan\n\nExercise behavior.\n','R':b'{"passed":true}', 'V':b'# Review\n\nApproved by anyone.\n'}
    kinds={'D':'design','P':'test_plan','R':'test_result','V':'review_record'}
    paths={'D':'docs/design.md','P':'docs/plan.md','R':'docs/result.json','V':'docs/review.md'}
    arts=[dict(COMMON,kind='artifact_ref',id=k,version='1',artifact_kind=kinds[k],relative_path=paths[k],content_digest=hashlib.sha256(v).hexdigest()) for k,v in contents.items()]
    req['required_artifacts']=['D','P','R','V']
    by_id={a['id']:a for a in arts}
    links=[]
    for i,(left,right,relation) in enumerate([(req,by_id['D'],'implements'),(by_id['D'],by_id['P'],'verifies'),(by_id['P'],by_id['R'],'reports'),(by_id['R'],by_id['V'],'reviews')]):
        links.append(dict(COMMON,kind='trace_link',id='LINK-'+str(i),version='1',from_ref=reference(left),to_ref=reference(right),relation=relation))
    index=dict(COMMON,kind='project_artifact_index',artifacts=arts,requirements=[req],traces=links)
    raw=security.canonical(index)
    inv=[dict(path=a['relative_path'],sha256=a['content_digest'],size_bytes=len(contents[a['id']])) for a in arts]
    inv.append(dict(path='index.json',sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw)))
    manifest=dict(format='govcode-project-artifact-snapshot-v1',tenant_id='t',project_id='p',commit_sha='a'*40,index_path='index.json',index_digest=hashlib.sha256(raw).hexdigest(),index_canonical_digest=c.digest(index),inventory=sorted(inv,key=lambda x:x['path']),artifacts=[dict(artifact_ref=a,format='json' if a['relative_path'].endswith('.json') else 'markdown',status='captured',reason_codes=[]) for a in arts],total_bytes=sum(f['size_bytes'] for f in inv),worktree_checked=False,operational_approval=False)
    return dict(manifest=manifest,index=index,contents=contents)


def refresh(value):
    value['manifest']['index_canonical_digest']=c.digest(value['index'])
    raw=security.canonical(value['index'])
    value['manifest']['index_digest']=hashlib.sha256(raw).hexdigest()
    for f in value['manifest']['inventory']:
        if f['path']==value['manifest']['index_path']:
            f.update(sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
    value['manifest']['total_bytes']=sum(f['size_bytes'] for f in value['manifest']['inventory'])


class DeliveryTraceTests(unittest.TestCase):
    def setUp(self):
        self.module=importlib.import_module('govcode_harness.project.delivery_trace')
        self.value=fixture()
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        key=security.generate_keypair(Path(self.tmp.name)/'operator','ops')
        self.key=key
        self.trust=dict(context=security.CONTEXT,keys={'ops':dict(public_key=key['public_key'],actor_id='operator',roles=['operator'],revoked=False,tenant_id='t',project_id='p')})
        self.tools={'CHK-TRACE':dict(adapter_id='synthetic-test',tool_digest='b'*64)}

    def proof(self, **updates):
        req=self.value['index']['requirements'][0]
        result=next(a for a in self.value['index']['artifacts'] if a['id']=='R')
        body=dict(COMMON,kind='artifact_test_attestation',actor_id='operator',event_id='EXEC-1',created_at=NOW,not_before=NOW,expires_at=END,commit_sha=self.value['manifest']['commit_sha'],artifact_manifest_digest=c.digest(self.value['manifest']),requirement_ref=reference(req),result_artifact_ref=reference(result),check_id='CHK-TRACE',adapter_id='synthetic-test',tool_digest='b'*64,result='pass')
        body.update(updates)
        return security.sign(body,self.key['private_path'],'ops')

    def inspect(self, **kwargs):
        options=dict(now=NOW,expected_requirements=copy.deepcopy(self.value['index']['requirements']),result_receipts=[self.proof()],trust=self.trust,allowed_result_tools=self.tools)
        options.update(kwargs)
        return self.module.inspect(self.value,**options)

    def check(self,result,name):
        return next(x['status'] for x in result['checks'] if x['check_id']==name)

    def test_complete_chain_and_current_signed_result_pass_checks_only(self):
        r=self.inspect()
        self.assertEqual('checks_passed',r['outcome'])
        self.assertEqual(['pass']*3,[x['status'] for x in r['checks']])
        for key in ('requirements_evaluated','operational_approval','applicability_evaluated','stage_gate_evaluated'):
            self.assertFalse(r[key])
        self.assertNotIn('PRIVATE_BODY_SENTINEL',json.dumps(r))
        self.assertNotIn('Approved by anyone',json.dumps(r))

    def test_unknown_requirement_authority_requires_review(self):
        r=self.inspect(expected_requirements=None)
        self.assertEqual('review_required',r['outcome'])
        self.assertEqual('not_checked',r['requirement_authority'])

    def test_external_requirement_subset_cannot_hide_requirements(self):
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect(expected_requirements=[])

    def test_external_requirement_content_must_match(self):
        req=copy.deepcopy(self.value['index']['requirements']);req[0]['review_required']=False
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect(expected_requirements=req)

    def test_passed_and_approved_strings_do_not_replace_receipts(self):
        r=self.inspect(result_receipts=[])
        self.assertEqual('review_required',r['outcome'])
        self.assertEqual('review_required',self.check(r,'result_binding'))

    def test_missing_continuous_link_is_defect(self):
        self.value['index']['traces'].pop(2);refresh(self.value)
        r=self.inspect()
        self.assertEqual('fail',self.check(r,'trace_integrity'))
        self.assertNotEqual('checks_passed',r['outcome'])

    def test_missing_required_artifact_is_defect(self):
        self.value['index']['requirements'][0]['required_artifacts'].append('MISSING');refresh(self.value)
        req=self.value['index']['requirements'][0]
        self.value['index']['traces'][0]['from_ref']=reference(req);refresh(self.value)
        r=self.inspect()
        self.assertEqual('fail',self.check(r,'trace_integrity'))

    def test_wrong_relation_is_error(self):
        self.value['index']['traces'][0]['relation']='reviews';refresh(self.value)
        self.assertEqual('error',self.inspect()['outcome'])

    def test_reference_digest_and_version_tampering_are_errors(self):
        for field,value in [('digest','f'*64),('version','2'),('id','MISSING')]:
            with self.subTest(field=field):
                self.value=fixture();self.value['index']['traces'][0]['to_ref'][field]=value;refresh(self.value)
                self.assertEqual('error',self.inspect()['outcome'])

    def test_duplicate_trace_edge_is_error(self):
        link=copy.deepcopy(self.value['index']['traces'][0]);link['id']='ANOTHER';self.value['index']['traces'].append(link);refresh(self.value)
        self.assertEqual('error',self.inspect()['outcome'])

    def test_index_mutation_after_capture_is_rejected(self):
        self.value['index']['traces'].pop()
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect()

    def test_content_mutation_after_capture_is_rejected(self):
        self.value['contents']['D']=b'# Changed'
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect()

    def test_manifest_scope_mismatch_is_rejected(self):
        self.value['manifest']['project_id']='other'
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect()

    def test_duplicate_artifact_id_is_rejected(self):
        self.value['index']['artifacts'].append(copy.deepcopy(self.value['index']['artifacts'][0]));refresh(self.value)
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect()

    def set_content(self,name,raw):
        a=next(x for x in self.value['index']['artifacts'] if x['id']==name)
        a['content_digest']=hashlib.sha256(raw).hexdigest();self.value['contents'][name]=raw
        for row in self.value['manifest']['artifacts']:
            if row['artifact_ref']['id']==name:row['artifact_ref']=copy.deepcopy(a)
        for row in self.value['manifest']['inventory']:
            if row['path']==a['relative_path']:row.update(sha256=a['content_digest'],size_bytes=len(raw))
        for link in self.value['index']['traces']:
            for field in ('from_ref','to_ref'):
                if link[field]['kind']=='artifact_ref' and link[field]['id']==name:link[field]=reference(a)
        refresh(self.value)

    def test_markdown_heading_gap_is_defect(self):
        self.set_content('D',b'# Design\n\n### Skipped\n')
        self.assertEqual('fail',self.check(self.inspect(),'artifact_structure'))

    def test_code_fence_headings_are_not_document_headings(self):
        self.set_content('D',b'# Design\n\n```md\n#### Code\n```\n\n## Actual\n')
        self.assertEqual('pass',self.check(self.inspect(),'artifact_structure'))

    def test_raw_html_requires_review_and_is_not_executed(self):
        self.set_content('D',b'# Design\n<script>PRIVATE_BODY_SENTINEL</script>\n')
        r=self.inspect()
        self.assertEqual('review_required',self.check(r,'artifact_structure'))
        self.assertNotIn('PRIVATE_BODY_SENTINEL',json.dumps(r))

    def test_empty_document_is_defect(self):
        self.set_content('D',b'  \n')
        self.assertEqual('fail',self.check(self.inspect(),'artifact_structure'))

    def test_duplicate_json_keys_are_error(self):
        self.set_content('R',b'{"passed":true,"passed":true}')
        self.assertEqual('error',self.check(self.inspect(),'artifact_structure'))

    def test_scalar_json_is_structural_defect(self):
        self.set_content('R',b'true')
        self.assertEqual('fail',self.check(self.inspect(),'artifact_structure'))

    def test_signed_fail_is_not_pass(self):
        r=self.inspect(result_receipts=[self.proof(result='fail')])
        self.assertEqual('defects_found',r['outcome'])
        self.assertEqual('fail',self.check(r,'result_binding'))

    def test_signed_payload_binding_mismatches_are_errors(self):
        for updates in [dict(commit_sha='c'*40),dict(artifact_manifest_digest='c'*64),dict(tool_digest='c'*64),dict(adapter_id='other'),dict(check_id='OTHER'),dict(project_id='other'),dict(operational_approval=True),dict(extra='unexpected')]:
            with self.subTest(updates=updates):self.assertEqual('error',self.inspect(result_receipts=[self.proof(**updates)])['outcome'])

    def test_expired_and_future_result_are_errors(self):
        for updates in [dict(expires_at=NOW),dict(created_at=END),dict(not_before=END),dict(created_at='2026-10-29T00:00:00Z')]:
            with self.subTest(updates=updates):self.assertEqual('error',self.inspect(result_receipts=[self.proof(**updates)])['outcome'])

    def test_replayed_event_or_requirement_check_is_error(self):
        for other in [self.proof(),self.proof(event_id='EXEC-2')]:
            self.assertEqual('error',self.inspect(result_receipts=[self.proof(),other])['outcome'])

    def test_invalid_signature_is_error(self):
        proof=self.proof();proof['signature']='A'*88
        self.assertEqual('error',self.inspect(result_receipts=[proof])['outcome'])

    def test_revoked_key_and_wrong_role_are_errors(self):
        for changes in [dict(revoked=True),dict(roles=['author'])]:
            trust=copy.deepcopy(self.trust);trust['keys']['ops'].update(changes)
            self.assertEqual('error',self.inspect(trust=trust)['outcome'])

    def test_missing_trust_or_tool_config_requires_review(self):
        for updates in [dict(trust=None),dict(allowed_result_tools=None)]:
            with self.subTest(updates=updates):self.assertEqual('review_required',self.inspect(**updates)['outcome'])

    def test_malformed_tool_config_is_error(self):
        self.assertEqual('error',self.inspect(allowed_result_tools={'CHK-TRACE':{'command':'run'}})['outcome'])

    def test_unknown_result_artifact_is_error(self):
        ref=reference(self.value['index']['artifacts'][0])
        self.assertEqual('error',self.inspect(result_receipts=[self.proof(result_artifact_ref=ref)])['outcome'])

    def test_no_required_check_does_not_invent_execution_success(self):
        self.value['index']['requirements'][0]['check_refs']=[]
        self.value['index']['traces'][0]['from_ref']=reference(self.value['index']['requirements'][0]);refresh(self.value)
        self.assertEqual('review_required',self.inspect(result_receipts=[])['outcome'])

    def test_dependency_cycle_is_error(self):
        art=self.value['index']['artifacts'][0]
        self.value['index']['traces'].append(dict(COMMON,kind='trace_link',id='CYCLE',version='1',from_ref=reference(art),to_ref=reference(art),relation='depends_on'))
        refresh(self.value)
        self.assertEqual('error',self.inspect()['outcome'])

    def test_dependency_requires_same_artifact_kind(self):
        left,right=self.value['index']['artifacts'][:2]
        self.value['index']['traces'].append(dict(COMMON,kind='trace_link',id='DEP',version='1',from_ref=reference(left),to_ref=reference(right),relation='depends_on'))
        refresh(self.value)
        self.assertEqual('error',self.inspect()['outcome'])

    def test_unsupported_artifact_remains_review_required(self):
        art=self.value['index']['artifacts'][0]
        old=art['relative_path'];art['relative_path']='docs/design.pdf'
        for row in self.value['manifest']['inventory']:
            if row['path']==old:row['path']=art['relative_path']
        for row in self.value['manifest']['artifacts']:
            if row['artifact_ref']['id']==art['id']:
                row.update(artifact_ref=copy.deepcopy(art),format='unsupported',status='unsupported')
        for link in self.value['index']['traces']:
            for field in ('from_ref','to_ref'):
                if link[field]['id']==art['id']:link[field]=reference(art)
        refresh(self.value)
        self.assertEqual('review_required',self.check(self.inspect(),'artifact_structure'))

    def test_invalid_utf8_remains_review_required(self):
        self.set_content('D',b'\xff')
        self.value['manifest']['artifacts'][0]['status']='encoding_error'
        self.assertEqual('review_required',self.check(self.inspect(),'artifact_structure'))

    def test_two_top_headings_and_unclosed_fence_are_defects(self):
        for raw in [b'# One\n# Two',b'# One\n```\ncode']:
            self.value=fixture();self.set_content('D',raw)
            self.assertEqual('fail',self.check(self.inspect(),'artifact_structure'))

    def test_multiline_html_opening_is_manual_review(self):
        self.set_content('D',b'# Design\n<script\n src="local.js">\n')
        self.assertEqual('review_required',self.check(self.inspect(),'artifact_structure'))

    def test_manifest_inventory_content_hash_cannot_be_changed(self):
        self.value['manifest']['inventory'][0]['sha256']='e'*64
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect()

    def test_receipt_reference_uses_whole_version_and_digest(self):
        ref=reference(self.value['index']['requirements'][0]);ref['version']='2'
        self.assertEqual('error',self.inspect(result_receipts=[self.proof(requirement_ref=ref)])['outcome'])

    def test_invalid_now_is_bounded_error(self):
        with self.assertRaises(self.module.DeliveryTraceError):self.inspect(now='today')

    def test_report_explicitly_excludes_worktree_files(self):
        result=self.inspect()
        self.assertEqual('commit_snapshot',result['input_mode'])
        self.assertIs(False,result['worktree_checked'])

    def add_required_branch(self,kind,predecessor,relation):
        """Register an additional required artifact on a reachable branch."""
        source=next(a for a in self.value['index']['artifacts'] if a['artifact_kind']==kind)
        art=copy.deepcopy(source);art['id']='BRANCH';art['relative_path']='docs/branch'+Path(source['relative_path']).suffix
        self.value['index']['artifacts'].append(art)
        self.value['contents']['BRANCH']=self.value['contents'][source['id']]
        self.value['manifest']['artifacts'].append(dict(artifact_ref=copy.deepcopy(art),format='json' if art['relative_path'].endswith('.json') else 'markdown',status='captured',reason_codes=[]))
        self.value['manifest']['inventory'].append(dict(path=art['relative_path'],sha256=art['content_digest'],size_bytes=len(self.value['contents']['BRANCH'])))
        req=self.value['index']['requirements'][0]
        req['required_artifacts'].append('BRANCH')
        for link in self.value['index']['traces']:
            if link['from_ref']['id']==req['id']:link['from_ref']=reference(req)
        left=req if predecessor=='REQ' else next(a for a in self.value['index']['artifacts'] if a['id']==predecessor)
        self.value['index']['traces'].append(dict(COMMON,kind='trace_link',id='BRANCH-LINK',version='1',from_ref=reference(left),to_ref=reference(art),relation=relation))
        refresh(self.value)
        return art

    def test_required_design_dead_end_cannot_borrow_another_chain(self):
        self.add_required_branch('design','REQ','implements')
        result=self.inspect()
        self.assertEqual('fail',self.check(result,'trace_integrity'))
        self.assertIn('REQUIRED_ARTIFACT_TRACE_INCOMPLETE',{f['code'] for f in result['findings']})

    def test_required_test_plan_dead_end_cannot_borrow_another_chain(self):
        self.add_required_branch('test_plan','D','verifies')
        self.assertEqual('fail',self.check(self.inspect(),'trace_integrity'))

    def test_required_test_result_dead_end_cannot_borrow_another_chain(self):
        self.add_required_branch('test_result','P','reports')
        self.assertEqual('fail',self.check(self.inspect(),'trace_integrity'))

    def test_required_design_can_share_a_complete_remaining_chain(self):
        art=self.add_required_branch('design','REQ','implements')
        plan=next(a for a in self.value['index']['artifacts'] if a['id']=='P')
        self.value['index']['traces'].append(dict(COMMON,kind='trace_link',id='BRANCH-COMPLETE',version='1',from_ref=reference(art),to_ref=reference(plan),relation='verifies'))
        refresh(self.value)
        self.assertEqual('checks_passed',self.inspect()['outcome'])

    def test_required_terminal_review_is_a_complete_path_endpoint(self):
        self.assertIn('V',self.value['index']['requirements'][0]['required_artifacts'])
        self.assertEqual('pass',self.check(self.inspect(),'trace_integrity'))
