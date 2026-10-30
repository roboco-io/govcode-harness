"""Current stage candidates and fail-closed evidence boundary, synthetic fixtures."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from govcode_harness import governance, runtime, security
from govcode_harness.project import contracts as c
from tests.test_project_assessment import AssessmentFixture
from tests.rule_pack_fixtures import NOW, END


class StageGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.tool=patch('govcode_harness.runtime._tool_digest',return_value='d'*64)
        self.tool.start();self.addCleanup(self.tool.stop)
        self.f=AssessmentFixture(self.root)

    def module(self):
        from govcode_harness.project import stage_gate
        return stage_gate

    def profile(self,value):
        profile=copy.deepcopy(self.f.a.profile)
        profile.update(revision=2,parent_digest=c.digest(self.f.a.profile))
        profile['facts']['code_checks_required']=dict(state='known',value_type='boolean',value=value,source_ref='SRC-EXAMPLE')
        self.f.a.approve_profile(profile)
        self.f.lock=self.f.a.lock([self.f.release],sequence=2)

    def request(self,approved=True,execution='pass'):
        proofs=self.f.proofs(execution)
        preview=self.f.assess(result_receipts=proofs)
        return dict(repo=self.f.repo,commit=self.f.commit,index_path='index.json',profile_registry=self.f.a.profiles,
            lock=self.f.lock,trust=self.f.a.trust,now=NOW,revocations=self.f.a.feed,
            expected_revocation_digest=c.digest(self.f.a.feed),result_tools=self.f.tools,result_receipts=proofs,
            reviews=[self.f.review(preview)] if approved else [])

    def test_approved_docs_only_is_candidate_not_allow(self):
        self.profile(False);request=self.request()
        result=self.module().prepare(request,self.f.commit)
        self.assertEqual('ready_for_evidence',result['outcome'])
        self.assertEqual('project_stage_candidate',result['kind'])
        self.assertEqual(False,result['code_required']);self.assertIsNone(result['code_receipt_digest'])
        self.assertEqual(c.digest({k:v for k,v in result.items() if k!='candidate_digest'}),result['candidate_digest'])
        self.assertFalse(result['operational_approval'])

    def test_original_inputs_required_not_unsigned_report(self):
        self.profile(False)
        result=self.module().prepare(self.f.assess(),self.f.commit)
        self.assertEqual('error',result['outcome'])

    def test_injected_pass_flag_is_invalid_request(self):
        self.profile(False);request=self.request();request['code_passed']=True
        self.assertEqual('error',self.module().prepare(request,self.f.commit)['outcome'])

    def test_expected_commit_must_be_full_exact_current_commit(self):
        self.profile(False);request=self.request()
        for commit in (None,'HEAD',self.f.commit[:8],'f'*40):
            with self.subTest(commit=commit):
                self.assertEqual('error',self.module().prepare(request,commit)['outcome'])

    def test_historical_commit_cannot_open_gate(self):
        self.profile(False);request=self.request()
        (self.f.repo/'new.md').write_text('# New\n');self.f.save()
        self.assertEqual('error',self.module().prepare(request,self.f.commit)['outcome'])

    def test_expected_subject_and_evaluation_must_match_exactly(self):
        self.profile(False);request=self.request()
        for key in ('expected_subject_digest','expected_evaluation_digest'):
            with self.subTest(key=key):
                result=self.module().prepare(request,self.f.commit,**{key:'f'*64})
                self.assertEqual('error',result['outcome'])
        good=self.module().prepare(request,self.f.commit)
        self.assertEqual('ready_for_evidence',self.module().prepare(request,self.f.commit,
            expected_subject_digest=good['assessment']['subject_digest'],
            expected_evaluation_digest=good['assessment']['evaluation_digest'])['outcome'])

    def test_unknown_code_requirement_needs_review(self):
        result=self.module().prepare(self.request(),self.f.commit)
        self.assertEqual('review_required',result['outcome']);self.assertIsNone(result['code_required'])
        self.assertIn('CODE_REQUIREMENT_UNCONFIRMED',result['reason_codes'])

    def test_non_boolean_known_fact_is_error(self):
        value=copy.deepcopy(self.f.a.profile);value.update(revision=2,parent_digest=c.digest(value))
        value['facts']['code_checks_required']=dict(state='known',value_type='string',value='false',source_ref='SRC-EXAMPLE')
        self.f.a.approve_profile(value);self.f.lock=self.f.a.lock([self.f.release],sequence=2)
        result=self.module().prepare(self.request(),self.f.commit)
        self.assertEqual('error',result['outcome'])

    def test_false_cannot_skip_tracked_code(self):
        self.profile(False);(self.f.repo/'source.ts').write_text('export const x=1;')
        self.f.commit=self.f.save()
        result=self.module().prepare(self.request(),self.f.commit)
        self.assertEqual('review_required',result['outcome'])
        self.assertIn('CODE_PRESENT_REQUIRES_REVIEW',result['reason_codes'])

    def test_zero_current_requirements_is_review(self):
        other=self.root/'other';other.mkdir();self.f=AssessmentFixture(other,[('FUTURE',False,['operations'])])
        self.profile(False)
        result=self.module().prepare(self.request(approved=False),self.f.commit)
        self.assertEqual('review_required',result['outcome'])
        self.assertIn('NO_CURRENT_REQUIREMENTS',result['reason_codes'])

    def test_document_failure_is_deny(self):
        self.profile(False)
        result=self.module().prepare(self.request(execution='fail'),self.f.commit)
        self.assertEqual('deny',result['outcome'])

    def test_document_review_cannot_be_bypassed(self):
        self.profile(False)
        self.assertEqual('review_required',self.module().prepare(self.request(approved=False),self.f.commit)['outcome'])

    def test_head_change_during_assessment_is_error(self):
        self.profile(False);request=self.request();module=self.module();real=module.assessment.assess
        def changed(**kwargs):
            result=real(**kwargs)
            (self.f.repo/'new.md').write_text('# New\n');self.f.save()
            return result
        with patch.object(module.assessment,'assess',side_effect=changed):
            result=module.prepare(request,self.f.commit)
        self.assertEqual('error',result['outcome']);self.assertIn('HEAD_MISMATCH',result['reason_codes'])

    def test_missing_actual_evidence_store_never_allows(self):
        self.profile(False);request=self.request()
        for extra in ({},{'evidence_store':{'verified':True},'evidence_id':'ITEM-1'}):
            result=self.module().evaluate(request,self.f.commit,**extra)
            self.assertEqual('project_stage_receipt',result['kind'])
            self.assertEqual(('review_required',3),(result['outcome'],result['exit_code']))
            self.assertIn('EVIDENCE_REQUIRED',result['reason_codes'])

    def code(self,source='def f():\n    return 1\n',filename='source.py'):
        self.profile(True);(self.f.repo/filename).write_text(source);self.f.commit=self.f.save()
        a=self.f.a
        registry=governance.PolicyRegistry.create(self.root/'code-policies','t','p',a.trust)
        policy=dict(id='P1',version='1',basis_kind='example_policy',scope=dict(tenant_id='t',project_id='p',languages=['python'],stage='merge'),
            condition=dict(field='finding.category',operator='eq',value='pii_logging_risk'),effect='deny')
        for action,actor in [('draft','alice'),('submit','alice'),('approve','bob')]:
            fields=dict(action=action)
            if action=='draft':fields.update(policy=policy,obligations=[])
            else:fields.update(policy_id='P1',version='1',policy_digest=governance.digest(policy))
            payload=dict(context='synthetic_reference',tenant_id='t',project_id='p',actor_id=actor,event_id=a.event(),created_at=NOW,**fields)
            registry.apply(security.sign(payload,a.keys[actor]['private_path'],actor),NOW)
        bundle=registry.issue_bundle([dict(id='P1',version='1')],a.keys['ops']['private_path'],'ops',not_before=NOW,expires_at=END,sequence=1)
        evidence=self.root/'code-evidence'
        runtime.scan(self.f.repo,evidence,local_demo=True,commit=self.f.commit,tenant_id='t',project_id='p')
        return evidence,dict(bundle=bundle,min_sequence=1)

    def test_real_code_and_document_checks_prepare_ready(self):
        evidence,context=self.code();request=self.request()
        candidate=self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('ready_for_evidence',candidate['outcome']);self.assertTrue(candidate['code_required'])
        self.assertRegex(candidate['code_receipt_digest'],r'^[a-f0-9]{64}$')
        again=self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual(candidate['candidate_digest'],again['candidate_digest'])

    def test_real_code_deny_cannot_be_satisfied_by_documents(self):
        evidence,context=self.code('def f(request_body, logger):\n    logger.info("%s", request_body)\n')
        result=self.module().prepare(self.request(),self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('deny',result['outcome'])

    def test_real_unsupported_code_requires_review(self):
        evidence,context=self.code('console.log("x")','source.js')
        self.assertEqual('review_required',self.module().prepare(self.request(),self.f.commit,code_evidence=evidence,code_context=context)['outcome'])

    def test_real_code_parse_error_is_error(self):
        evidence,context=self.code('def malformed(')
        self.assertEqual('error',self.module().prepare(self.request(),self.f.commit,code_evidence=evidence,code_context=context)['outcome'])

    def test_code_requirement_needs_actual_signed_code_context(self):
        self.profile(True);request=self.request()
        result=self.module().prepare(request,self.f.commit)
        self.assertEqual('review_required',result['outcome'])
        self.assertIn('CODE_EVIDENCE_REQUIRED',result['reason_codes'])

    def test_code_context_is_closed_and_positive(self):
        evidence,context=self.code();request=self.request()
        for extra in ({'min_sequence':0},{'min_sequence':True},{'code_passed':True},{'tenant_id':'other'},{'with_iron_laws':'false'}):
            with self.subTest(extra=extra):
                self.assertEqual('error',self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context={**context,**extra})['outcome'])

    def test_code_profile_mismatch_is_error(self):
        evidence,context=self.code();context['with_iron_laws']=True
        self.assertEqual('error',self.module().prepare(self.request(),self.f.commit,code_evidence=evidence,code_context=context)['outcome'])

    def test_code_bundle_tampering_is_error(self):
        evidence,context=self.code();context['bundle']['signature']='A'*88
        self.assertEqual('error',self.module().prepare(self.request(),self.f.commit,code_evidence=evidence,code_context=context)['outcome'])

    def test_candidate_does_not_copy_code_or_authority(self):
        evidence,context=self.code();result=self.module().prepare(self.request(),self.f.commit,code_evidence=evidence,code_context=context)
        import json
        text=json.dumps(result)
        for secret in ('def f()', 'PRIVATE-ASSESSMENT-CONTENT','public_key','signature','private_path'):
            self.assertNotIn(secret,text)

    def test_review_ranks_above_document_deny(self):
        evidence,context=self.code('console.log("x")','source.js')
        result=self.module().prepare(self.request(execution='fail'),self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('review_required',result['outcome'])

    def test_code_error_ranks_above_document_review(self):
        evidence,context=self.code('def malformed(')
        result=self.module().prepare(self.request(approved=False),self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('error',result['outcome'])

    def test_passing_code_cannot_bypass_failed_documents(self):
        evidence,context=self.code()
        result=self.module().prepare(self.request(execution='fail'),self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('deny',result['outcome'])

    def test_time_only_does_not_change_valid_code_binding(self):
        evidence,context=self.code();request=self.request()
        first=self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context=context)
        request['now']='2026-10-29T00:00:01Z'
        second=self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('ready_for_evidence',second['outcome'])
        self.assertEqual(first['candidate_digest'],second['candidate_digest'])
        request['now']=END
        self.assertEqual('error',self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context=context)['outcome'])

    def test_current_code_manifest_is_verified_not_supplied_receipt(self):
        evidence,context=self.code();request=self.request()
        (evidence/'receipt.json').write_text('{}')
        self.assertEqual('error',self.module().prepare(request,self.f.commit,code_evidence=evidence,code_context=context)['outcome'])

    def test_inconsistent_runtime_and_root_gate_cannot_bind_candidate(self):
        evidence,context=self.code();request=self.request();module=self.module();real=runtime.verify
        real_gate=module.gate.evaluate;inside_gate=[False]
        def root_check(*args,**kwargs):
            inside_gate[0]=True
            try:return real_gate(*args,**kwargs)
            finally:inside_gate[0]=False
        def changed(*args,**kwargs):
            value=real(*args,**kwargs)
            if not inside_gate[0]:value.update(outcome='deny',exit_code=2)
            return value
        with patch.object(module.runtime,'verify',side_effect=changed), patch.object(module.gate,'evaluate',side_effect=root_check):
            result=module.prepare(request,self.f.commit,code_evidence=evidence,code_context=context)
        self.assertEqual('error',result['outcome'])

    def test_final_gate_reassesses_old_candidate(self):
        self.profile(False);request=self.request();candidate=self.module().prepare(request,self.f.commit)
        self.f.a.trust['keys']['bob']['revoked']=True
        result=self.module().evaluate(request,self.f.commit,evidence_store=candidate,evidence_id='ITEM-1')
        self.assertEqual('error',result['outcome'])

    def test_missing_storage_review_ranks_above_document_deny(self):
        self.profile(False)
        result=self.module().evaluate(self.request(execution='fail'),self.f.commit)
        self.assertEqual('review_required',result['outcome'])
        self.assertIn('EVIDENCE_REQUIRED',result['reason_codes'])
