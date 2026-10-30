"""Current signed inputs, full denominators and independent artifact reviews."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import security, snapshot
from govcode_harness.project import artifact_snapshot, contracts as c
from tests.rule_pack_fixtures import Authority, NOW, END, reference


def assessment_module():
    from govcode_harness.project import assessment
    return assessment


class AssessmentFixture:
    def __init__(self, root, variants=None):
        self.root = root
        (root/'authority').mkdir()
        self.a = Authority(root/'authority')
        template=copy.deepcopy(self.a.requirements[0])
        variants = variants or [('CURRENT',False,['acceptance'])]
        self.requirements=[]
        for name,value,stages in variants:
            req=copy.deepcopy(template);req.update(id=name,stages=stages)
            if value == 'unknown':req['applicability_expr']['fact']='procurement_type'
            else:req['applicability_expr']=dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=value))
            self.requirements.append(req)
        self.a.requirements=self.requirements
        self.release=self.a.publish()
        self.lock=self.a.lock([self.release])
        self.repo=root/'repo';self.repo.mkdir()
        snapshot.run_git(self.repo,'init','-b','main')
        common=self.a.common
        self.artifacts=[]
        for identity,kind in [('ART-DESIGN','design'),('ART-PLAN','test_plan'),('ART-RESULT','test_result'),('ART-REVIEW','review_record')]:
            raw=('# '+identity+'\n\nPRIVATE-ASSESSMENT-CONTENT 검토 대상이다.\n').encode()
            path=identity+'.md';(self.repo/path).write_bytes(raw)
            self.artifacts.append(dict(common,kind='artifact_ref',id=identity,version='1',artifact_kind=kind,relative_path=path,content_digest=hashlib.sha256(raw).hexdigest()))
        self.index=dict(common,kind='project_artifact_index',requirements=copy.deepcopy(self.requirements),artifacts=self.artifacts,traces=[])
        self.counter=0
        for req in self.requirements:self.link(req,self.artifacts[0],'implements')
        for a,b,kind in zip(self.artifacts,self.artifacts[1:],('verifies','reports','reviews')):self.link(a,b,kind)
        self.commit=self.save()
        self.tools={'CHK-TRACE':dict(adapter_id='delivery.trace_integrity',tool_digest='b'*64)}

    def link(self,a,b,relation):
        self.counter+=1
        self.index['traces'].append(dict(self.a.common,kind='trace_link',id='LINK-'+str(self.counter),version='1',from_ref=reference(a),to_ref=reference(b),relation=relation))

    def save(self):
        (self.repo/'index.json').write_bytes(security.canonical(self.index))
        snapshot.run_git(self.repo,'add','--all');snapshot.run_git(self.repo,'commit','-m','synthetic assessment fixture')
        return snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip()

    def capture(self):
        return artifact_snapshot.collect(self.repo,self.commit,'index.json',tenant_id='t',project_id='p')

    def proofs(self,result='pass',req_ids=None):
        captured=self.capture();proofs=[]
        for req in self.requirements:
            if req_ids is not None and req['id'] not in req_ids:continue
            proofs.append(self.a.signed('artifact_test_attestation','ops',not_before=NOW,expires_at=END,
                commit_sha=self.commit,artifact_manifest_digest=c.digest(captured['manifest']),requirement_ref=reference(req),
                result_artifact_ref=reference(self.artifacts[2]),check_id='CHK-TRACE',result=result,**self.tools['CHK-TRACE']))
        return proofs

    def assess(self,**changes):
        options=dict(revocations=self.a.feed,expected_revocation_digest=c.digest(self.a.feed),result_tools=self.tools)
        options.update(changes)
        return assessment_module().assess(self.repo,self.commit,'index.json',self.a.profiles,self.lock,self.a.trust,NOW,**options)

    def review(self,report,req=None,actor='bob',decision='approved',**changes):
        req=req or self.requirements[0]
        payload=dict(not_before=NOW,expires_at=END,subject_digest=report['subject_digest'],requirement_ref=reference(req),
            artifact_digests=sorted({a['content_digest'] for a in self.artifacts}),decision=decision,reason_ref='REVIEW-EXAMPLE')
        payload.update(changes)
        return self.a.signed('project_artifact_review',actor,**payload)

    def applicability_review(self,req,decision='not_applicable'):
        from govcode_harness.project import applicability
        return self.a.signed('applicability_review','bob',not_before=NOW,expires_at=END,lock_digest=c.digest(self.lock),
            profile_digest=c.digest(self.a.profile),requirement_ref=reference(req),decision=decision,reason_ref='EXCLUSION-REVIEW',
            subject_digest=applicability.review_subject(c.digest(self.lock),c.digest(self.a.profile),reference(req),'t','p'))


class ProjectAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        # A stable trusted tool in unit fixtures avoids concurrent source edits changing subjects.
        self.tool=patch('govcode_harness.runtime._tool_digest',return_value='d'*64);self.fingerprint=self.tool.start();self.addCleanup(self.tool.stop)
        self.f=AssessmentFixture(self.root)

    def test_missing_execution_remains_not_evaluated(self):
        report=self.f.assess()
        self.assertEqual('not_evaluated',report['requirements'][0]['status'])
        self.assertEqual('review_required',report['outcome'])
        self.assertEqual(1,report['counts']['current'])

    def test_execution_success_waits_for_independent_review(self):
        report=self.f.assess(result_receipts=self.f.proofs())
        self.assertEqual('review_required',report['requirements'][0]['status'])
        self.assertIn('ARTIFACT_REVIEW_REQUIRED',report['requirements'][0]['reason_codes'])
        self.assertEqual(0,report['counts']['satisfied'])

    def approved(self):
        proofs=self.f.proofs();report=self.f.assess(result_receipts=proofs)
        return proofs,self.f.review(report)

    def test_approved_current_inputs_are_satisfied_not_gate_allowed(self):
        proofs,review=self.approved();report=self.f.assess(result_receipts=proofs,reviews=[review])
        self.assertEqual('satisfied',report['requirements'][0]['status'])
        self.assertEqual('ready_for_stage',report['outcome'])
        self.assertFalse(report['operational_approval']);self.assertFalse(report['stage_gate_evaluated'])
        self.assertEqual(c.digest({k:v for k,v in report.items() if k!='evaluation_digest'}),report['evaluation_digest'])

    def test_rejected_review_is_unsatisfied(self):
        proofs=self.f.proofs();initial=self.f.assess(result_receipts=proofs)
        report=self.f.assess(result_receipts=proofs,reviews=[self.f.review(initial,decision='rejected')])
        self.assertEqual('unsatisfied',report['requirements'][0]['status']);self.assertEqual('deny',report['outcome'])

    def test_signed_failed_execution_is_unsatisfied(self):
        report=self.f.assess(result_receipts=self.f.proofs(result='fail'))
        self.assertEqual('unsatisfied',report['requirements'][0]['status'])

    def test_author_cannot_approve_with_second_key(self):
        proofs=self.f.proofs();report=self.f.assess(result_receipts=proofs)
        for actor in ('alice','alice2'):
            with self.subTest(actor=actor),self.assertRaises(assessment_module().AssessmentError) as error:
                self.f.assess(result_receipts=proofs,reviews=[self.f.review(report,actor=actor)])
            self.assertEqual('SELF_APPROVAL',error.exception.code)

    def test_review_binds_subject(self):
        proofs,review=self.approved();review['payload']['subject_digest']='f'*64
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess(result_receipts=proofs,reviews=[review])

    def test_wrong_artifact_set_is_rejected(self):
        proofs=self.f.proofs();report=self.f.assess(result_receipts=proofs)
        review=self.f.review(report,artifact_digests=[self.f.artifacts[0]['content_digest']])
        with self.assertRaises(assessment_module().AssessmentError) as error:self.f.assess(result_receipts=proofs,reviews=[review])
        self.assertEqual('REVIEW_ARTIFACT_MISMATCH',error.exception.code)

    def test_expired_review_is_rejected(self):
        proofs=self.f.proofs();report=self.f.assess(result_receipts=proofs)
        review=self.f.review(report,expires_at=NOW)
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess(result_receipts=proofs,reviews=[review])

    def test_review_event_or_requirement_cannot_repeat(self):
        proofs,review=self.approved()
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess(result_receipts=proofs,reviews=[review,review])

    def test_changed_tool_invalidates_existing_review(self):
        proofs,review=self.approved();self.fingerprint.return_value='e'*64
        with self.assertRaises(assessment_module().AssessmentError) as error:self.f.assess(result_receipts=proofs,reviews=[review])
        self.assertEqual('REVIEW_SUBJECT_MISMATCH',error.exception.code)

    def test_changed_commit_invalidates_execution_and_review(self):
        proofs,review=self.approved();(self.f.repo/'extra.md').write_text('# Changed\n');self.f.commit=self.f.save()
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess(result_receipts=proofs,reviews=[review])

    def test_unknown_and_future_and_excluded_are_not_satisfied(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            f=AssessmentFixture(Path(tmp),[('CURRENT',False,['acceptance']),('FUTURE',False,['operations']),('EXCLUDED',True,['acceptance']),('UNKNOWN','unknown',['acceptance'])])
            app_review=f.applicability_review(f.requirements[2]);proofs=f.proofs(req_ids={'CURRENT'})
            report=f.assess(result_receipts=proofs,applicability_reviews=[app_review])
            rows={r['requirement_ref']['id']:r for r in report['requirements']}
            self.assertEqual('not_due',rows['FUTURE']['status']);self.assertEqual('not_applicable',rows['EXCLUDED']['status'])
            self.assertEqual('review_required',rows['UNKNOWN']['status'])
            self.assertEqual((4,2,1,1,1,1),tuple(report['counts'][k] for k in ('total','applicable','not_applicable','pending','current','not_due')))
            self.assertEqual('review_required',report['outcome'])
            self.assertNotIn('TEST_ATTESTATION_REQUIRED',rows['CURRENT']['reason_codes'])

    def test_full_locked_requirement_set_cannot_be_shrunk(self):
        self.f.index['requirements']=[];self.f.commit=self.f.save()
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess()

    def test_stale_lock_or_wrong_feed_fails_closed(self):
        for change in ({'expected_revocation_digest':'f'*64},{'min_sequence':2}):
            with self.subTest(change=change),self.assertRaises(assessment_module().AssessmentError):self.f.assess(**change)

    def test_revoked_review_digest_is_rejected(self):
        proofs,review=self.approved();self.f.a.feed=self.f.a.issue_feed(review_digests=[c.digest(review)])
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess(result_receipts=proofs,reviews=[review])

    def test_current_trust_revokes_approver(self):
        proofs,review=self.approved();self.f.a.trust['keys']['bob']['revoked']=True
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess(result_receipts=proofs,reviews=[review])

    def test_unregistered_adapter_cannot_be_selected(self):
        self.f.tools['CHK-TRACE']['adapter_id']='wrong.adapter'
        with self.assertRaises(assessment_module().AssessmentError):self.f.assess()

    def test_work_items_are_stable_and_do_not_copy_sources(self):
        report=self.f.assess();again=self.f.assess()
        self.assertEqual(report['work_items'],again['work_items'])
        self.assertEqual(len(report['work_items']),len({w['id'] for w in report['work_items']}))
        text=json.dumps(report,ensure_ascii=False)
        self.assertNotIn('PRIVATE-ASSESSMENT-CONTENT',text)
        self.assertNotIn('relative_path',text)
        self.assertTrue(all(w['owner_ref']=='alice' for w in report['work_items']))

    def test_subject_excludes_review_and_final_result(self):
        proofs,review=self.approved();a=self.f.assess(result_receipts=proofs);b=self.f.assess(result_receipts=proofs,reviews=[review])
        self.assertEqual(a['subject_digest'],b['subject_digest'])
        self.assertNotEqual(a['evaluation_digest'],b['evaluation_digest'])

    def test_future_missing_execution_does_not_block_ready_current_stage(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            f=AssessmentFixture(Path(tmp),[('CURRENT',False,['acceptance']),('FUTURE',False,['operations'])])
            proofs=f.proofs(req_ids={'CURRENT'});preview=f.assess(result_receipts=proofs)
            final=f.assess(result_receipts=proofs,reviews=[f.review(preview)])
            self.assertEqual('ready_for_stage',final['outcome'])
            self.assertEqual(1,final['counts']['satisfied']);self.assertEqual(1,final['counts']['not_due'])
            self.assertEqual(2,final['counts']['total'])

    def test_row_provides_exact_current_review_digest_set(self):
        report=self.f.assess()
        self.assertEqual(sorted({a['content_digest'] for a in self.f.artifacts}),report['requirements'][0]['artifact_digests'])

    def test_signed_result_metadata_changes_evaluation_not_review_subject(self):
        proofs=self.f.proofs();a=self.f.assess(result_receipts=proofs)
        other=self.f.proofs();b=self.f.assess(result_receipts=other)
        self.assertEqual(a['subject_digest'],b['subject_digest'])
        self.assertNotEqual(a['evaluation_digest'],b['evaluation_digest'])

    def test_review_unknown_fields_and_foreign_scope_are_rejected(self):
        proofs=self.f.proofs();report=self.f.assess(result_receipts=proofs)
        for changes in ({'extra':True},{'project_id':'foreign'}):
            with self.subTest(changes=changes),self.assertRaises(assessment_module().AssessmentError):
                self.f.assess(result_receipts=proofs,reviews=[self.f.review(report,**changes)])

    def test_invalid_result_signature_is_error_even_when_review_exists(self):
        proofs,review=self.approved();proofs[0]['signature']='A'*88
        report=self.f.assess(result_receipts=proofs,reviews=[review])
        self.assertEqual('error',report['outcome']);self.assertEqual(1,report['counts']['error'])

    def test_bad_markdown_is_unsatisfied_not_satisfied_by_review(self):
        target=self.f.repo/self.f.artifacts[0]['relative_path'];target.write_text('No heading\n')
        self.f.artifacts[0]['content_digest']=hashlib.sha256(target.read_bytes()).hexdigest()
        # Rebind exact entity references to the newly committed artifact.
        for link in self.f.index['traces']:
            for side in ('from_ref','to_ref'):
                if link[side]['id']==self.f.artifacts[0]['id']:link[side]=reference(self.f.artifacts[0])
        self.f.commit=self.f.save()
        proofs=self.f.proofs();preview=self.f.assess(result_receipts=proofs)
        final=self.f.assess(result_receipts=proofs,reviews=[self.f.review(preview)])
        self.assertEqual('unsatisfied',final['requirements'][0]['status'])
        self.assertIn('MARKDOWN_STRUCTURE_INVALID',final['requirements'][0]['reason_codes'])

    def test_optional_review_policy_can_be_satisfied_by_current_checks(self):
        # A new signed pack is needed to change whether review is required.
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            f=AssessmentFixture(Path(tmp))
            requirement=f.requirements[0]
            requirement['review_required']=False
            manifest=copy.deepcopy(f.a.manifest);manifest['pack_id']='PACK-NO-CONTENT-REVIEW'
            release=f.a.publish(manifest=manifest,requirements=[requirement])
            f.lock=f.a.lock([release],sequence=2)
            for link in f.index['traces']:
                if link['from_ref']['id']==requirement['id']:link['from_ref']=reference(requirement)
            f.index['requirements']=[requirement];f.commit=f.save()
            final=f.assess(result_receipts=f.proofs())
            self.assertEqual('satisfied',final['requirements'][0]['status'])

    def test_unrecognized_inspector_error_cannot_be_approved(self):
        module=assessment_module();real=module.delivery_trace.inspect
        def changed(*args,**kwargs):
            result=real(*args,**kwargs)
            result['checks'][0]['status']='error'
            result['findings'].append(dict(check_id='trace_integrity',code='FUTURE_INSPECTOR_ERROR'))
            return result
        with patch.object(module.delivery_trace,'inspect',side_effect=changed):
            report=self.f.assess(result_receipts=self.f.proofs())
        self.assertEqual('error',report['outcome'])

    def test_other_dual_role_document_author_cannot_self_review(self):
        key=security.generate_keypair(self.root/'charlie','charlie')
        self.f.a.keys['charlie']=key
        self.f.a.trust['keys']['charlie']=dict(public_key=key['public_key'],actor_id='charlie',roles=['author','approver'],tenant_id='t',project_id='p',revoked=False)
        proofs=self.f.proofs();preview=self.f.assess(result_receipts=proofs)
        with self.assertRaises(assessment_module().AssessmentError) as error:
            self.f.assess(result_receipts=proofs,reviews=[self.f.review(preview,actor='charlie')])
        self.assertEqual('SELF_APPROVAL',error.exception.code)

    def test_independent_approver_only_actor_can_review(self):
        key=security.generate_keypair(self.root/'charlie','charlie')
        self.f.a.keys['charlie']=key
        self.f.a.trust['keys']['charlie']=dict(public_key=key['public_key'],actor_id='charlie',roles=['approver'],tenant_id='t',project_id='p',revoked=False)
        proofs=self.f.proofs();preview=self.f.assess(result_receipts=proofs)
        report=self.f.assess(result_receipts=proofs,reviews=[self.f.review(preview,actor='charlie')])
        self.assertEqual('ready_for_stage',report['outcome'])
