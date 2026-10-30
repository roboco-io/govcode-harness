"""Contract-authored, synthetic whole-stack independent acceptance inventory.

Expected classifications are declared in cases.json before execution. Fixture
helpers supply signed authorities, never inherited developer TestCase methods.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import security
from govcode_harness.evidence_store import StoreError
from govcode_harness.project import assessment, contracts as c, evidence, stage_gate
from tests import test_project_assessment as fixtures
from tests.rule_pack_fixtures import NOW, END, reference

CASES = json.loads((Path(__file__).parent/'fixtures/project-acceptance/cases.json').read_text())['cases']
SENTINEL = 'PRIVATE-ASSESSMENT-CONTENT'


class ProjectIndependentAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        fingerprint=patch('govcode_harness.runtime._tool_digest',return_value='9'*64)
        fingerprint.start();self.addCleanup(fingerprint.stop)

    def fixture(self,variants=None,code_fact=False):
        f=fixtures.AssessmentFixture(self.root,variants)
        profile=copy.deepcopy(f.a.profile)
        profile.update(revision=2,parent_digest=c.digest(f.a.profile))
        profile['facts']['code_checks_required']=(dict(state='unknown',owner_ref='alice',reason_ref='CHECK-CODE')
            if code_fact=='unknown' else dict(state='known',value_type='boolean',value=code_fact,source_ref='SRC-EXAMPLE'))
        f.a.approve_profile(profile);f.lock=f.a.lock([f.release],sequence=2)
        f.a.trust['keys']['ops']['roles'].append('auditor')
        return f

    def request(self,f,proofs=True,reviews=True,app_reviews=()):
        receipts=f.proofs(req_ids={'CURRENT'}) if proofs else []
        request=dict(repo=f.repo,commit=f.commit,index_path='index.json',profile_registry=f.a.profiles,
            lock=f.lock,trust=f.a.trust,now=NOW,revocations=f.a.feed,
            expected_revocation_digest=c.digest(f.a.feed),result_tools=f.tools,
            result_receipts=receipts,applicability_reviews=list(app_reviews),reviews=[])
        preview=assessment.assess(**request)
        if reviews and any(r['id']=='CURRENT' for r in f.requirements):
            request['reviews']=[f.review(preview,next(r for r in f.requirements if r['id']=='CURRENT'))]
        return request

    def store(self,f):
        return evidence.ProjectEvidenceStore.create(self.root/'store',f.a.trust,'t','p',
            private_path=f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:NOW)

    def auth(self,f,store,action,item,params=None,**changes):
        payload=dict(f.a.common,kind='project_store_authorization',actor_id='ops',store_id=store.store_id,
            action=action,evidence_id=item,event_id=f.a.event(),time=NOW,parameters_digest=c.digest(params or {}))
        payload.update(changes)
        return security.sign(payload,f.a.keys['ops']['private_path'],'ops')

    def check_source_free(self,*values):
        for value in values:
            text=json.dumps(value,ensure_ascii=False)
            self.assertNotIn(SENTINEL,text)
            self.assertNotIn('relative_path',text)
            self.assertNotIn(str(self.root),text)

    def run_case(self,case):
        scenario=case['scenario'];variants=None
        if scenario=='future_denominator':variants=[('CURRENT',False,['acceptance']),('LATER',False,['operations'])]
        elif scenario=='approved_exclusion':variants=[('CURRENT',False,['acceptance']),('EXCLUDED',True,['acceptance'])]
        elif scenario=='pending_applicability':variants=[('CURRENT',False,['acceptance']),('PENDING','unknown',['acceptance'])]
        elif scenario=='no_current_targets':variants=[('LATER',False,['operations'])]
        f=self.fixture(variants,code_fact='unknown' if scenario=='unknown_code_fact' else False)
        if scenario=='code_with_false_fact':
            (f.repo/'helper.py').write_text('print("synthetic example")\n');f.commit=f.save()
        if scenario=='unsupported_format':
            artifact=f.artifacts[0];old=f.repo/artifact['relative_path'];raw=old.read_bytes();old.unlink()
            artifact['relative_path']='opaque.bin';(f.repo/'opaque.bin').write_bytes(raw)
            artifact['content_digest']=hashlib.sha256(raw).hexdigest()
            for link in f.index['traces']:
                for side in ('from_ref','to_ref'):
                    if link[side]['id']==artifact['id']:link[side]=reference(artifact)
            f.commit=f.save()
        app=[f.applicability_review(f.requirements[1])] if scenario=='approved_exclusion' else []
        req=self.request(f,proofs=scenario!='missing_execution',reviews=scenario!='missing_review',app_reviews=app)
        candidate=stage_gate.prepare(req,f.commit)
        if scenario=='stable_plan':
            again=assessment.assess(**req)
            self.assertEqual(candidate['assessment']['work_items'],again['work_items'])
            # Exercise nonempty work identities independently of the satisfied result.
            pending=dict(req,reviews=[],result_receipts=[])
            a=assessment.assess(**pending);b=assessment.assess(**pending)
            self.assertTrue(a['work_items']);self.assertEqual(a['work_items'],b['work_items'])
        if scenario=='future_denominator':
            self.assertEqual((2,1,1),tuple(candidate['assessment']['counts'][k] for k in ('total','current','not_due')))
        if scenario=='approved_exclusion':
            self.assertEqual((2,1,1),tuple(candidate['assessment']['counts'][k] for k in ('total','not_applicable','satisfied')))
        if scenario=='pending_applicability':self.assertEqual(1,candidate['assessment']['counts']['pending'])
        self.check_source_free(candidate)
        if case['classification']=='unknown_unverified':
            store=None;item=None
            if scenario!='missing_storage':
                store=self.store(f);item=store.put(req,f.commit,retain_until=END)
            result=stage_gate.evaluate(req,f.commit,evidence_store=store,evidence_id=item)
            self.assertEqual(case['expected'],result['outcome']);self.assertFalse(result['operational_approval'])
            return
        store=self.store(f);item=store.put(req,f.commit,retain_until=END,legal_hold=scenario=='hold_retained')
        if scenario=='wrong_commit':
            result=stage_gate.evaluate(req,'0'*40,evidence_store=store,evidence_id=item)
        elif scenario in ('wrong_subject','wrong_evaluation'):
            option='expected_subject_digest' if scenario=='wrong_subject' else 'expected_evaluation_digest'
            result=stage_gate.evaluate(req,f.commit,evidence_store=store,evidence_id=item,**{option:'0'*64})
        elif scenario=='tampered_projection':
            path=store.root/'objects'/item/'projection.json';data=json.loads(path.read_text());data['counts']['satisfied']=999
            path.write_bytes(security.canonical(data))
            result=stage_gate.evaluate(req,f.commit,evidence_store=store,evidence_id=item)
        elif scenario=='missing_parent':
            child=store.put(req,f.commit,retain_until=END,parent_id=item)
            shutil.rmtree(store.root/'objects'/item)
            result=stage_gate.evaluate(req,f.commit,evidence_store=store,evidence_id=child)
        elif scenario=='nonce_replay':
            auth=self.auth(f,store,'read',item);store.read(item,auth)
            with self.assertRaises(StoreError):store.read(item,auth)
            return
        elif scenario=='revoked_trust':
            f.a.trust['keys']['bob']['revoked']=True
            result=stage_gate.evaluate(req,f.commit,evidence_store=store,evidence_id=item)
        elif scenario=='wrong_scope':
            auth=self.auth(f,store,'read',item,project_id='other-project')
            with self.assertRaises(StoreError):store.read(item,auth)
            return
        else:
            if scenario=='history_read':
                history=store.read(item,self.auth(f,store,'read',item))
                self.assertTrue(history['integrity_verified']);self.assertIs(False,history['release_approval']);self.check_source_free(history)
            elif scenario=='hold_retained':
                history=store.read(item,self.auth(f,store,'read',item));self.assertIs(True,history['metadata']['legal_hold'])
                with self.assertRaises(StoreError):store.delete(item,self.auth(f,store,'delete',item))
            elif scenario=='parent_chain':
                parent=item;item=store.put(req,f.commit,retain_until=END,parent_id=parent)
                metadata=store.verify_receipt(item,candidate);self.assertEqual(parent,metadata['parent_id'])
            elif scenario=='protected_restore':
                destination=self.root/'backup';checkpoint=store.backup(destination,self.auth(f,store,'backup','STORE',{'destination':str(destination)}))
                restored=self.root/'restored'
                auth=self.auth(f,store,'restore','STORE',{'destination':str(restored)})
                old_journal={p.name:p.read_bytes() for p in (destination/'journal').iterdir()}
                store=evidence.ProjectEvidenceStore.restore(destination,restored,f.a.trust,'t','p',auth,
                    expected_head_digest=checkpoint['head_digest'],minimum_sequence=checkpoint['sequence'],
                    private_path=f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:NOW)
                self.assertGreater(store.checkpoint()['sequence'],checkpoint['sequence'])
                for name,raw in old_journal.items():self.assertEqual(raw,(restored/'journal'/name).read_bytes())
            result=stage_gate.evaluate(req,f.commit,evidence_store=store,evidence_id=item)
        self.check_source_free(result)
        if case['classification']=='normal':
            self.assertEqual(case['expected'],result['outcome']);self.assertFalse(result['operational_approval'])
            projection=json.loads((store.root/'objects'/item/'projection.json').read_text());self.check_source_free(projection)
        else:self.assertEqual('error',result['outcome'])


def _make_test(case):
    def test(self):self.run_case(case)
    test.__doc__=case['contract']
    return test

for _case in CASES:
    setattr(ProjectIndependentAcceptanceTests,'test_'+_case['id']+'_'+_case['scenario'],_make_test(_case))
