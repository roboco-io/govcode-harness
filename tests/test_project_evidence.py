"""Real source-free project evidence lifecycle and final gate binding."""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from govcode_harness import security
from govcode_harness.project import contracts as c, stage_gate
from tests import test_project_stage_gate as gate_fixtures
from tests.rule_pack_fixtures import NOW, END

class ProjectEvidenceTests(unittest.TestCase):
    profile=gate_fixtures.StageGateTests.profile
    request=gate_fixtures.StageGateTests.request
    # Reuse fixture helpers without inheriting the gate test cases.
    def store(self):
        from govcode_harness.project.evidence import ProjectEvidenceStore
        self.cls=ProjectEvidenceStore
        return self.cls.create(self.root/'store',self.f.a.trust,'t','p',private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:self.now)

    def setUp(self):
        gate_fixtures.StageGateTests.setUp(self);self.now=NOW;self.profile(False);self.s=self.store()
        self.f.a.trust['keys']['ops2']['roles'].append('auditor')
        self.req=self.request()

    def auth(self,action,item,params=None,actor='ops',**changes):
        payload=dict(kind='project_store_authorization',schema_version='1',context=security.CONTEXT,
            tenant_id='t',project_id='p',operational_approval=False,actor_id=actor,store_id=self.s.store_id,
            action=action,evidence_id=item,event_id=self.f.a.event(),time=self.now,parameters_digest=c.digest(params or {}))
        payload.update(changes)
        return security.sign(payload,self.f.a.keys[actor]['private_path'],actor)

    def put(self,**changes):
        return self.s.put(self.req,self.f.commit,retain_until=END,**changes)

    def test_real_store_opens_current_gate_and_historical_read_stays_unapproved(self):
        item=self.put();candidate=stage_gate.prepare(self.req,self.f.commit)
        self.assertEqual('allow',stage_gate.evaluate(self.req,self.f.commit,evidence_store=self.s,evidence_id=item)['outcome'])
        self.assertEqual(candidate['candidate_digest'],self.s.verify_receipt(item,candidate)['candidate_digest'])
        result=self.s.read(item,self.auth('read',item,actor='ops2'))
        self.assertTrue(result['integrity_verified']);self.assertFalse(result['release_approval'])
        text=json.dumps(result)
        for secret in ('PRIVATE-ASSESSMENT-CONTENT','private_path','public_key','relative_path','facts','new_content'):
            self.assertNotIn(secret,text)

    def test_candidate_changes_and_unsigned_reports_rejected(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();candidate=stage_gate.prepare(self.req,self.f.commit)
        for key in ('subject_digest','evaluation_digest','candidate_digest','commit_sha','stage','tenant_id'):
            changed=copy.deepcopy(candidate);changed[key]='different'
            with self.subTest(key=key),self.assertRaises(StoreError):self.s.verify_receipt(item,changed)
        with self.assertRaises(StoreError):self.s.put(candidate,self.f.commit,retain_until=END)
        for key in ('expected_subject_digest','expected_evaluation_digest'):
            with self.assertRaises(StoreError):self.put(**{key:'f'*64})

    def test_pending_and_denied_are_archivable_but_invalid_not_archivable(self):
        self.req=self.request(approved=False);item=self.put()
        self.assertEqual('review_required',stage_gate.evaluate(self.req,self.f.commit,evidence_store=self.s,evidence_id=item)['outcome'])
        self.req=self.request(execution='fail');self.put()
        self.req['result_receipts'][0]['signature']='A'*88
        from govcode_harness.project.evidence import StoreError
        with self.assertRaises(StoreError):self.put()

    def test_tamper_missing_parent_and_deletion_fail_closed(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();child=self.put(parent_id=item);candidate=stage_gate.prepare(self.req,self.f.commit)
        with self.assertRaises(StoreError):self.s.delete(item,self.auth('delete',item))
        path=self.s.root/'objects'/item/'projection.json';path.write_text('{}')
        with self.assertRaises(StoreError):self.s.verify_receipt(child,candidate)
        self.assertEqual('error',stage_gate.evaluate(self.req,self.f.commit,evidence_store=self.s,evidence_id=child)['outcome'])

    def test_retention_hold_roles_body_binding_and_replay(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();read=self.auth('read',item,actor='ops2')
        self.s.read(item,read)
        with self.assertRaises(StoreError):self.s.read(item,read)
        with self.assertRaises(StoreError):self.s.read(item,self.auth('read',item))
        with self.assertRaises(StoreError):self.s.set_hold(item,True,self.auth('set_hold',item,{'enabled':False}))
        with self.assertRaises(StoreError):self.s.delete(item,self.auth('delete',item))
        self.s.set_hold(item,True,self.auth('set_hold',item,{'enabled':True}));self.now=END
        with self.assertRaises(StoreError):self.s.delete(item,self.auth('delete',item))
        self.s.set_hold(item,False,self.auth('set_hold',item,{'enabled':False}))
        self.s.delete(item,self.auth('delete',item))
        with self.assertRaises(StoreError):self.s.read(item,self.auth('read',item,actor='ops2'))

    def test_checkpoint_rejects_rollback_but_accepts_extension(self):
        from govcode_harness.project.evidence import StoreError
        self.put();checkpoint=self.s.checkpoint();self.put()
        self.cls(self.s.root,self.s.trust,checkpoint=checkpoint,clock=lambda:self.now)
        (self.s.root/'journal'/'000000000002.json').unlink()
        with self.assertRaises(StoreError):self.cls(self.s.root,self.s.trust,checkpoint=self.s.checkpoint(),clock=lambda:self.now)

    def test_backup_restore_requires_external_anchor_and_exact_destination(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();dest=self.root/'backup';params={'destination':str(dest)}
        with self.assertRaises(StoreError):self.s.backup(dest,self.auth('backup','STORE',{'destination':str(self.root/'wrong')}))
        checkpoint=self.s.backup(dest,self.auth('backup','STORE',params))
        target=self.root/'restored'
        options=dict(expected_head_digest=checkpoint['head_digest'],minimum_sequence=checkpoint['sequence'],
            private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:self.now)
        authorization=self.auth('restore','STORE',{'destination':str(target)})
        with self.assertRaises(StoreError):self.cls.restore(dest,target,self.s.trust,'t','p',authorization,**{**options,'expected_head_digest':'f'*64})
        restored=self.cls.restore(dest,target,self.s.trust,'t','p',authorization,**options)
        self.assertEqual(self.s.store_id,restored.store_id)
        self.assertEqual('allow',stage_gate.evaluate(self.req,self.f.commit,evidence_store=restored,evidence_id=item)['outcome'])
        self.assertEqual(checkpoint['sequence']+1,restored.checkpoint()['sequence'])

    def test_closed_authorization_scope_ttl_and_wrong_store(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put()
        for change in ({'extra':True},{'store_id':'STORE-other'},{'project_id':'other'},
                       {'time':'2026-10-28T23:54:59Z'},{'operational_approval':True},{'operational_approval':0}):
            with self.subTest(change=change),self.assertRaises(StoreError):
                self.s.read(item,self.auth('read',item,actor='ops2',**change))
        self.assertEqual(1,self.s.checkpoint()['sequence'])

    def test_deleted_and_tampered_signed_objects_are_rejected(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();path=self.s.root/'objects'/item/'metadata.json';original=path.read_bytes()
        data=json.loads(original);data['payload']['retain_until']=NOW;path.write_bytes(security.canonical(data))
        with self.assertRaises(StoreError):self.s.checkpoint()
        path.write_bytes(original);path.unlink()
        with self.assertRaises(StoreError):self.s.verify_receipt(item,stage_gate.prepare(self.req,self.f.commit))

    def test_active_parent_cannot_be_deleted_after_retention(self):
        from govcode_harness.project.evidence import StoreError
        parent=self.put();child=self.put(parent_id=parent);self.now=END
        with self.assertRaises(StoreError) as error:self.s.delete(parent,self.auth('delete',parent))
        self.assertEqual('ACTIVE_ANCESTOR',error.exception.code)
        self.s.delete(child,self.auth('delete',child));self.s.delete(parent,self.auth('delete',parent))
        self.assertEqual(4,self.s.checkpoint()['sequence'])

    def test_wrong_scope_and_missing_parent_never_write(self):
        from govcode_harness.project.evidence import StoreError
        with self.assertRaises(StoreError):self.put(parent_id='EVID-'+'f'*32)
        self.s.project_id='foreign'
        # A reopen restores verified scope; caller-edited attributes grant no authority.
        self.put();self.assertEqual('p',self.s.project_id)

    def test_links_git_and_existing_backup_destinations_are_rejected(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();file=self.s.root/'objects'/item/'projection.json';original=file.read_bytes()
        target=self.root/'external';target.write_bytes(original);file.unlink();file.symlink_to(target)
        with self.assertRaises(StoreError):self.s.checkpoint()
        file.unlink();file.hardlink_to(target)
        with self.assertRaises(StoreError):self.s.checkpoint()
        file.unlink();file.write_bytes(original)
        for dest in (self.f.repo/'.git'/'backup',self.s.root/'backup',self.root):
            with self.subTest(dest=dest),self.assertRaises(StoreError):
                self.s.backup(dest,self.auth('backup','STORE',{'destination':str(dest)}))
        self.assertEqual(1,self.s.checkpoint()['sequence'])

    def test_corrupt_backup_rejected_before_creating_restore(self):
        from govcode_harness.project.evidence import StoreError
        item=self.put();backup=self.root/'backup';cp=self.s.backup(backup,self.auth('backup','STORE',{'destination':str(backup)}))
        (backup/'objects'/item/'projection.json').write_text('{}');target=self.root/'restore'
        with self.assertRaises(StoreError):self.cls.restore(backup,target,self.s.trust,'t','p',
            self.auth('restore','STORE',{'destination':str(target)}),expected_head_digest=cp['head_digest'],minimum_sequence=cp['sequence'],
            private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:self.now)
        self.assertFalse(target.exists())

    def test_restore_uses_verified_capture_without_reopening_changed_source(self):
        from govcode_harness.project import evidence
        item=self.put();backup=self.root/'backup';cp=self.s.backup(backup,self.auth('backup','STORE',{'destination':str(backup)}))
        target=self.root/'restore';real=evidence._capture
        def captured(root):
            result=real(root)
            if Path(root)==backup:(backup/'objects'/item/'projection.json').write_text('{}')
            return result
        with patch.object(evidence,'_capture',side_effect=captured):
            restored=self.cls.restore(backup,target,self.s.trust,'t','p',self.auth('restore','STORE',{'destination':str(target)}),
                expected_head_digest=cp['head_digest'],minimum_sequence=cp['sequence'],
                private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:self.now)
        self.assertEqual('allow',stage_gate.evaluate(self.req,self.f.commit,evidence_store=restored,evidence_id=item)['outcome'])

    def test_readonly_reopen_verifies_without_signer(self):
        item=self.put();store=self.cls(self.s.root,self.s.trust,checkpoint=self.s.checkpoint(),clock=lambda:self.now)
        self.assertEqual('allow',stage_gate.evaluate(self.req,self.f.commit,evidence_store=store,evidence_id=item)['outcome'])
    def test_ignored_runtime_in_parent_checkout_is_valid_store_location(self):
        from govcode_harness import snapshot
        parent=self.root/'container';parent.mkdir();snapshot.run_git(parent,'init','-b','main')
        (parent/'.gitignore').write_text('.runtime/\n');runtime=parent/'.runtime';runtime.mkdir()
        store=self.cls.create(runtime/'store',self.s.trust,'t','p',private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:self.now)
        item=store.put(self.req,self.f.commit,retain_until=END)
        self.assertEqual('allow',stage_gate.evaluate(self.req,self.f.commit,evidence_store=store,evidence_id=item)['outcome'])
    def test_action_uses_one_trusted_time_for_authorization_and_event(self):
        item=self.put();times=iter((NOW,END));self.s.clock=lambda:next(times)
        result=self.s.read(item,self.auth('read',item,actor='ops2'))
        self.assertTrue(result['integrity_verified'])
        self.assertEqual(2,self.s.checkpoint()['sequence'])
    def test_git_metadata_alias_components_are_rejected(self):
        from govcode_harness.project.evidence import StoreError
        for alias in ('.GiT','.git.','.git ','.ｇｉｔ','.g\u200bit'):
            (self.root/alias).mkdir(exist_ok=True)
            with self.subTest(alias=alias),self.assertRaises(StoreError):
                self.cls.create(self.root/alias/'store',self.s.trust,'t','p',private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:self.now)

    def test_protected_checkpoint_rejects_fresh_open_rollback(self):
        from govcode_harness.project.evidence import StoreError
        first=self.put();second=self.put();protected=self.s.checkpoint()
        (self.s.root/'journal'/'000000000002.json').unlink();shutil.rmtree(self.s.root/'objects'/second)
        with self.assertRaises(StoreError) as error:self.cls(self.s.root,self.s.trust,checkpoint=protected)
        self.assertEqual('ROLLBACK_DETECTED',error.exception.code)

    def test_new_signed_proof_does_not_reuse_old_evidence(self):
        item=self.put();changed=dict(self.req,result_receipts=self.f.proofs())
        result=stage_gate.evaluate(changed,self.f.commit,evidence_store=self.s,evidence_id=item)
        self.assertEqual('error',result['outcome']);self.assertIn('EVIDENCE_VERIFICATION_FAILED',result['reason_codes'])
