"""Desk stage status comes from real stored evidence, never a UI flag."""
from pathlib import Path
from govcode_harness import security
from govcode_harness.project import assessment,stage_gate
from govcode_harness.project.evidence import ProjectEvidenceStore
from tests import test_project_control as controls
from tests import test_project_stage_gate as gates
from tests.rule_pack_fixtures import NOW,END
import unittest


class ProjectControlStageTests(unittest.TestCase):
    request=controls.ProjectControlTests.request
    def setUp(self):
        controls.ProjectControlTests.setUp(self)
        gates.StageGateTests.profile(self,False)
        (self.root/'lock.json').write_bytes(security.canonical(self.f.lock))
        service=self.server.desk.project_service
        self.context=service.contexts[('t','p')]
        self.current_request=service.request(self.context,NOW)
        report=assessment.assess(**self.current_request)
        review=self.f.review(report)
        path=self.root/'artifact-review.json';path.write_bytes(security.canonical(review))
        self.context['assessment']['artifact_review']=[str(path)]
        self.current_request=service.request(self.context,NOW)
        self.s=ProjectEvidenceStore.create(self.root/'project-store',self.f.a.trust,'t','p',private_path=self.f.a.keys['ops']['private_path'],key_id='ops',clock=lambda:NOW)
        self.item=self.s.put(self.current_request,self.f.commit,retain_until=END)
        candidate=stage_gate.prepare(self.current_request,self.f.commit)
        storeconfig=self.root/'project-store.json';storeconfig.write_bytes(security.canonical(dict(root=str(self.s.root),checkpoint=self.s.checkpoint())))
        self.context['stage_bindings']=dict(expected_commit=self.f.commit,expected_subject_digest=candidate['subject_digest'],expected_evaluation_digest=candidate['evaluation_digest'],evidence_store=str(storeconfig),evidence_id=self.item)

    def test_current_status_verifies_real_store_and_current_candidate(self):
        status,value=self.request();self.assertEqual(200,status)
        self.assertEqual('allow',value['stage_gate']['outcome'])
        self.assertTrue(value['stage_gate']['allowed'])
        self.assertFalse(value['operational_approval'])
        self.assertNotIn(str(self.root),str(value))

    def test_tampered_store_cannot_be_rendered_as_current_stage_success(self):
        (self.s.root/'objects'/self.item/'projection.json').write_text('{}')
        status,value=self.request();self.assertEqual(200,status)
        self.assertEqual('error',value['stage_gate']['outcome'])
        self.assertFalse(value['stage_gate']['allowed'])

    def test_wrong_expected_subject_remains_blocked(self):
        self.context['stage_bindings']['expected_subject_digest']='f'*64
        status,value=self.request();self.assertEqual(200,status)
        self.assertEqual('error',value['stage_gate']['outcome']);self.assertFalse(value['stage_gate']['allowed'])
