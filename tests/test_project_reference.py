"""Acceptance of the real, local synthetic project reference."""
import json
from pathlib import Path
import tempfile
import unittest


class ProjectReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from govcode_harness.project import project_reference
        cls.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        cls.root = Path(cls.tmp.name)/'reference'
        cls.result = project_reference.demo(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_full_denominator_preserves_future_and_exclusions(self):
        r=self.result
        self.assertEqual((8,5,1,2),tuple(r[k] for k in ('total_requirements','current_stage_satisfied','not_due','approved_exclusions')))
        self.assertEqual((6,1,1),tuple(r['before']['counts'][k] for k in ('applicable','not_applicable','pending')))
        self.assertEqual((6,2,0),tuple(r['after']['counts'][k] for k in ('applicable','not_applicable','pending')))

    def test_initial_current_rows_keep_distinct_blockers(self):
        report=json.loads((self.root/'assessment-before.json').read_text())
        self.assertEqual((2,1,2,1),tuple(report['counts'][k] for k in ('satisfied','unsatisfied','review_required','not_evaluated')))

    def test_real_lifecycle_checks_all_pass(self):
        self.assertTrue(self.result['checks'])
        self.assertTrue(all(v is True for v in self.result['checks'].values()))
        self.assertEqual('allow',self.result['after']['stage_outcome'])

    def test_public_result_has_no_source_or_credentials(self):
        text=json.dumps(self.result)
        for token in ('private_path','public_key','new_content','token_sha256','relative_path'):
            self.assertNotIn(token,text)
        self.assertFalse(self.result['operational_approval'])
        self.assertFalse(self.result['real_model_executed'])
        self.assertEqual('pending',self.result['legal_records'])

    def test_restored_store_and_reviewable_control_configuration_exist(self):
        config=json.loads((self.root/'control-config.json').read_text())
        self.assertIn('restored-store',Path(json.loads(Path(config['project_contexts'][0]['stage_bindings']['evidence_store']).read_text())['root']).name)
        self.assertTrue((self.root/'tokens'/'author.token').exists())
        self.assertFalse((self.root/'store').exists())

    def test_code_gate_cannot_be_replaced_by_caller_flags(self):
        for name in ('unsafe_code_blocks', 'code_context_flags_rejected', 'report_flags_rejected'):
            self.assertIs(self.result['checks'].get(name), True, name)

    def test_output_folder_cannot_be_reused(self):
        from govcode_harness.project import project_reference
        with self.assertRaises(Exception):project_reference.demo(self.root)
