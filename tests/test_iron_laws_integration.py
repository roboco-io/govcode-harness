import copy
import io
import json
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from govcode_harness import runtime
from tests import test_runtime as fixtures

PIN = '2a820e8cd7ade4c3060381198ed13bf3e6b43146'

def external(outcome='allow', findings=None, issues=None):
    return {'tool': {'name':'iron-laws','version':'1.11.2','source_commit':PIN,
                     'profile':'AI-112-v2-python-poc','config_sha256':'a'*64,'status':'verified',
                     'environment_sha256':'a'*64,'artifact_sha256':'a'*64,'interpreter_sha256':'a'*64,
                     'interpreter_version':'Python 3.12.9','lock_sha256':'a'*64,'build_lock_sha256':'a'*64},
            'outcome':outcome, 'findings':findings or [], 'issues':issues or [],
            'report':({'format':'govcode-iron-laws-sanitized-v1','profile':'AI-112-v2-python-poc',
                       'status':'error','findings':findings or [],'issues':issues or []} if outcome == 'error' else
                      {'format':'govcode-iron-laws-sanitized-v1','profile':'AI-112-v2-python-poc','config_sha256':'a'*64,
                       'schema_version':'1.8','status':'complete','files_analyzed':['complaints.py'],
                       'verification':'upstream-structural-consistency','findings':findings or [],
                       'issues':issues or [],'outcome':outcome})}

class IronLawsIntegrationTests(unittest.TestCase):
    setUp = fixtures.RuntimeTests.setUp
    git = fixtures.RuntimeTests.git
    commit = fixtures.RuntimeTests.commit

    def execute(self, result, source=runtime.AFTER_SOURCE, name='evidence'):
        self.commit(source)
        with patch.object(runtime, '_iron_laws_analysis', return_value=result, create=True):
            outcome = runtime.scan(self.repo, self.base / name, local_demo=True, with_iron_laws=True)
        return outcome, self.base / name

    def test_hybrid_clean_snapshot_seals_external_report_and_policy(self):
        result, out = self.execute(external())
        self.assertEqual(result['outcome'], 'allow')
        self.assertTrue((out/'iron-laws.json').is_file())
        self.assertTrue((out/'iron-laws-policy.json').is_file())
        execution=json.loads((out/'execution.json').read_text())
        self.assertEqual(execution['detectors'], ['python-local-flow','iron-laws'])
        policy=json.loads((out/'iron-laws-policy.json').read_text())
        self.assertEqual(policy['basis_kind'], 'example_policy')
        self.assertFalse(policy['enabled'])
        refs=json.loads((out/'decision.json').read_text())['policy_refs']
        self.assertIn(policy['id'], [ref['id'] for ref in refs])

    def test_external_clean_does_not_override_builtin_privacy_risk(self):
        result,_ = self.execute(external(), runtime.BEFORE_SOURCE)
        self.assertEqual(result['outcome'], 'deny')

    def test_external_generic_risk_denies_builtin_clean(self):
        finding={'path':'complaints.py','line':2,'severity':'high','rule_id':'AI-112',
                 'category':'external_code_risk','data_classes':[]}
        result,out=self.execute(external('deny',[finding]))
        self.assertEqual(result['exit_code'],2)
        found=json.loads((out/'finding-0001.json').read_text())
        self.assertEqual(found['detector_id'],'iron-laws')
        self.assertEqual(found['category'],'external_code_risk')
        self.assertEqual(found['data_classes'],['source_code'])
        self.assertIn('AI-112',(out/'iron-laws.json').read_text())

    def test_external_error_never_falls_back_to_builtin_allow(self):
        issue={'path':'.','line':1,'code':'IRON_LAWS_UNAVAILABLE'}
        result,_=self.execute(external('error',issues=[issue]))
        self.assertEqual(result['exit_code'],4)

    def test_external_review_never_allows(self):
        result,_=self.execute(external('review_required',issues=[{'path':'.','line':1,'code':'ANALYSIS_UNKNOWN'}]))
        self.assertEqual(result['exit_code'],3)

    def test_builtin_review_is_not_overridden_by_external_allow(self):
        result,_=self.execute(external(),'def f(request_body):\n    for item in request_body:\n        pass\n')
        self.assertEqual(result['exit_code'],3)

    def test_verify_automatically_reruns_required_external_tool(self):
        _,out=self.execute(external())
        with patch.object(runtime,'_iron_laws_analysis',return_value=external(),create=True) as analyzer:
            self.assertEqual(runtime.verify(self.repo,out,local_demo=True)['exit_code'],0)
        analyzer.assert_called()

    def test_external_tool_identity_drift_invalidates_evidence(self):
        _,out=self.execute(external())
        changed=external()
        changed['tool']['environment_sha256']='b'*64
        with patch.object(runtime,'_iron_laws_analysis',return_value=changed,create=True):
            with self.assertRaises(runtime.HarnessError):
                runtime.verify(self.repo,out,local_demo=True)

    def test_external_report_deletion_or_rehashed_forgery_is_rejected(self):
        _,out=self.execute(external())
        report=json.loads((out/'iron-laws.json').read_text())
        report['outcome']='deny'
        (out/'iron-laws.json').write_text(json.dumps(report))
        runtime._seal(out)
        with patch.object(runtime,'_iron_laws_analysis',return_value=external(),create=True):
            with self.assertRaises(runtime.HarnessError):
                runtime.verify(self.repo,out,local_demo=True)
        (out/'iron-laws.json').unlink()
        with patch.object(runtime,'_iron_laws_analysis',return_value=external(),create=True):
            with self.assertRaises(runtime.HarnessError):
                runtime.verify(self.repo,out,local_demo=True)

    def test_rehashed_detector_downgrade_cannot_reuse_hybrid_run(self):
        _,out=self.execute(external())
        execution=json.loads((out/'execution.json').read_text())
        del execution['detectors']
        (out/'execution.json').write_text(json.dumps(execution))
        (out/'iron-laws.json').unlink()
        (out/'iron-laws-policy.json').unlink()
        runtime._seal(out)
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo,out,local_demo=True)

    def test_parent_detector_profile_must_match(self):
        self.commit(runtime.BEFORE_SOURCE)
        runtime.scan(self.repo,self.base/'before',local_demo=True)
        self.commit(runtime.AFTER_SOURCE)
        with patch.object(runtime,'_iron_laws_analysis',return_value=external(),create=True):
            with self.assertRaises(runtime.HarnessError):
                runtime.scan(self.repo,self.base/'after',parent=self.base/'before',local_demo=True,with_iron_laws=True)

    def test_hybrid_new_commit_links_denied_parent(self):
        self.commit(runtime.BEFORE_SOURCE)
        with patch.object(runtime,'_iron_laws_analysis',return_value=external(),create=True):
            before=runtime.scan(self.repo,self.base/'before',local_demo=True,with_iron_laws=True)
            self.commit(runtime.AFTER_SOURCE)
            after=runtime.scan(self.repo,self.base/'after',parent=self.base/'before',local_demo=True,with_iron_laws=True)
        self.assertEqual(before['outcome'],'deny')
        self.assertEqual(after['outcome'],'allow')

    def test_invalid_adapter_shape_cannot_allow_or_write_raw_source(self):
        self.commit(runtime.AFTER_SOURCE)
        invalid=external()
        invalid['findings']=[{'snippet':'PRIVATE_SENTINEL'}]
        with patch.object(runtime,'_iron_laws_analysis',return_value=invalid,create=True):
            with self.assertRaises(runtime.HarnessError):
                runtime.scan(self.repo,self.base/'invalid',local_demo=True,with_iron_laws=True)
        self.assertFalse((self.base/'invalid').exists())

    def test_cli_flag_passes_explicit_opt_in(self):
        from govcode_harness.__main__ import main
        with patch.object(runtime,'scan',return_value={'exit_code':0}) as scan, redirect_stdout(io.StringIO()):
            self.assertEqual(main(['scan','--repo','repo','--output','output','--local-demo','--with-iron-laws']),0)
        self.assertTrue(scan.call_args.kwargs['with_iron_laws'])

if __name__ == '__main__':
    unittest.main()
