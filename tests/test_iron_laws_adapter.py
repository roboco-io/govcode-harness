import json
import subprocess
import unittest
from unittest.mock import patch
from govcode_harness import iron_laws_adapter as adapter


def report():
    return {'schema_version':'1.8', 'summary':{'scan_status':'complete','is_passed':True,'total_files_scanned':1,'total_violations':0,'gate_exceeded':[],'unverified_rule_language_pairs':0},
      'execution':{'tool_version':'1.11.2','scan_status':'complete','files_scanned':1,'files_skipped':0,'error_diagnostics':0,'cross_file_limit_hits':0},
      'violations':[], 'diagnostics':[], 'metadata':{'suppressions':[], 'file_coverage':{'listed':1,'counts':{'analyzed':1},'unexplained':[]}}}


class ParserTests(unittest.TestCase):
    def run_report(self, value=None, rc=0):
        return adapter._normalize(report() if value is None else value, rc, {'complaint.py':4})
    def test_complete(self):
        self.assertEqual(self.run_report()['outcome'],'allow')
    def test_malformed(self):
        for value in ({}, [], {'schema_version':'2.0'}):
            with self.subTest(value=value): self.assertEqual(self.run_report(value)['outcome'],'error')
    def test_code_one_without_findings(self):
        self.assertEqual(self.run_report(rc=1)['outcome'],'review_required')
    def test_code_two(self):
        self.assertEqual(self.run_report(rc=2)['outcome'],'error')
    def test_missing_coverage(self):
        r=report(); del r['metadata']['file_coverage']
        self.assertEqual(self.run_report(r)['outcome'],'error')
    def test_incomplete(self):
        r=report();r['summary']['scan_status']='incomplete'
        self.assertEqual(self.run_report(r)['outcome'],'error')
    def test_gate(self):
        r=report();r['summary']['gate_exceeded']=['unknown']
        self.assertEqual(self.run_report(r)['outcome'],'review_required')
    def test_unverified(self):
        r=report();r['summary']['unverified_rule_language_pairs']=1
        self.assertEqual(self.run_report(r)['outcome'],'review_required')
    def test_unknown_analysis(self):
        r=report();r['summary']['analysis_unknown_rate']=0.5
        self.assertEqual(self.run_report(r)['outcome'],'review_required')
    def test_contract_unmet(self):
        r=report();r['summary']['contract_status']='unmet'
        self.assertEqual(self.run_report(r)['outcome'],'review_required')
    def test_privacy(self):
        r=report();r['violations']=[{'rule_id':'AI-112','file_path':'complaint.py','line_number':2,'severity':'HIGH','confidence':'CONFIRMED','snippet':'SECRET','message':'SECRET','scope_name':'SECRET'}]
        r['summary'].update(is_passed=False,total_violations=1)
        result=self.run_report(r,1)
        self.assertEqual(result['outcome'],'deny');self.assertNotIn('SECRET',json.dumps(result))
    def test_unsafe_finding_path(self):
        r=report();r['violations']=[{'rule_id':'AI-112','file_path':'../secret.py','line_number':1,'severity':'HIGH','confidence':'CONFIRMED'}];r['summary']['total_violations']=1
        self.assertEqual(self.run_report(r,1)['outcome'],'error')
    def test_inputs(self):
        for sources in [[('../escape.py','x')],[('/tmp/escape.py','x')],[('a.py','x'),('a.py','x')],[('.git/a.py','x')],[('x.txt','x')]]:
            self.assertEqual(adapter.analyze(sources)['outcome'],'error')
    def test_missing(self):
        with patch.object(adapter,'_environment',return_value=adapter.RUNTIME),patch.object(adapter,'_identity',side_effect=adapter.AdapterError('IRON_TOOL_MISSING')):
            self.assertEqual(adapter.analyze([('a.py','pass')])['issues'][0]['code'],'IRON_TOOL_MISSING')
    def test_drift(self):
        with patch.object(adapter,'_environment',return_value=adapter.RUNTIME),patch.object(adapter,'_identity',side_effect=adapter.AdapterError('IRON_IDENTITY_DRIFT')):
            self.assertEqual(adapter.analyze([('a.py','pass')])['outcome'],'error')
    def test_timeout(self):
        with patch.object(adapter,'_environment',return_value=adapter.RUNTIME),patch.object(adapter,'_identity',return_value={'status':'verified'}),patch.object(adapter,'_invoke',side_effect=subprocess.TimeoutExpired('private',1)):
            self.assertEqual(adapter.analyze([('a.py','pass')])['issues'][0]['code'],'IRON_TIMEOUT')

class RuntimeBoundaryTests(unittest.TestCase):
    def test_actual_missing_interpreter(self):
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as folder:
            root=Path(folder);env=root/('env-'+'c'*32);env.mkdir()
            with patch.object(adapter,'RUNTIME',root),patch.object(adapter,'_environment',return_value=env):
                self.assertEqual(adapter.analyze([('a.py','pass')])['issues'][0]['code'],'IRON_TOOL_MISSING')
    def test_recomputed_identity_drift(self):
        import tempfile
        from pathlib import Path
        adapter.RUNTIME.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as folder:
            root=Path(folder);env=root/('env-'+'d'*32);env.mkdir()
            (env/'identity.json').write_text('{"status":"old"}')
            with patch.object(adapter,'RUNTIME',root),patch.object(adapter,'measure_identity',return_value={'status':'changed'}):
                with self.assertRaisesRegex(adapter.AdapterError,'IRON_IDENTITY_DRIFT'): adapter._identity(env)
    def test_real_bounded_output(self):
        try: adapter._environment()
        except adapter.AdapterError: self.skipTest('optional isolated tool is absent')
        with self.assertRaisesRegex(adapter.AdapterError,'IRON_OUTPUT_LIMIT'):
            adapter._invoke(['-c','import sys; sys.stdout.write("x" * 2100000)'],adapter.RUNTIME)
    def test_real_timeout(self):
        try: adapter._environment()
        except adapter.AdapterError: self.skipTest('optional isolated tool is absent')
        with patch.object(adapter,'TIMEOUT',0.03),self.assertRaises(subprocess.TimeoutExpired):
            adapter._invoke(['-c','import time; time.sleep(5)'],adapter.RUNTIME)

class ReviewPrecedenceTests(unittest.TestCase):
    def run_report(self, value, rc=0):
        return adapter._normalize(value, rc, {"complaint.py":4})
    def finding_report(self):
        r=report();r['summary'].update(total_violations=1,is_passed=False)
        r['violations']=[{'file_path':'complaint.py','line_number':2,'rule_id':'AI-112','severity':'HIGH','confidence':'CONFIRMED'}]
        return r
    def test_finding_gate_requires_review(self):
        r=self.finding_report();r['summary']['gate_exceeded']=['unknown']
        self.assertEqual(self.run_report(r,1)['outcome'],'review_required')
    def test_finding_warning_requires_review(self):
        r=self.finding_report();r['diagnostics']=[{'severity':'warning','message':'PRIVATE'}]
        self.assertEqual(self.run_report(r,1)['outcome'],'review_required')
    def test_review_confidence_requires_review(self):
        r=self.finding_report();r['violations'][0]['confidence']='REVIEW'
        self.assertEqual(self.run_report(r,1)['outcome'],'review_required')

class ActiveEnvironmentTests(unittest.TestCase):
    def test_confined_unique_selection(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as folder:
            root=Path(folder);name='env-'+'a'*32;(root/name).mkdir()
            (root/'active.json').write_text(json.dumps({'environment':name}))
            with patch.object(adapter,'RUNTIME',root):
                self.assertEqual(adapter._environment(),root/name)
    def test_reject_escape_and_legacy_selection(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as folder:
            root=Path(folder)
            with patch.object(adapter,'RUNTIME',root):
                for name in ['../venv','/tmp/venv','venv','env-xyz']:
                    (root/'active.json').write_text(json.dumps({'environment':name}))
                    with self.assertRaises(adapter.AdapterError):adapter._environment()
    def test_reject_symlink_selection(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as folder:
            root=Path(folder);name='env-'+'b'*32;(root/'target').mkdir();(root/name).symlink_to(root/'target',target_is_directory=True)
            (root/'active.json').write_text(json.dumps({'environment':name}))
            with patch.object(adapter,'RUNTIME',root),self.assertRaises(adapter.AdapterError):adapter._environment()
    def test_unexpected_duplicates_and_bytecode_change_identity(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as folder:
            root=Path(folder);env=root/('env-'+'e'*32)
            site=env/'lib/python3.12/site-packages';metadata=site/'iron_laws-1.11.2.dist-info'
            metadata.mkdir(parents=True);(env/'bin').mkdir();(env/'bin/python').write_bytes(b'fake interpreter')
            (env/'pyvenv.cfg').write_text('include-system-site-packages = false')
            (metadata/'METADATA').write_text('Name: iron-laws\nVersion: 1.11.2\n')
            with patch.object(adapter,'RUNTIME',root),patch.object(adapter,'_invoke',return_value=(0,b'Python 3.12.14',b'')):
                before=adapter.measure_identity(env)
                (metadata/'METADATA 2').write_bytes((metadata/'METADATA').read_bytes())
                duplicate=adapter.measure_identity(env)
                self.assertNotEqual(before['artifact_sha256'],duplicate['artifact_sha256'])
                pycache=site/'iron_laws/__pycache__';pycache.mkdir(parents=True);(pycache/'cli.pyc').write_bytes(b'injected bytecode')
                after=adapter.measure_identity(env)
                self.assertNotEqual(duplicate['environment_sha256'],after['environment_sha256'])

class ProcessGroupCleanupTests(unittest.TestCase):
    def test_exited_leader_with_pipe_inheriting_child_is_killed(self):
        import os
        from pathlib import Path
        import signal
        import tempfile
        try: adapter._environment()
        except adapter.AdapterError: self.skipTest('optional isolated tool is absent')
        with tempfile.TemporaryDirectory(dir=adapter.RUNTIME) as directory:
            group_file=Path(directory)/'own-group.txt'
            code=('import os, subprocess, sys; from pathlib import Path; '
                  'subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                  f'Path({str(group_file)!r}).write_text(str(os.getpgrp()))')
            cleaned=False
            try:
                with patch.object(adapter,'TIMEOUT',0.5),patch.object(adapter.os,'killpg',wraps=os.killpg) as kill_group:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        adapter._invoke(['-c',code],adapter.RUNTIME)
                    self.assertTrue(group_file.exists(),'trusted test leader failed to start')
                    kill_group.assert_called_with(int(group_file.read_text()),signal.SIGKILL)
                    cleaned=True
            finally:
                # Clean up the trusted test child even when the red assertion fails.
                if not cleaned and group_file.exists():
                    try: os.killpg(int(group_file.read_text()),signal.SIGKILL)
                    except ProcessLookupError: pass
