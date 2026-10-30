"""Ralph completion cannot be inferred from a progress label alone."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / 'scripts/ralph_r7_checkpoint.py'


def module():
    spec = importlib.util.spec_from_file_location('r7_checkpoint', SCRIPT)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class RalphR7CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.loop = self.root/'loop';self.loop.mkdir()

    def write(self,name,value):
        (self.loop/name).write_text(json.dumps(value))

    def proof(self):
        (self.root/'source.py').write_text('# current source\n')
        self.write('progress.json',dict(scope_mode='local_reference',operational_approval=False,phases={phase:dict(implementation='complete',acceptance='passed') for phase in ('R7-F','R7-G','R7-H','R7-I')}))
        self.write('final-proof.json',dict(full_suite=dict(tests=600,failures=0,errors=0,skipped=0,exit_code=0),final_review='APPROVED',installed_package_verified=True,reference_result='reference.json',operational_approval=False))
        (self.root/'reference.json').write_text(json.dumps(dict(operational_approval=False,total_requirements=8,current_stage_satisfied=5,not_due=1,approved_exclusions=2,checks=dict(reinspection=True,code_and_documents=True,recovery=True))))
        self.write('source-manifest.json',dict(files=[dict(path='source.py',sha256=hashlib.sha256((self.root/'source.py').read_bytes()).hexdigest())]))

    def test_rejects_incomplete_phase(self):
        self.proof();p=json.loads((self.loop/'progress.json').read_text());p['phases']['R7-H']['acceptance']='pending';self.write('progress.json',p)
        with self.assertRaises(ValueError):module().validate_completion(self.root,self.loop)

    def test_rejects_skipped_regression(self):
        self.proof();p=json.loads((self.loop/'final-proof.json').read_text());p['full_suite']['skipped']=1;self.write('final-proof.json',p)
        with self.assertRaises(ValueError):module().validate_completion(self.root,self.loop)

    def test_rejects_source_changed_after_proof(self):
        self.proof();(self.root/'source.py').write_text('# different source')
        with self.assertRaises(ValueError):module().validate_completion(self.root,self.loop)

    def test_accepts_only_complete_bound_proof(self):
        self.proof();self.assertTrue(module().validate_completion(self.root,self.loop))

    def test_rejects_failed_reference_check(self):
        self.proof();v=json.loads((self.root/'reference.json').read_text());v['checks']['recovery']=False;(self.root/'reference.json').write_text(json.dumps(v))
        with self.assertRaises(ValueError):module().validate_completion(self.root,self.loop)

    def test_actual_hook_preserves_prompt_and_advances_iteration(self):
        code=module();prompt='Continue verified local work.'
        subprocess.run(['bash',str(code.HOOK.parents[1]/'scripts/setup-ralph-loop.sh'),prompt,'--max-iterations','3','--completion-promise',code.PROMISE],cwd=self.loop,check=True,capture_output=True,text=True)
        self.write('controller.json',dict(session_id='',iteration=1,status='active',promise=code.PROMISE))
        (self.loop/'PROMPT.md').write_text(prompt+'\n')
        result=code.checkpoint(self.root,self.loop,dict(phase='R7-F',result='in_progress'))
        self.assertEqual('active',result['status']);self.assertEqual(2,result['next_iteration'])
        self.assertTrue((self.loop/'.claude/ralph-loop.local.md').exists())
