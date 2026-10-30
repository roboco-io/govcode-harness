from contextlib import redirect_stdout,redirect_stderr
import io,json,unittest
from govcode_harness.__main__ import main


class ProjectStageCLITests(unittest.TestCase):
    def test_gate_help_requires_caller_expected_inputs(self):
        out=io.StringIO()
        with redirect_stdout(out),self.assertRaises(SystemExit) as caught:
            main(['project','gate','--help'])
        self.assertEqual(0,caught.exception.code)
        for flag in ('--expected-commit','--expected-subject-digest','--expected-evaluation-digest','--evidence-store','--code-context'):
            self.assertIn(flag,out.getvalue())

    def test_unsigned_report_cannot_replace_gate_inputs(self):
        for args in (['gate'],['gate','--report','untrusted.json']):
            out,err=io.StringIO(),io.StringIO()
            with redirect_stdout(out),redirect_stderr(err):result=main(['project',*args])
            self.assertEqual(4,result);self.assertEqual('',out.getvalue());self.assertEqual('error',json.loads(err.getvalue())['outcome'])
