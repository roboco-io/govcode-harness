"""Assessment commands require original authorities; plan does not approve."""
from contextlib import redirect_stdout,redirect_stderr
import io,json,unittest
from govcode_harness.__main__ import main


class ProjectAssessmentCLITests(unittest.TestCase):
    def invoke(self,args):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):code=main(['project',*args])
        return code,out.getvalue(),err.getvalue()

    def test_assess_help_declares_original_authorities(self):
        out=io.StringIO()
        with redirect_stdout(out),self.assertRaises(SystemExit) as caught:
            main(['project','assess','--help'])
        self.assertEqual(0,caught.exception.code)
        self.assertIn('--expected-revocation-digest',out.getvalue())
        self.assertIn('--artifact-review',out.getvalue())

    def test_plan_and_assess_do_not_accept_an_unsigned_report(self):
        for args in (['plan'],['assess'],['assess','--report','untrusted.json']):
            code,out,err=self.invoke(args)
            self.assertEqual(4,code);self.assertEqual('',out)
            self.assertEqual('error',json.loads(err)['outcome'])
