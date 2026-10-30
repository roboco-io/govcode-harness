from contextlib import redirect_stdout,redirect_stderr
import io,json,unittest
from govcode_harness.__main__ import main


class ProjectReferenceCLITests(unittest.TestCase):
    def test_project_demo_help_exists_at_both_entry_points(self):
        for args in (['project-demo','--help'],['project','project-demo','--help']):
            out=io.StringIO()
            with redirect_stdout(out),self.assertRaises(SystemExit) as caught:main(args)
            self.assertEqual(0,caught.exception.code);self.assertIn('--output',out.getvalue())

    def test_no_output_is_an_error_not_an_implicit_shared_demo(self):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):code=main(['project','project-demo'])
        self.assertEqual(4,code);self.assertEqual('',out.getvalue());self.assertEqual('error',json.loads(err.getvalue())['outcome'])
