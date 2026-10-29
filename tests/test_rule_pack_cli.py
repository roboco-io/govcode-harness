from contextlib import redirect_stdout,redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness.__main__ import main


class RulePackCLITests(unittest.TestCase):
    @staticmethod
    def invoke(args):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):code=main(['project',*args])
        return code,out.getvalue(),err.getvalue()

    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(dir='/private/tmp')
        cls.root=Path(cls.tmp.name)/'demo'
        code,out,err=cls.invoke(['pack-demo','--output',str(cls.root)])
        if code != 0:
            cls.tmp.cleanup()
            raise AssertionError('pack-demo feature unavailable: '+err)
        cls.report=json.loads(out)

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def assess_args(self):
        anchor=json.loads((self.root/'revocation-anchor.json').read_text())
        return ['assess-applicability','--profile-registry',str(self.root/'profile-registry'),
            '--lock',str(self.root/'pack-lock.json'),'--trust',str(self.root/'public-trust.json'),
            '--revocations',str(self.root/'revocations.json'),'--expected-revocation-digest',anchor['digest'],
            '--min-revocation-epoch',str(anchor['epoch']),'--min-sequence','2',
            '--tenant-id','TENANT-REFERENCE','--project-id','PROJECT-DELIVERY-REFERENCE']

    def test_signed_demo_checks_unknown_stale_and_revoked_cases(self):
        self.assertTrue(all(self.report['checks'].values()))
        self.assertEqual(2,self.report['initial_counts']['pending'])
        self.assertEqual(0,self.report['final_counts']['pending'])
        self.assertFalse(self.report['operational_approval'])
        self.assertFalse(self.report['requirements_evaluated'])
        code,_,_=self.invoke(['pack-demo','--output',str(self.root)])
        self.assertEqual(4,code)

    def test_applicability_cli_resolves_with_independent_review(self):
        code,out,err=self.invoke(self.assess_args()+['--review',str(self.root/'applicability-review.json')])
        value=json.loads(out)
        self.assertEqual(0,code)
        self.assertEqual('applicability_resolved',value['outcome'])
        self.assertEqual(1,value['counts']['not_applicable'])
        self.assertEqual('',err)

    def test_without_exclusion_review_the_cli_returns_three(self):
        code,out,_=self.invoke(self.assess_args())
        self.assertEqual(3,code)
        self.assertEqual(1,json.loads(out)['counts']['pending'])

    def test_bad_anchor_and_foreign_scope_are_errors(self):
        for field,value in [('--expected-revocation-digest','f'*64),('--project-id','foreign')]:
            args=self.assess_args();args[args.index(field)+1]=value
            code,out,err=self.invoke(args)
            self.assertEqual(4,code)
            self.assertEqual('',out)
            self.assertEqual('error',json.loads(err)['outcome'])

    def test_pack_validation_is_not_publication(self):
        code,out,_=self.invoke(['validate-pack','--manifest',str(self.root/'delivery-manifest.json'),
                               '--requirements',str(self.root/'delivery-requirements.json')])
        self.assertEqual(0,code)
        self.assertEqual('not_checked',json.loads(out)['approval_status'])


if __name__ == '__main__':unittest.main()
