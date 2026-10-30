"""Public commands must distinguish artifact inspection from fulfillment."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness.__main__ import main


class ArtifactCLITests(unittest.TestCase):
    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(['project', *args])
        return code, out.getvalue(), err.getvalue()

    def test_actual_artifact_demo_detects_repairs_and_rechecks(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp) / 'demo'
            code, out, err = self.invoke(['artifact-demo', '--output', str(root)])
            self.assertEqual(0, code, err)
            result = json.loads(out)
            self.assertTrue(all(result['checks'].values()))
            self.assertFalse(result['requirements_evaluated'])
            self.assertFalse(result['operational_approval'])
            self.assertNotIn('private_path', out)
            before = json.loads((root / 'before-report.json').read_text())
            after = json.loads((root / 'after-report.json').read_text())
            self.assertNotEqual(before['commit_sha'], after['commit_sha'])
            self.assertEqual('review_required', after['outcome'])
            self.assertEqual('not_checked', after['requirement_authority'])
            self.assertNotIn('PRIVATE-CONTENT', json.dumps(after))
            code, _, _ = self.invoke(['artifact-demo', '--output', str(root)])
            self.assertEqual(4, code)

    def test_invalid_inspection_does_not_fall_back_to_code_or_profile(self):
        for args in (['inspect-artifacts'], ['inspect-artifacts', '--repo', '/missing'],
                     ['artifact-demo']):
            code, out, err = self.invoke(args)
            self.assertEqual(4, code)
            self.assertEqual('', out)
            self.assertEqual('error', json.loads(err)['outcome'])
