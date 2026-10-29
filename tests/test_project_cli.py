from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

from govcode_harness.__main__ import main

FIXTURE = Path(__file__).parent / 'fixtures/project-compliance/profile.example.json'


class ProjectCLITests(unittest.TestCase):
    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = main(['project', *args])
        return result, out.getvalue(), err.getvalue()

    def test_unknown_profile_is_review_not_approval(self):
        result, out, err = self.invoke(['validate-profile', '--profile', str(FIXTURE)])
        value = json.loads(out)
        self.assertEqual(3, result)
        self.assertTrue(value['valid'])
        self.assertEqual('not_checked', value['approval_status'])
        self.assertFalse(value['requirements_evaluated'])
        self.assertEqual('review_required', value['outcome'])
        self.assertEqual('', err)

    def test_known_facts_validate_without_becoming_gate_allow(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            path = Path(tmp) / 'profile.json'
            profile = json.loads(FIXTURE.read_text())
            profile['facts'] = {'public_web': profile['facts']['public_web']}
            path.write_text(json.dumps(profile))
            result, out, _ = self.invoke(['validate-profile', '--profile', str(path)])
            self.assertEqual(0, result)
            self.assertEqual('validated', json.loads(out)['outcome'])
            self.assertNotIn('allow', json.loads(out).values())

    def test_required_missing_fact_is_reported(self):
        result, out, _ = self.invoke(['validate-profile', '--profile', str(FIXTURE), '--require-fact', 'not_supplied'])
        self.assertEqual(3, result)
        gaps = json.loads(out)['information_gaps']
        self.assertEqual('missing', next(g['state'] for g in gaps if g['fact'] == 'not_supplied'))

    def test_errors_and_future_subcommands_do_not_fall_back(self):
        for args in (['assess'], ['validate-profile'], ['validate-profile', '--profile', '/does-not-exist']):
            code, out, err = self.invoke(args)
            self.assertEqual(4, code)
            self.assertEqual('', out)
            self.assertEqual('error', json.loads(err)['outcome'])

    def test_actual_demo_creates_signed_revisions_and_preserves_unknown(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            output = Path(tmp) / 'profile-demo'
            code, out, err = self.invoke(['profile-demo', '--output', str(output)])
            result = json.loads(out)
            self.assertEqual(0, code)
            self.assertTrue(all(result['checks'].values()))
            self.assertFalse(result['operational_approval'])
            self.assertEqual(2, result['active_revision'])
            self.assertEqual(1, result['initial_information_gaps'])
            for path in (output / 'private').rglob('*.key'):
                self.assertEqual(0, stat.S_IMODE(path.stat().st_mode) & 0o077)
            self.assertNotIn('private_path', out)
            code, _, _ = self.invoke(['profile-demo', '--output', str(output)])
            self.assertEqual(4, code)
            self.assertEqual('', err)


if __name__ == '__main__':
    unittest.main()
