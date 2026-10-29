import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from govcode_harness import gate, runtime
from tests import test_runtime as fixture


class GateTests(unittest.TestCase):
    setUp = fixture.RuntimeTests.setUp
    git = fixture.RuntimeTests.git
    commit = fixture.RuntimeTests.commit

    # Reuse only the real Git fixture helpers.
    def evidence(self, source='def f():\n    return 1\n', *, snapshot=True, filename='complaints.py'):
        sha = self.commit(source, filename)
        out = self.base / 'gate-evidence'
        runtime.scan(self.repo, out, local_demo=True, commit=sha if snapshot else None)
        return sha, out

    def evaluate(self, sha, out, **kwargs):
        return gate.evaluate(self.repo, out, sha, local_demo=True, **kwargs)

    def test_allow_exact_commit(self):
        sha, out = self.evidence()
        result = self.evaluate(sha, out)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['checked_commit'], sha)
        self.assertTrue(all(result['checks'].values()))
        self.assertIs(result['operational_approval'], False)

    def test_historical_safe_commit_cannot_open_current_head(self):
        sha, out = self.evidence()
        self.commit('def f():\n    return 2\n')
        self.assertEqual(self.evaluate(sha, out)['code'], 'HEAD_MISMATCH')

    def test_run_commit_must_match_trusted_expectation(self):
        _, out = self.evidence()
        sha = self.commit('def f():\n    return 2\n')
        self.assertEqual(self.evaluate(sha, out)['code'], 'RUN_COMMIT_MISMATCH')

    def test_dirty_snapshot_allowed_strict_rejected(self):
        sha = self.commit('def f():\n    return 1\n')
        for snapshot in (True, False):
            with self.subTest(snapshot=snapshot):
                out = self.base / ('snapshot' if snapshot else 'strict')
                runtime.scan(self.repo, out, local_demo=True, commit=sha if snapshot else None)
                (self.repo / 'complaints.py').write_text('PRIVATE_RAW_MARKER')
                result = self.evaluate(sha, out)
                self.assertEqual(result['exit_code'], 0 if snapshot else 4)
                (self.repo / 'complaints.py').write_text('def f():\n    return 1\n')

    def test_changed_head_during_verification_rejected(self):
        sha, out = self.evidence()
        original = runtime.verify
        def changing(*args, **kwargs):
            result = original(*args, **kwargs)
            self.commit('def f():\n    return 2\n')
            return result
        with patch.object(runtime, 'verify', side_effect=changing):
            result = self.evaluate(sha, out)
        self.assertEqual(result['code'], 'HEAD_MISMATCH')
        self.assertFalse(result['checks']['head'])

    def test_required_profile_cannot_downgrade(self):
        sha, out = self.evidence()
        self.assertEqual(self.evaluate(sha, out, with_iron_laws=True)['code'], 'PROFILE_MISMATCH')

    def test_unrequested_profile_rejected(self):
        sha, out = self.evidence()
        execution = json.loads((out / 'execution.json').read_text())
        execution['detectors'] = ['python-local-flow', 'iron-laws']
        (out / 'execution.json').write_text(json.dumps(execution))
        self.assertEqual(self.evaluate(sha, out)['code'], 'PROFILE_MISMATCH')

    def test_invalid_commit_and_flag_are_errors(self):
        sha, out = self.evidence()
        for bad in ('HEAD', sha[:8], 'f' * 40, '../PRIVATE_RAW_MARKER', None):
            self.assertEqual(self.evaluate(bad, out)['exit_code'], 4)
        self.assertEqual(gate.evaluate(self.repo, out, sha)['code'], 'LOCAL_DEMO_FLAG_REQUIRED')

    def test_receipt_missing_and_tampered_block(self):
        sha, out = self.evidence()
        receipt = out / 'receipt.json'
        receipt.write_text('{}')
        self.assertEqual(self.evaluate(sha, out)['exit_code'], 4)
        receipt.unlink()
        self.assertEqual(self.evaluate(sha, out)['exit_code'], 4)

    def test_deny_review_and_error_keep_exit_codes(self):
        for source, filename, expected in [
            ('def f(request_body, logger):\n    logger.info("%s", request_body)\n', 'complaints.py', 2),
            ('console.log("x")', 'complaints.js', 3),
            ('def malformed(', 'complaints.py', 4),
        ]:
            with self.subTest(expected=expected):
                sha = self.commit(source, filename)
                out = self.base / str(expected)
                runtime.scan(self.repo, out, commit=sha, local_demo=True)
                self.assertEqual(self.evaluate(sha, out)['exit_code'], expected)
                (self.repo / filename).unlink()
                self.git('add', '--all')
                self.git('commit', '-m', 'reset fixture')

    def test_unexpected_error_is_sanitized(self):
        sha, out = self.evidence()
        with patch.object(runtime, 'verify', side_effect=RuntimeError('PRIVATE_RAW_MARKER')):
            result = self.evaluate(sha, out)
        self.assertEqual(result['code'], 'GATE_ERROR')
        self.assertNotIn('PRIVATE_RAW_MARKER', json.dumps(result))
        self.assertNotIn(str(self.base), json.dumps(result))

    def test_cli_exit_and_redaction(self):
        sha, out = self.evidence('def f(request_body, logger):\n    logger.info("PRIVATE_RAW_MARKER=%s", request_body)\n')
        args = [sys.executable, '-m', 'govcode_harness.gate', '--repo', str(self.repo), '--evidence', str(out), '--expected-commit', sha, '--local-demo']
        for argv, expected in ((args, 2), (args[:-1], 4), (args + ['--PRIVATE_RAW_MARKER'], 4)):
            process = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(process.returncode, expected)
            self.assertEqual(json.loads(process.stdout)['exit_code'], expected)
            self.assertNotIn('PRIVATE_RAW_MARKER', process.stdout + process.stderr)
            self.assertNotIn(str(self.repo), process.stdout + process.stderr)

    def test_trusted_isolated_wrapper_publishes_proof_and_preserves_deny(self):
        import venv
        trusted = self.base / 'trusted'
        trusted.mkdir()
        root = Path(runtime.__file__).resolve().parents[1]
        shutil.copytree(root / 'govcode_harness', trusted / 'govcode_harness', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(root / 'policies', trusted / 'policies')
        environment = self.base / 'environment'
        venv.EnvBuilder(with_pip=False).create(environment)
        python = environment / 'bin' / 'python3'
        purelib = subprocess.check_output([str(python), '-I', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip()
        (Path(purelib) / 'trusted-harness.pth').write_text(str(trusted) + '\n')
        wrapper = root / 'ci' / 'reference-gate.sh'
        for index, (source, expected) in enumerate([
            ('def f(request_body, logger):\n    logger.info("PRIVATE_RAW_MARKER=%s", request_body)\n', 2),
            ('def f():\n    return 1\n', 0),
        ]):
            sha = self.commit(source)
            out = self.base / ('pipeline-' + str(index))
            # A hostile module in checkout must never be imported in isolated mode.
            (self.repo / 'govcode_harness.py').write_text('raise RuntimeError("PRIVATE_RAW_MARKER")')
            env = {**os.environ, 'GOVCODE_PYTHON': str(python), 'GOVCODE_REPO': str(self.repo),
                   'GOVCODE_EXPECTED_COMMIT': sha, 'GOVCODE_ARTIFACTS': str(out), 'GOVCODE_WITH_IRON_LAWS': '0'}
            process = subprocess.run([str(wrapper)], cwd=self.repo, env=env, text=True, capture_output=True)
            self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
            self.assertEqual(json.loads((out / 'gate.json').read_text())['exit_code'], expected)
            self.assertTrue((out / 'evidence' / 'receipt.json').is_file())
            for artifact in out.rglob('*.json'):
                self.assertNotIn('PRIVATE_RAW_MARKER', artifact.read_text())
            (self.repo / 'govcode_harness.py').unlink()
