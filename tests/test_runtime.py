import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import runtime

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / 'repository'
        self.repo.mkdir()
        self.git('init', '-b', 'main')

    def git(self, *args):
        env = {**os.environ, 'GIT_CONFIG_GLOBAL':os.devnull, 'GIT_CONFIG_NOSYSTEM':'1'}
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
            '-c', 'user.name=GovCode synthetic demo', '-c', 'user.email=demo@example.invalid', *args],
            cwd=self.repo, env=env, check=True, capture_output=True).stdout.decode().strip()

    def commit(self, source, filename='complaints.py'):
        (self.repo / filename).write_text(source)
        self.git('add', '--all')
        self.git('commit', '-m', 'synthetic fixture')
        return self.git('rev-parse', 'HEAD')

    def test_risky_snapshot_is_denied_with_local_receipt(self):
        self.commit('def submit(request_body, logger):\n    logger.info("complaint=%s", request_body)\n')
        result = runtime.scan(self.repo, self.base / 'before', local_demo=True)
        self.assertEqual(result['outcome'], 'deny')
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue((self.base / 'before' / 'receipt.json').is_file())

    def test_fixed_new_commit_rechecks_and_links_denied_parent(self):
        old = self.commit('def submit(request_body, logger):\n    logger.info("complaint=%s", request_body)\n')
        runtime.scan(self.repo, self.base / 'before', local_demo=True)
        new = self.commit('def submit(request_body, request_id, logger):\n    logger.info("received", extra={"request_id": request_id})\n')
        result = runtime.scan(self.repo, self.base / 'after', parent=self.base / 'before', local_demo=True)
        self.assertEqual(result['outcome'], 'allow')
        run = json.loads((self.base / 'after' / 'run.json').read_text())
        self.assertEqual(run['commit_sha'], new)
        self.assertNotEqual(old, new)
        self.assertIsNotNone(run['parent_run_id'])
        self.assertEqual(runtime.verify(self.repo, self.base / 'after', local_demo=True)['outcome'], 'allow')

    def test_explicit_mode_required(self):
        self.commit('def f():\n    return 1\n')
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, self.base / 'evidence')

    def test_dirty_worktree_rejected(self):
        self.commit('def f():\n    return 1\n')
        (self.repo / 'complaints.py').write_text('changed')
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, self.base / 'evidence', local_demo=True)

    def test_untracked_source_rejected(self):
        self.commit('def f():\n    return 1\n')
        (self.repo / 'untracked.py').write_text('print("x")')
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, self.base / 'evidence', local_demo=True)

    def test_existing_output_never_overwritten(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        out.mkdir()
        (out / 'sentinel').write_text('keep')
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, out, local_demo=True)
        self.assertEqual((out / 'sentinel').read_text(), 'keep')

    def test_unsupported_language_review(self):
        self.commit('console.log(request.body)', 'complaints.js')
        result = runtime.scan(self.repo, self.base / 'evidence', local_demo=True)
        self.assertEqual(result['outcome'], 'review_required')
        self.assertEqual(result['exit_code'], 3)

    def test_syntax_error_is_error(self):
        self.commit('def malformed(')
        self.assertEqual(runtime.scan(self.repo, self.base / 'evidence', local_demo=True)['exit_code'], 4)

    def test_tampered_or_deleted_artifact_rejected(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        (out / 'decision.json').write_text('{}')
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo, out, local_demo=True)
        (out / 'decision.json').unlink()
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo, out, local_demo=True)

    def test_receipt_missing_rejected(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        (out / 'receipt.json').unlink()
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo, out, local_demo=True)

    def test_current_head_must_match(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        self.commit('def f():\n    return 2\n')
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo, out, local_demo=True)

    def test_source_symlink_rejected(self):
        target = self.base / 'elsewhere'
        target.write_text('def f(): pass')
        (self.repo / 'complaints.py').symlink_to(target)
        self.git('add', '--all')
        self.git('commit', '-m', 'link fixture')
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, self.base / 'evidence', local_demo=True)

    def test_output_symlink_rejected(self):
        self.commit('def f():\n    return 1\n')
        real = self.base / 'real'
        real.mkdir()
        link = self.base / 'linked'
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, link / 'evidence', local_demo=True)

    def test_no_raw_source_or_body_in_artifacts(self):
        marker = 'PRIVATE_SENTINEL_NEVER_COPY'
        self.commit('def submit(request_body, logger):\n    logger.info("'+marker+'=%s", request_body)\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        for path in out.iterdir():
            self.assertNotIn(marker, path.read_text())
            self.assertNotIn('logger.info', path.read_text())

    def test_demo_runs_deny_fix_allow(self):
        out = self.base / 'demo'
        report = runtime.demo(out)
        self.assertEqual(report['before']['exit_code'], 2)
        self.assertEqual(report['after']['exit_code'], 0)
        self.assertTrue(report['regression']['response_preserved'])
        self.assertTrue(report['regression']['audit_preserved'])
        self.assertTrue(report['regression']['body_removed_from_app_log'])
        with self.assertRaises(runtime.HarnessError):
            runtime.demo(out)

    def test_forged_semantic_decision_rejected_even_with_rehashed_artifacts(self):
        self.commit('def submit(request_body, logger):\n    logger.info("complaint=%s", request_body)\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        decision = json.loads((out / 'decision.json').read_text())
        decision['outcome'] = 'allow'
        (out / 'decision.json').write_text(json.dumps(decision))
        # Rehash is deliberately exposed only as a writer helper: verification must recompute semantics.
        runtime._seal(out)
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo, out, local_demo=True)

    def test_repository_clean_filter_is_never_executed(self):
        self.commit('def f():\n    return 1\n')
        (self.repo / '.gitattributes').write_text('*.py filter=evil\n')
        self.git('add', '--all')
        self.git('commit', '-m', 'attributes fixture')
        marker = self.base / 'filter-executed'
        self.git('config', 'filter.evil.clean', 'touch ' + str(marker) + '; cat')
        (self.repo / 'complaints.py').write_text('def f():\n    return 2\n')
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, self.base / 'evidence', local_demo=True)
        self.assertFalse(marker.exists())

    def test_malformed_top_level_evidence_is_sanitized(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        (out / 'run.json').write_text('[]')
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo, out, local_demo=True)

    def test_oversized_blob_rejected_before_content_read(self):
        self.commit('x' * (runtime.MAX_BLOB + 1))
        original = runtime._git
        calls = []
        def observed(repo, *args):
            calls.append(args)
            return original(repo, *args)
        with patch.object(runtime, '_git', side_effect=observed):
            with self.assertRaises(runtime.HarnessError) as result:
                runtime.scan(self.repo, self.base / 'evidence', local_demo=True)
        self.assertEqual(result.exception.code, 'SNAPSHOT_TOO_LARGE')
        self.assertTrue(any(a[:2] == ('cat-file', '-s') for a in calls))
        self.assertFalse(any(a[:2] == ('cat-file', 'blob') for a in calls))

    def test_changed_tool_invalidates_evidence(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        with patch.object(runtime, '_tool_digest', return_value='f' * 64):
            with self.assertRaises(runtime.HarnessError):
                runtime.verify(self.repo, out, local_demo=True)

    def test_invalid_policy_never_allows(self):
        self.commit('def f():\n    return 1\n')
        profile = json.loads(runtime.PROFILE_PATH.read_text())
        profile['effect'] = 'allow'
        invalid = self.base / 'invalid-policy.json'
        invalid.write_text(json.dumps(profile))
        with patch.object(runtime, 'PROFILE_PATH', invalid):
            with self.assertRaises(runtime.HarnessError) as result:
                runtime.scan(self.repo, self.base / 'evidence', local_demo=True)
        self.assertEqual(result.exception.code, 'POLICY_INVALID')

    def test_storage_failure_never_exposes_allow(self):
        self.commit('def f():\n    return 1\n')
        with patch.object(runtime, '_write', side_effect=runtime.HarnessError('EVIDENCE_WRITE_FAILED')):
            with self.assertRaises(runtime.HarnessError) as result:
                runtime.scan(self.repo, self.base / 'evidence', local_demo=True)
        self.assertEqual(result.exception.code, 'EVIDENCE_WRITE_FAILED')

    def test_cli_rejects_error_without_raw_source(self):
        (self.repo / 'complaints.py').write_text('PRIVATE_SENTINEL')
        command = subprocess.run(['python3', '-m', 'govcode_harness', 'scan', '--repo', str(self.repo),
            '--output', str(self.base / 'evidence'), '--local-demo'],
            cwd=Path(runtime.__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(command.returncode, 4)
        self.assertNotIn('PRIVATE_SENTINEL', command.stdout + command.stderr)
        self.assertNotIn('Traceback', command.stderr)

    def test_staged_index_change_rejected_even_when_worktree_matches_head(self):
        original = 'def f():\n    return 1\n'
        self.commit(original)
        (self.repo / 'complaints.py').write_text('def f():\n    return 2\n')
        self.git('add', '--all')
        (self.repo / 'complaints.py').write_text(original)
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo, self.base / 'evidence', local_demo=True)

    def test_interpreter_fingerprint_change_invalidates_evidence(self):
        self.commit('def f():\n    return 1\n')
        out = self.base / 'evidence'
        runtime.scan(self.repo, out, local_demo=True)
        with patch.object(runtime.sys, 'version_info', (99, 0, 0, 'final', 0)):
            with self.assertRaises(runtime.HarnessError):
                runtime.verify(self.repo, out, local_demo=True)

if __name__ == '__main__':
    unittest.main()
