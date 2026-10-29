"""Explicit commit snapshots are separate from worktree/current-head approval."""
import io
import json
from pathlib import Path
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from govcode_harness import runtime
from tests import test_runtime as fixtures

class CommitModeTests(unittest.TestCase):
    setUp = fixtures.RuntimeTests.setUp
    git = fixtures.RuntimeTests.git
    commit = fixtures.RuntimeTests.commit

    def test_dirty_current_commit_scans_committed_bytes_only(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        (self.repo/'complaints.py').write_text(runtime.BEFORE_SOURCE+'# PRIVATE_UNCHECKED\n')
        (self.repo/'untracked.py').write_text('PRIVATE_UNCHECKED')
        out=self.base/'commit-evidence'
        result=runtime.scan(self.repo,out,commit=sha,local_demo=True)
        self.assertEqual(result['outcome'],'allow')
        self.assertEqual(result['input_mode'],'commit_snapshot')
        self.assertFalse(result['worktree_checked'])
        self.assertTrue(result['head_matches_commit'])
        self.assertEqual(result['commit_sha'],sha)
        for path in out.iterdir():self.assertNotIn('PRIVATE_UNCHECKED',path.read_text())
        with self.assertRaises(runtime.HarnessError):runtime.scan(self.repo,self.base/'strict',local_demo=True)
        self.assertEqual(runtime.verify(self.repo,out,local_demo=True)['outcome'],'allow')

    def test_historical_commit_stays_pinned(self):
        old=self.commit(runtime.BEFORE_SOURCE)
        self.commit(runtime.AFTER_SOURCE)
        out=self.base/'historical'
        result=runtime.scan(self.repo,out,commit=old,local_demo=True)
        self.assertEqual(result['outcome'],'deny')
        self.assertFalse(result['head_matches_commit'])
        with self.assertRaises(runtime.HarnessError) as error:runtime.verify(self.repo,out,local_demo=True)
        self.assertEqual(error.exception.code,'STALE_HEAD')
        self.assertEqual(runtime.verify(self.repo,out,commit=old,local_demo=True)['exit_code'],2)

    def test_invalid_commit_never_creates_output(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        blob=self.git('rev-parse','HEAD:complaints.py')
        self.git('tag','-a','fixture-tag','-m','synthetic')
        tag=self.git('rev-parse','fixture-tag')
        for index,value in enumerate(['HEAD',sha[:8],'-c','z'*40,'f'*40,blob,tag]):
            with self.subTest(value=value):
                out=self.base/('bad-'+str(index))
                with self.assertRaises(runtime.HarnessError):runtime.scan(self.repo,out,commit=value,local_demo=True)
                self.assertFalse(out.exists())

    def test_explicit_verify_requires_same_commit_and_mode(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        out=self.base/'explicit'
        runtime.scan(self.repo,out,commit=sha,local_demo=True)
        other=self.commit(runtime.BEFORE_SOURCE)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,commit=other,local_demo=True)
        strict=self.base/'strict'
        runtime.scan(self.repo,strict,local_demo=True)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,strict,commit=other,local_demo=True)

    def test_snapshot_manifest_missing_or_forged_is_rejected(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        out=self.base/'evidence'
        runtime.scan(self.repo,out,commit=sha,local_demo=True)
        snapshot=json.loads((out/'snapshot.json').read_text())
        self.assertEqual(snapshot['commit_sha'],sha)
        self.assertNotIn('sources',snapshot)
        snapshot['files'][0]['sha256']='f'*64
        (out/'snapshot.json').write_text(json.dumps(snapshot))
        runtime._seal(out)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,commit=sha,local_demo=True)
        (out/'snapshot.json').unlink()
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,commit=sha,local_demo=True)

    def test_mode_downgrade_even_after_reseal_is_rejected(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        out=self.base/'evidence'
        runtime.scan(self.repo,out,commit=sha,local_demo=True)
        execution=json.loads((out/'execution.json').read_text())
        execution['input_scope']['mode']='strict_head'
        execution['input_scope']['worktree_checked']=True
        (out/'execution.json').write_text(json.dumps(execution));runtime._seal(out)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_parent_mode_must_match(self):
        self.commit(runtime.BEFORE_SOURCE)
        runtime.scan(self.repo,self.base/'before',local_demo=True)
        sha=self.commit(runtime.AFTER_SOURCE)
        with self.assertRaises(runtime.HarnessError):
            runtime.scan(self.repo,self.base/'after',parent=self.base/'before',commit=sha,local_demo=True)

    def test_explicit_parent_links_old_commit_in_dirty_tree(self):
        before=self.commit(runtime.BEFORE_SOURCE)
        runtime.scan(self.repo,self.base/'before',commit=before,local_demo=True)
        after=self.commit(runtime.AFTER_SOURCE)
        (self.repo/'complaints.py').unlink()
        result=runtime.scan(self.repo,self.base/'after',parent=self.base/'before',commit=after,local_demo=True)
        self.assertEqual(result['outcome'],'allow')
        self.assertIsNotNone(json.loads((self.base/'after/run.json').read_text())['parent_run_id'])

    def test_strict_summary_and_manifest(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        result=runtime.scan(self.repo,self.base/'strict',local_demo=True)
        self.assertEqual(result['input_mode'],'strict_head')
        self.assertTrue(result['worktree_checked'])
        self.assertEqual(json.loads((self.base/'strict/snapshot.json').read_text())['commit_sha'],sha)

    def test_commit_mode_does_not_follow_untracked_symlink_or_ignored_cache(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        outside=self.base/'outside-secret';outside.write_text('PRIVATE_UNCHECKED')
        (self.repo/'cache').mkdir()
        (self.repo/'cache'/'secret.py').symlink_to(outside)
        (self.repo/'.gitignore').write_text('cache/\n')
        result=runtime.scan(self.repo,self.base/'ignored',commit=sha,local_demo=True)
        self.assertEqual(result['outcome'],'allow')
        self.assertFalse(result['worktree_checked'])
        manifest=json.loads((self.base/'ignored/snapshot.json').read_text())
        self.assertEqual([file['path'] for file in manifest['files']],['complaints.py'])

    def test_requested_commit_does_not_follow_moving_head(self):
        pinned=self.commit(runtime.AFTER_SOURCE)
        newer=self.commit(runtime.BEFORE_SOURCE)
        self.git('reset','--hard',pinned)
        original=runtime._analysis
        moved=False
        def advance(repo, commit, **kwargs):
            nonlocal moved
            if not moved:
                self.git('update-ref','HEAD',newer)
                moved=True
            return original(repo,commit,**kwargs)
        with patch.object(runtime,'_analysis',side_effect=advance):
            result=runtime.scan(self.repo,self.base/'moving',commit=pinned,local_demo=True)
        self.assertEqual(result['commit_sha'],pinned)
        self.assertEqual(result['outcome'],'allow')
        self.assertFalse(result['head_matches_commit'])

    def test_removed_mode_after_reseal_is_rejected(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        out=self.base/'removed-mode'
        runtime.scan(self.repo,out,commit=sha,local_demo=True)
        execution=json.loads((out/'execution.json').read_text())
        del execution['input_scope']
        (out/'execution.json').write_text(json.dumps(execution));runtime._seal(out)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,commit=sha,local_demo=True)

    def test_cli_commit_flag_and_scope_json(self):
        sha=self.commit(runtime.AFTER_SOURCE)
        (self.repo/'cache.bin').write_bytes(b'PRIVATE_CACHE')
        command=subprocess.run(['python3','-m','govcode_harness','scan','--repo',str(self.repo),
            '--output',str(self.base/'cli'),'--local-demo','--commit',sha],
            cwd=Path(runtime.__file__).resolve().parents[1],capture_output=True,text=True)
        self.assertEqual(command.returncode,0,command.stderr)
        result=json.loads(command.stdout)
        self.assertEqual(result['scope'],'all_tracked_files_at_commit')
        self.assertFalse(result['worktree_checked'])
        self.assertNotIn('PRIVATE_CACHE',command.stdout+command.stderr)

if __name__=='__main__':unittest.main()
