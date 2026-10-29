import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import snapshot


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        snapshot.run_git(self.repo, 'init', '-b', 'main')

    def git(self, *args):
        return snapshot.run_git(self.repo, *args)

    def commit(self, files):
        for name, raw in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git('add', '--all')
        self.git('commit', '-m', 'synthetic fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def test_commit_is_pinned_despite_worktree_changes(self):
        sha = self.commit({'app.py': b'private_marker = 1\n', '문서.md': b'doc'})
        self.commit({'app.py': b'changed = 2\n'})
        (self.repo / 'app.py').unlink()
        (self.repo / 'untracked.py').write_text('unknown = 3')
        result = snapshot.collect(self.repo, sha)
        self.assertEqual(result['sources'], [('app.py', 'private_marker = 1\n')])
        manifest = snapshot.manifest(result)
        self.assertNotIn('private_marker', json.dumps(manifest))
        self.assertNotIn('sources', manifest)
        self.assertEqual(manifest, snapshot.manifest(snapshot.collect(self.repo, sha)))
        self.assertEqual(manifest['inventory_digest'], hashlib.sha256(json.dumps(result['inventory'], ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest())

    def test_all_files_are_classified(self):
        sha = self.commit({'ok.py': b'x=1', 'bad.py': b'\xff', 'readme.md': b'doc', 'app.js': b'x=2', '.gitignore': b'cache'})
        result = snapshot.collect(self.repo, sha)
        self.assertEqual([f['path'] for f in result['files']], sorted(f['path'] for f in result['files']))
        self.assertEqual({f['classification'] for f in result['files']}, {'python_source', 'encoding_error', 'supporting_file', 'unsupported_file'})
        self.assertEqual(result['total_bytes'], sum(f['size_bytes'] for f in result['files']))
        self.assertEqual(snapshot.manifest(result)['supported_files'], 1)
        self.assertEqual({x['code'] for x in result['issues']}, {'SOURCE_ENCODING_ERROR', 'UNSUPPORTED_FILE_TYPE'})

    def test_invalid_commit_forms_and_noncommit(self):
        sha = self.commit({'ok.py': b'x=1'})
        blob = self.git('rev-parse', 'HEAD:ok.py').decode().strip()
        tree = self.git('rev-parse', 'HEAD^{tree}').decode().strip()
        for value in [None, '', 'HEAD', sha[:12], sha.upper(), '--help', '0'*40, blob, tree]:
            with self.subTest(value=value), self.assertRaises(snapshot.SnapshotError) as caught:
                snapshot.collect(self.repo, value)
            self.assertEqual(caught.exception.code, 'COMMIT_INVALID')

    def test_no_source_and_empty_commit(self):
        self.git('commit', '--allow-empty', '-m', 'empty')
        sha = self.git('rev-parse', 'HEAD').decode().strip()
        self.assertEqual(snapshot.collect(self.repo, sha)['issues'], [{'path': '.', 'line': 1, 'code': 'NO_SUPPORTED_SOURCE'}])

    def test_limits_reject_before_blob_content(self):
        sha = self.commit({'a.py': b'12345'})
        calls = []
        def spy(repo, *args):
            calls.append(args)
            return snapshot.run_git(repo, *args)
        with self.assertRaises(snapshot.SnapshotError) as caught:
            snapshot.collect(self.repo, sha, git=spy, max_blob=4)
        self.assertEqual(caught.exception.code, 'SNAPSHOT_TOO_LARGE')
        self.assertFalse(any(args[:2] == ('cat-file', 'blob') for args in calls))
        for kwargs in [{'max_files': 0}, {'max_blob': True}, {'max_total': -1}, {'max_blob': 2.5}]:
            with self.assertRaises(snapshot.SnapshotError) as caught:
                snapshot.collect(self.repo, sha, **kwargs)
            self.assertEqual(caught.exception.code, 'SNAPSHOT_LIMIT_INVALID')

    def test_symlink_and_gitlink_rejected(self):
        sha = self.commit({'a.py': b'x=1'})
        os.symlink('a.py', self.repo / 'link')
        self.git('add', 'link')
        self.git('commit', '-m', 'link')
        with self.assertRaises(snapshot.SnapshotError) as caught:
            snapshot.collect(self.repo, self.git('rev-parse', 'HEAD').decode().strip())
        self.assertEqual(caught.exception.code, 'SOURCE_TYPE_UNSUPPORTED')
        self.git('rm', 'link')
        self.git('update-index', '--add', '--cacheinfo', '160000,' + sha + ',module')
        self.git('commit', '-m', 'gitlink')
        with self.assertRaises(snapshot.SnapshotError) as caught:
            snapshot.collect(self.repo, self.git('rev-parse', 'HEAD').decode().strip())
        self.assertEqual(caught.exception.code, 'SOURCE_TYPE_UNSUPPORTED')

    def test_git_ignores_inherited_repository_and_replace_objects(self):
        sha = self.commit({'a.py': b'x=1'})
        other = self.commit({'a.py': b'x=2'})
        self.git('replace', sha, other)
        with patch.dict(os.environ, {'GIT_DIR': '/missing', 'GIT_WORK_TREE': '/missing'}):
            self.assertEqual(snapshot.collect(self.repo, sha)['sources'], [('a.py', 'x=1')])

    def test_collector_never_runs_clean_filter(self):
        sha = self.commit({'a.py': b'x=1', '.gitattributes': b'*.py filter=untrusted'})
        marker = self.repo / 'executed'
        self.git('config', 'filter.untrusted.clean', 'touch ' + str(marker))
        self.git('config', 'core.fsmonitor', 'touch ' + str(marker))
        snapshot.collect(self.repo, sha)
        self.assertFalse(marker.exists())

    def test_tree_listing_invariants(self):
        sha = self.commit({'a.py': b'x=1'})
        original = self.git('ls-tree', '-rz', '--full-tree', sha)
        for listing, expected in [(original + original, 'SOURCE_PATH_INVALID'),
                                  (original.replace(b'a.py', b'../a.py'), 'SOURCE_PATH_INVALID'),
                                  (original.replace(b'a.py', b'a\x7f.py'), 'SOURCE_PATH_INVALID'),
                                  (original.replace(b'a.py', b'\xff.py'), 'SOURCE_PATH_INVALID'),
                                  (original.replace(b'100644', b'120000'), 'SOURCE_TYPE_UNSUPPORTED')]:
            def spy(repo, *args):
                return listing if args[0] == 'ls-tree' else snapshot.run_git(repo, *args)
            with self.subTest(expected=expected), self.assertRaises(snapshot.SnapshotError) as caught:
                snapshot.collect(self.repo, sha, git=spy)
            self.assertEqual(caught.exception.code, expected)

    def test_count_total_and_object_length_mismatch(self):
        sha = self.commit({'a.py': b'123', 'b.py': b'456'})
        for kwargs in [{'max_files': 1}, {'max_total': 5}]:
            with self.assertRaises(snapshot.SnapshotError) as caught:
                snapshot.collect(self.repo, sha, **kwargs)
            self.assertEqual(caught.exception.code, 'SNAPSHOT_TOO_LARGE')
        def spy(repo, *args):
            return b'secret overflow' if args[:2] == ('cat-file', 'blob') else snapshot.run_git(repo, *args)
        with self.assertRaises(snapshot.SnapshotError) as caught:
            snapshot.collect(self.repo, sha, git=spy)
        self.assertEqual(str(caught.exception), 'SNAPSHOT_TOO_LARGE')

    def test_git_arguments_and_environment_are_hardened(self):
        captured = []
        real = subprocess.Popen
        def observe(command, **kwargs):
            captured.append((command, kwargs))
            return real(command, **kwargs)
        with patch.object(snapshot.subprocess, 'Popen', side_effect=observe), patch.dict(os.environ, {'GIT_TRACE': '/secret', 'GIT_CONFIG_COUNT': '1'}):
            self.git('rev-parse', '--git-dir')
        command, options = captured[0]
        self.assertTrue(options['start_new_session'])
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        self.assertEqual(options['env']['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual(options['env']['GIT_ALLOW_PROTOCOL'], '')
        self.assertEqual(options['env']['GIT_GRAFT_FILE'], os.devnull)
        self.assertNotIn('GIT_TRACE', options['env'])
        self.assertNotIn('GIT_CONFIG_COUNT', options['env'])
        for flag in ['--no-replace-objects', 'core.fsmonitor=false', 'protocol.allow=never', 'commit.gpgsign=false']:
            self.assertIn(flag, command)

    def test_git_bounds_stdout_and_stderr_and_redacts_diagnostics(self):
        import sys
        real = subprocess.Popen
        for fd in [1, 2]:
            def fake(command, **kwargs):
                return real([sys.executable, '-c', 'import os; os.write(' + str(fd) + ', b"SECRET" * 100000)'], **kwargs)
            with patch.object(snapshot.subprocess, 'Popen', side_effect=fake), patch.object(snapshot, 'MAX_GIT_OUTPUT', 1024):
                with self.assertRaises(snapshot.SnapshotError) as caught:
                    self.git('unused')
            self.assertEqual(str(caught.exception), 'GIT_FAILURE')

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX process groups')
    def test_timeout_cleans_group_even_after_leader_exit(self):
        import sys
        import time
        real = subprocess.Popen
        marker = self.repo / 'surviving-child'
        program = 'import os,time; child=os.fork();\nif child: os._exit(0)\ntime.sleep(.6)\nopen(' + repr(str(marker)) + ',"w").write("survived")\n'
        def fake(command, **kwargs):
            return real([sys.executable, '-c', program], **kwargs)
        with patch.object(snapshot.subprocess, 'Popen', side_effect=fake), patch.object(snapshot, 'GIT_TIMEOUT', .15):
            with self.assertRaises(snapshot.SnapshotError):
                self.git('unused')
        time.sleep(.65)
        self.assertFalse(marker.exists())

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX process groups')
    def test_success_cleans_child_that_closed_pipes(self):
        import sys
        import time
        real = subprocess.Popen
        marker = self.repo / 'surviving-child'
        program = 'import os,time; child=os.fork();\nif child: os._exit(0)\nos.close(1); os.close(2)\ntime.sleep(.3)\nopen(' + repr(str(marker)) + ',"w").write("survived")\n'
        def fake(command, **kwargs):
            return real([sys.executable, '-c', program], **kwargs)
        with patch.object(snapshot.subprocess, 'Popen', side_effect=fake):
            self.assertEqual(self.git('unused'), b'')
        time.sleep(.4)
        self.assertFalse(marker.exists())

    def test_callback_error_adapter_preserves_invalid_commit_code(self):
        class AdaptedError(Exception):
            code = 'GIT_FAILURE'
        def callback(repo, *args):
            raise AdaptedError()
        with self.assertRaises(snapshot.SnapshotError) as caught:
            snapshot.validate_commit(self.repo, '0' * 40, git=callback)
        self.assertEqual(caught.exception.code, 'COMMIT_INVALID')

    def test_manifest_contract_is_exact_and_detached(self):
        sha = self.commit({'a.py': b'SYNTHETIC_SECRET = 1'})
        result = snapshot.collect(self.repo, sha)
        self.assertEqual(set(result), {'format', 'commit_sha', 'inventory', 'files', 'sources', 'issues', 'total_bytes'})
        manifest = snapshot.manifest(result)
        self.assertEqual(set(manifest), {'format', 'commit_sha', 'scope', 'inventory_digest', 'files', 'total_bytes', 'supported_files', 'issues'})
        self.assertEqual(manifest['scope'], 'all_tracked_files_at_commit')
        manifest['files'][0]['path'] = 'changed'
        self.assertEqual(result['files'][0]['path'], 'a.py')
        schema = json.loads((Path(__file__).resolve().parents[1] / 'packages/contracts/snapshot.schema.json').read_text())
        self.assertEqual(schema['$schema'], 'http://json-schema.org/draft-07/schema#')
        self.assertEqual(set(schema['required']), set(manifest))
        self.assertFalse(schema['additionalProperties'])
