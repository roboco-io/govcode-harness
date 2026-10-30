"""Commit-pinned private document bytes and public source-free manifests."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from govcode_harness import snapshot
from govcode_harness.project import contracts


class ArtifactSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        snapshot.run_git(self.repo, 'init', '-b', 'main')
        self.common = dict(schema_version='1', context='synthetic_reference', tenant_id='t', project_id='p', operational_approval=False)
        self.artifact = dict(self.common, kind='artifact_ref', id='DOC', version='1', artifact_kind='design',
                             relative_path='docs/design.md', content_digest=hashlib.sha256(b'# Private marker\n').hexdigest())
        self.index = dict(self.common, kind='project_artifact_index', artifacts=[self.artifact], requirements=[], traces=[])

    def api(self):
        from govcode_harness.project import artifact_snapshot
        return artifact_snapshot

    def commit(self, files=None, index=None, raw_index=None):
        values = {'docs/design.md': b'# Private marker\n'}
        values.update(files or {})
        values['artifacts.json'] = raw_index if raw_index is not None else json.dumps(self.index if index is None else index, ensure_ascii=False).encode()
        for name, raw in values.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        snapshot.run_git(self.repo, 'add', '--all')
        snapshot.run_git(self.repo, 'commit', '--allow-empty', '-m', 'synthetic document input')
        return snapshot.run_git(self.repo, 'rev-parse', 'HEAD').decode().strip()

    def collect(self, commit, path='artifacts.json', **kwargs):
        return self.api().collect(self.repo, commit, path, tenant_id='t', project_id='p', **kwargs)

    def rejected(self, commit, code=None, path='artifacts.json', **kwargs):
        with self.assertRaises(self.api().ArtifactSnapshotError) as caught:
            self.collect(commit, path, **kwargs)
        if code:
            self.assertEqual(code, caught.exception.code)

    def test_common_capture_reads_all_bytes_without_code_requirement(self):
        commit = self.commit()
        result = snapshot.capture(self.repo, commit)
        self.assertEqual(b'# Private marker\n', result['blobs']['docs/design.md'])
        self.assertEqual(commit, result['commit_sha'])
        self.assertEqual(2, len(result['inventory']))
        self.assertEqual(sum(len(v) for v in result['blobs'].values()), result['total_bytes'])
        self.assertEqual({'path', 'sha256', 'size_bytes'}, set(result['inventory'][0]))
        self.assertEqual('NO_SUPPORTED_SOURCE', snapshot.collect(self.repo, commit)['issues'][0]['code'])

    def test_same_bytes_are_read_once_and_manifest_contains_no_body(self):
        commit = self.commit({'unregistered.txt': b'not an artifact'})
        calls = []
        def git(repo, *args):
            calls.append(args)
            return snapshot.run_git(repo, *args)
        result = self.collect(commit, git=git)
        self.assertEqual(3, sum(args[:2] == ('cat-file', 'blob') for args in calls))
        self.assertEqual(b'# Private marker\n', result['contents']['DOC'])
        manifest = result['manifest']
        self.assertEqual('govcode-project-artifact-snapshot-v1', manifest['format'])
        self.assertEqual(3, len(manifest['inventory']))
        self.assertEqual(hashlib.sha256((self.repo/'artifacts.json').read_bytes()).hexdigest(), manifest['index_digest'])
        self.assertEqual(contracts.digest(result['index']), manifest['index_canonical_digest'])
        self.assertFalse(manifest['worktree_checked'])
        self.assertFalse(manifest['operational_approval'])
        self.assertNotIn('Private marker', json.dumps(manifest))
        self.assertEqual('captured', manifest['artifacts'][0]['status'])
        self.assertEqual('markdown', manifest['artifacts'][0]['format'])

    def test_dirty_worktree_and_later_commit_do_not_change_selected_bytes(self):
        original = self.commit()
        self.commit({'docs/design.md': b'# changed\n'})
        (self.repo/'docs/design.md').unlink()
        (self.repo/'untracked.md').write_text('not captured')
        result = self.collect(original)
        self.assertEqual(b'# Private marker\n', result['contents']['DOC'])
        self.assertEqual(original, result['manifest']['commit_sha'])
        self.assertNotIn('untracked.md', [v['path'] for v in result['manifest']['inventory']])

    def test_bad_commit_is_rejected(self):
        commit = self.commit()
        for value in ('HEAD', commit[:12], commit.upper(), '0'*40):
            with self.subTest(value=value): self.rejected(value, 'COMMIT_INVALID')

    def test_index_path_must_be_safe_relative_json(self):
        commit = self.commit()
        for name in ('../artifacts.json', '/artifacts.json', './artifacts.json', 'a//artifacts.json', 'a/../artifacts.json',
                     'C:artifacts.json', 'a\\artifacts.json', '.git/artifacts.json', 'artifacts.md', 'a\x7f.json'):
            with self.subTest(path=name): self.rejected(commit, 'ARTIFACT_PATH_INVALID', path=name)

    def test_missing_index_is_error(self):
        self.rejected(self.commit(), 'ARTIFACT_INDEX_MISSING', path='missing.json')

    def test_duplicate_json_index_properties_rejected(self):
        self.rejected(self.commit(raw_index=b'{"kind":"x","kind":"y"}'), 'JSON_DUPLICATE_KEY')

    def test_non_utf8_index_rejected(self):
        self.rejected(self.commit(raw_index=b'\xff'), 'JSON_INVALID')

    def test_index_unknown_fields_and_wrong_scope_rejected(self):
        for change, code in [({'command':'run'}, 'ARTIFACT_INDEX_INVALID'), ({'tenant_id':'other'}, 'SCOPE_MISMATCH'),
                             ({'operational_approval':True}, 'ARTIFACT_INDEX_INVALID'), ({'kind':'other'}, 'ARTIFACT_INDEX_INVALID')]:
            with self.subTest(change=change): self.rejected(self.commit(index=dict(self.index, **change)), code)

    def test_artifact_wrong_scope_rejected(self):
        index = copy.deepcopy(self.index)
        index['artifacts'][0]['project_id'] = 'other'
        self.rejected(self.commit(index=index), 'SCOPE_MISMATCH')

    def test_duplicate_artifact_ids_rejected(self):
        index = copy.deepcopy(self.index)
        index['artifacts'].append(dict(self.artifact, relative_path='docs/other.md'))
        self.rejected(self.commit(index=index), 'ARTIFACT_ID_DUPLICATE')

    def test_duplicate_paths_rejected(self):
        index = copy.deepcopy(self.index)
        index['artifacts'].append(dict(self.artifact, id='OTHER'))
        self.rejected(self.commit(index=index), 'ARTIFACT_PATH_DUPLICATE')

    def test_requirement_ids_cannot_collide_with_artifact_ids(self):
        requirement = next(v for v in json.loads((Path(__file__).parent/'fixtures/project-compliance/contract-set.example.json').read_text()) if v['kind']=='requirement_spec')
        index = copy.deepcopy(self.index)
        index['requirements'] = [dict(requirement, id='DOC')]
        self.rejected(self.commit(index=index), 'ENTITY_ID_DUPLICATE')

    def test_duplicate_requirements_rejected(self):
        requirement = next(v for v in json.loads((Path(__file__).parent/'fixtures/project-compliance/contract-set.example.json').read_text()) if v['kind']=='requirement_spec')
        index = copy.deepcopy(self.index)
        index['requirements'] = [requirement, requirement]
        self.rejected(self.commit(index=index), 'REQUIREMENT_ID_DUPLICATE')

    def test_duplicate_trace_ids_rejected(self):
        trace = next(v for v in json.loads((Path(__file__).parent/'fixtures/project-compliance/contract-set.example.json').read_text()) if v['kind']=='trace_link')
        index = copy.deepcopy(self.index)
        index['traces'] = [trace, trace]
        self.rejected(self.commit(index=index), 'TRACE_ID_DUPLICATE')

    def test_missing_artifact_is_error(self):
        index = copy.deepcopy(self.index)
        index['artifacts'][0]['relative_path'] = 'missing.md'
        self.rejected(self.commit(index=index), 'ARTIFACT_MISSING')

    def test_changed_artifact_digest_is_error(self):
        self.rejected(self.commit({'docs/design.md':b'# changed\n'}), 'ARTIFACT_DIGEST_MISMATCH')

    def test_index_cannot_reference_itself(self):
        index = copy.deepcopy(self.index)
        index['artifacts'][0]['relative_path'] = 'artifacts.json'
        self.rejected(self.commit(index=index), 'ARTIFACT_INDEX_SELF_REFERENCE')

    def test_unsupported_format_is_explicit_and_preserves_private_bytes(self):
        raw = b'unsupported document'
        index = copy.deepcopy(self.index)
        index['artifacts'][0].update(relative_path='docs/input.hwpx', content_digest=hashlib.sha256(raw).hexdigest())
        result = self.collect(self.commit({'docs/input.hwpx':raw}, index=index))
        row = result['manifest']['artifacts'][0]
        self.assertEqual(('unsupported','unsupported'), (row['format'],row['status']))
        self.assertEqual(['ARTIFACT_FORMAT_UNSUPPORTED'], row['reason_codes'])
        self.assertEqual(raw, result['contents']['DOC'])

    def test_invalid_utf8_artifact_is_explicit(self):
        index = copy.deepcopy(self.index)
        index['artifacts'][0]['content_digest'] = hashlib.sha256(b'\xff').hexdigest()
        row = self.collect(self.commit({'docs/design.md':b'\xff'}, index=index))['manifest']['artifacts'][0]
        self.assertEqual('encoding_error', row['status'])
        self.assertEqual(['ARTIFACT_ENCODING_ERROR'], row['reason_codes'])

    def test_json_artifact_format(self):
        index = copy.deepcopy(self.index)
        index['artifacts'][0].update(relative_path='data.json',content_digest=hashlib.sha256(b'{}').hexdigest())
        row = self.collect(self.commit({'data.json':b'{}'}, index=index))['manifest']['artifacts'][0]
        self.assertEqual('json', row['format'])

    def test_limits_reject_values_and_excess_files_and_bytes(self):
        commit = self.commit()
        for kwargs in ({'max_files':True},{'max_blob':0},{'max_total':-1}):
            with self.subTest(kwargs=kwargs): self.rejected(commit,'SNAPSHOT_LIMIT_INVALID',**kwargs)
        for kwargs in ({'max_files':1},{'max_blob':10},{'max_total':10}):
            with self.subTest(kwargs=kwargs): self.rejected(commit,'SNAPSHOT_TOO_LARGE',**kwargs)

    def test_symlink_and_gitlink_rejected_even_if_unregistered(self):
        sha = self.commit()
        (self.repo/'link').symlink_to('docs/design.md')
        snapshot.run_git(self.repo,'add','link')
        snapshot.run_git(self.repo,'commit','-m','link')
        self.rejected(snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip(),'SOURCE_TYPE_UNSUPPORTED')
        snapshot.run_git(self.repo,'rm','link')
        snapshot.run_git(self.repo,'update-index','--add','--cacheinfo','160000,'+sha+',module')
        snapshot.run_git(self.repo,'commit','-m','gitlink')
        self.rejected(snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip(),'SOURCE_TYPE_UNSUPPORTED')

    def test_parse_json_rejects_duplicates_nonfinite_deep_and_oversized(self):
        parser = self.api().parse_json
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'\xff', b'['*40+b'0'+b']'*40, b' '*1048577):
            with self.subTest(raw=raw[:40]), self.assertRaises(self.api().ArtifactSnapshotError): parser(raw)
        self.assertEqual({'x':[1,False,'안녕']}, parser('{"x":[1,false,"안녕"]}'.encode()))

    def test_index_array_type_and_size_limits_are_rejected(self):
        for field in ('artifacts', 'requirements', 'traces'):
            index = copy.deepcopy(self.index)
            index[field] = {}
            with self.subTest(field=field): self.rejected(self.commit(index=index), 'ARTIFACT_INDEX_INVALID')
        for field, limit in [('artifacts',100),('requirements',1000),('traces',10000)]:
            index = copy.deepcopy(self.index)
            index[field] = [{}] * (limit + 1)
            with self.subTest(field=field): self.rejected(self.commit(index=index), 'ARTIFACT_INDEX_INVALID')

    def test_artifact_paths_are_safe_and_distinct_from_index(self):
        for name in ('C:input.md', '.git/secret.md', '.GIT/secret.md', 'docs/../secret.md', 'docs//secret.md'):
            index = copy.deepcopy(self.index)
            index['artifacts'][0]['relative_path'] = name
            with self.subTest(path=name): self.rejected(self.commit(index=index))

    def test_manifest_and_index_do_not_share_mutable_references(self):
        result = self.collect(self.commit())
        previous = contracts.digest(result['index'])
        result['manifest']['artifacts'][0]['artifact_ref']['id'] = 'CHANGED'
        self.assertEqual(previous, contracts.digest(result['index']))
        self.assertEqual('DOC', result['index']['artifacts'][0]['id'])

    def test_index_raw_and_canonical_digests_have_distinct_meanings(self):
        raw = json.dumps(self.index, indent=3).encode()
        result = self.collect(self.commit(raw_index=raw))
        self.assertNotEqual(result['manifest']['index_digest'], result['manifest']['index_canonical_digest'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['manifest']['index_digest'])
        self.assertEqual(contracts.digest(result['index']), result['manifest']['index_canonical_digest'])
