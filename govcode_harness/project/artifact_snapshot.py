"""Commit-pinned artifact bytes, separate from code classification and approval.

Only ``contents`` contains registered document bodies. It is private input to
inspection. ``manifest`` contains hashes and inventory, never document bodies.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re

from .. import security, snapshot
from . import contracts

FORMAT = 'govcode-project-artifact-snapshot-v1'
INDEX_FIELDS = {'kind', 'schema_version', 'context', 'operational_approval', 'tenant_id',
                'project_id', 'artifacts', 'requirements', 'traces'}


class ArtifactSnapshotError(Exception):
    """Stable public code without repository diagnostics or document excerpts."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise ArtifactSnapshotError(code)


def parse_json(raw):
    """Parse the exact captured UTF-8 bytes with duplicate and size safeguards."""
    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value, 'JSON_DUPLICATE_KEY')
            value[key] = item
        return value
    try:
        _require(type(raw) is bytes, 'JSON_INVALID')
        _require(len(raw) <= security.MAX_BYTES, 'JSON_LIMIT')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ArtifactSnapshotError('JSON_INVALID')))
        security.canonical(value)
        return value
    except ArtifactSnapshotError:
        raise
    except security.SecurityError as error:
        raise ArtifactSnapshotError(error.code) from None
    except Exception:
        raise ArtifactSnapshotError('JSON_INVALID') from None


def _path(value):
    _require(type(value) is str and bool(value) and len(value) <= 1024, 'ARTIFACT_PATH_INVALID')
    _require(not value.startswith('/') and '\\' not in value and re.match(r'^[A-Za-z]:', value) is None,
             'ARTIFACT_PATH_INVALID')
    _require(not any(ord(c) < 32 or ord(c) == 127 for c in value), 'ARTIFACT_PATH_INVALID')
    _require(not any(part in ('', '.', '..') or part.casefold() == '.git' for part in value.split('/')),
             'ARTIFACT_PATH_INVALID')
    return value


def _index(value, tenant_id, project_id):
    _require(type(value) is dict and set(value) == INDEX_FIELDS, 'ARTIFACT_INDEX_INVALID')
    _require(value['kind'] == 'project_artifact_index' and value['schema_version'] == '1' and
             value['context'] == security.CONTEXT and value['operational_approval'] is False,
             'ARTIFACT_INDEX_INVALID')
    _require((value['tenant_id'], value['project_id']) == (tenant_id, project_id), 'SCOPE_MISMATCH')
    for field, limit in [('artifacts', 100), ('requirements', 1000), ('traces', 10000)]:
        _require(type(value[field]) is list and len(value[field]) <= limit, 'ARTIFACT_INDEX_INVALID')
    ids, paths = set(), set()
    for field, kind, duplicate in [('artifacts', 'artifact_ref', 'ARTIFACT_ID_DUPLICATE'),
                                    ('requirements', 'requirement_spec', 'REQUIREMENT_ID_DUPLICATE'),
                                    ('traces', 'trace_link', 'TRACE_ID_DUPLICATE')]:
        local_ids = set()
        for position, item in enumerate(value[field]):
            item = contracts.validate(item)
            _require(item['kind'] == kind, 'ARTIFACT_INDEX_INVALID')
            _require((item['tenant_id'], item['project_id']) == (tenant_id, project_id), 'SCOPE_MISMATCH')
            _require(item['id'] not in local_ids, duplicate)
            local_ids.add(item['id'])
            if field != 'traces':
                _require(item['id'] not in ids, 'ENTITY_ID_DUPLICATE')
                ids.add(item['id'])
            if field == 'artifacts':
                name = _path(item['relative_path'])
                _require(name not in paths, 'ARTIFACT_PATH_DUPLICATE')
                paths.add(name)
            value[field][position] = item
    return value


def collect(repo, commit, index_path, *, tenant_id, project_id, git=None,
            max_files=100, max_blob=256000, max_total=2000000):
    """Read a declared document set from one immutable Git capture.

    This does not verify rule-pack authority, applicability, test execution or
    approval. Worktree files, Markdown links and embedded commands are not used.
    """
    try:
        security.identifier(tenant_id)
        security.identifier(project_id)
        index_path = _path(index_path)
        _require(PurePosixPath(index_path).suffix.lower() == '.json', 'ARTIFACT_PATH_INVALID')
        captured = snapshot.capture(repo, commit, git=git, max_files=max_files,
                                    max_blob=max_blob, max_total=max_total)
        _require(index_path in captured['blobs'], 'ARTIFACT_INDEX_MISSING')
        raw_index = captured['blobs'][index_path]
        index = _index(parse_json(raw_index), tenant_id, project_id)
        rows, contents = [], {}
        for artifact in index['artifacts']:
            name = artifact['relative_path']
            _require(name != index_path, 'ARTIFACT_INDEX_SELF_REFERENCE')
            _require(name in captured['blobs'], 'ARTIFACT_MISSING')
            raw = captured['blobs'][name]
            _require(hashlib.sha256(raw).hexdigest() == artifact['content_digest'], 'ARTIFACT_DIGEST_MISMATCH')
            suffix = PurePosixPath(name).suffix.lower()
            form = {'.md': 'markdown', '.json': 'json'}.get(suffix, 'unsupported')
            status, reasons = 'captured', []
            if form == 'unsupported':
                status, reasons = 'unsupported', ['ARTIFACT_FORMAT_UNSUPPORTED']
            else:
                try:
                    raw.decode('utf-8')
                except UnicodeError:
                    status, reasons = 'encoding_error', ['ARTIFACT_ENCODING_ERROR']
            rows.append(dict(artifact_ref=artifact, format=form, status=status, reason_codes=reasons))
            contents[artifact['id']] = raw
        manifest = dict(format=FORMAT, tenant_id=tenant_id, project_id=project_id,
                        commit_sha=captured['commit_sha'], index_path=index_path,
                        index_digest=hashlib.sha256(raw_index).hexdigest(),
                        index_canonical_digest=contracts.digest(index),
                        inventory=captured['inventory'], artifacts=rows,
                        total_bytes=captured['total_bytes'], worktree_checked=False,
                        operational_approval=False)
        # Roundtrip prevents shared mutable aliases between manifest and index.
        manifest = json.loads(security.canonical(manifest))
        return dict(manifest=manifest, index=index, contents=contents)
    except ArtifactSnapshotError:
        raise
    except (security.SecurityError, snapshot.SnapshotError, contracts.ContractError) as error:
        raise ArtifactSnapshotError(error.code) from None
    except Exception:
        raise ArtifactSnapshotError('ARTIFACT_SNAPSHOT_INVALID') from None
