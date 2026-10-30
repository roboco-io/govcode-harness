"""Private signed document drafts and isolated copies, never approval of fulfillment.

Drafts follow document_assets/DOCUMENT_WRITING_POLICY.md. Structure checks do not
verify facts or execute aidocready. Review notes stay separate from final documents.
"""
import functools
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import unicodedata
import uuid

from .. import security, snapshot
from . import artifact_snapshot, contracts as c, delivery_trace

COMMON = {'schema_version', 'context', 'tenant_id', 'project_id', 'operational_approval'}
EVENT = {'kind', 'actor_id', 'event_id', 'created_at', 'not_before', 'expires_at'}
PROPOSAL_FIELDS = COMMON | EVENT | {'source_commit', 'index_path', 'index_digest', 'changes',
                                  'subject_digest', 'review_notes', 'aidocready_executed'}
APPROVAL_FIELDS = COMMON | EVENT | {'proposal_digest', 'decision', 'reason_ref'}
CHANGE_FIELDS = {'relative_path', 'old_digest', 'new_content', 'new_digest'}
FORBIDDEN = {'.git', '.github', '.gitlab', 'tests', 'test', 'ci', 'policies', 'rule_packs',
             'regulations', 'scripts', 'integrations', 'govcode_harness', 'packages', 'apps',
             'deploy', 'private', 'keys', 'secrets', 'node_modules', 'tools', 'tooling',
             '.claude', '.codex', '.agents', '.cursor', '.windsurf', '.cline', '.gemini',
             '.opencode', '.continue', '.aider', '.vscode', '.idea', '.husky', '.devcontainer',
             '.superlite', '.runtime', '.circleci', '.buildkite', 'commands', 'skills', 'hooks'}
CONTROL_FILES = {'agents.md', 'agents.local.md', 'agent.md', 'claude.md', 'claude.local.md',
                 'gemini.md', 'codex.md', 'skill.md', 'copilot-instructions.md', 'instructions.md',
                 'instruction.md', 'rules.md', 'policy.md', 'policies.md', 'prompt.md',
                 'system_prompt.md', 'developer_prompt.md', 'document_writing_policy.md',
                 'intent.md', 'product_direction.md', 'security.md', 'contributing.md',
                 'code_of_conduct.md', '.cursorrules', '.windsurfrules', '.clinerules'}
SHA = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')


class DocumentProposalError(ValueError):
    def __init__(self, code='DOCUMENT_PROPOSAL_INVALID'):
        self.code = code
        super().__init__(code)


def _require(condition, code='DOCUMENT_PROPOSAL_INVALID'):
    if not condition:
        raise DocumentProposalError(code)


def _guard(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except DocumentProposalError:
            raise
        except (security.SecurityError, snapshot.SnapshotError, c.ContractError,
                artifact_snapshot.ArtifactSnapshotError) as error:
            raise DocumentProposalError(error.code) from None
        except Exception:
            raise DocumentProposalError() from None
    return wrapped


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    _require(type(value) is str and SHA.fullmatch(value) is not None)
    return value


def _normalized_component(value):
    value = unicodedata.normalize('NFKC', value).casefold().rstrip(' .')
    return ''.join(ch for ch in value if unicodedata.category(ch) != 'Cf')


def _copy_path(value):
    artifact_snapshot._path(value)
    # Reject administrative-directory aliases on case/Unicode-insensitive filesystems.
    for part in value.split('/'):
        normalized = _normalized_component(part)
        _require(normalized != '.git', 'ARTIFACT_PATH_INVALID')
    return value


def _path(value):
    _copy_path(value)
    parts = [_normalized_component(part) for part in value.split('/')]
    _require(not any(part in FORBIDDEN for part in parts) and parts[-1] not in CONTROL_FILES,
             'DOCUMENT_PATH_FORBIDDEN')
    _require(not any(part.startswith('.env') for part in parts), 'DOCUMENT_PATH_FORBIDDEN')
    return value


def _common(tenant_id, project_id):
    security.identifier(tenant_id)
    security.identifier(project_id)
    return dict(schema_version='1', context=security.CONTEXT, tenant_id=tenant_id,
                project_id=project_id, operational_approval=False)


def _event(kind, trust, key_id, now, expires_at, tenant_id, project_id):
    _require(c.timestamp(now) < c.timestamp(expires_at), 'TIME_WINDOW_INVALID')
    return dict(_common(tenant_id, project_id), kind=kind,
                actor_id=trust['keys'][key_id]['actor_id'], event_id=uuid.uuid4().hex,
                created_at=now, not_before=now, expires_at=expires_at)


def _window(value, now):
    start, created, end, current = (c.timestamp(v) for v in
        (value['not_before'], value['created_at'], value['expires_at'], now))
    _require(start <= created <= current < end, 'AUTHORIZATION_EXPIRED')


def _header(value, fields, kind):
    _require(type(value) is dict and set(value) == fields)
    _require(value['kind'] == kind and value['schema_version'] == '1' and
             value['context'] == security.CONTEXT and value['operational_approval'] is False)
    for name in ('tenant_id', 'project_id', 'actor_id', 'event_id'):
        security.identifier(value[name])


def _markdown(content):
    _require(type(content) is str, 'DOCUMENT_FORMAT_INVALID')
    raw = content.encode('utf-8')
    _require(0 < len(raw) <= 256000, 'DOCUMENT_SIZE_LIMIT')
    _require(not any(ord(ch) < 32 and ch not in '\n\r\t' for ch in content), 'DOCUMENT_FORMAT_INVALID')
    valid, html = delivery_trace._markdown(content)
    _require(valid and not html, 'DOCUMENT_STRUCTURE_INVALID')
    lines = content.splitlines()
    previous = ''
    in_table = False
    fence = None
    for line in lines:
        token = re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$', line)
        if token:
            mark = token.group(1)
            if fence is None:
                fence = (mark[0], len(mark))
            elif mark[0] == fence[0] and len(mark) >= fence[1] and not token.group(2).strip():
                fence = None
            continue
        if fence is not None:
            continue
        stripped = line.strip()
        if stripped.startswith('|') and not in_table:
            _require(re.match(r'^표\s+\d+[.:．]\s*\S', previous) is not None, 'TABLE_CAPTION_REQUIRED')
        if re.search(r'!\[[^\]]*\]\(', line):
            _require(re.match(r'^그림\s+\d+[.:．]\s*\S', previous) is not None, 'FIGURE_CAPTION_REQUIRED')
        if stripped:
            in_table = stripped.startswith('|')
            previous = stripped
    return raw


def _clean_source(repo, commit):
    _worktree_root(repo)
    _require(snapshot.run_git(repo, 'rev-parse', '--verify', 'HEAD').decode().strip() == commit,
             'SOURCE_COMMIT_STALE')
    # status can invoke repository-defined clean/process filters. Enumerate only
    # configuration names, then explicitly disable every local filter before it.
    keys = snapshot.run_git(repo, 'config', '--local', '--includes', '--null', '--name-only', '--list')
    names = [key.decode('utf-8') for key in keys.split(b'\0') if key]
    filters = [key for key in names if key.casefold().startswith('filter.')]
    _require(len(filters) <= 64 and all(len(key) <= 512 and key.isascii() and
        re.fullmatch(r'filter\.[A-Za-z0-9_.-]+\.(clean|smudge|process|required)', key, re.IGNORECASE)
        for key in filters), 'SOURCE_CONFIG_INVALID')
    overrides = []
    for key in sorted(set(filters)):
        overrides.extend(('-c', key + ('=false' if key.casefold().endswith('.required') else '=')))
    _require(not snapshot.run_git(repo, *overrides, 'status', '--porcelain=v1',
                                  '--untracked-files=all', '--ignore-submodules=all'),
             'SOURCE_WORKTREE_DIRTY')


def _index(raw, tenant_id, project_id):
    return artifact_snapshot._index(artifact_snapshot.parse_json(raw), tenant_id, project_id)


def _validate_changes(captured, index_path, changes, tenant_id, project_id):
    """Compare authorized deltas to committed bytes, never client claims."""
    _path(index_path)
    _require(PurePosixPath(index_path).suffix.lower() == '.json', 'DOCUMENT_FORMAT_INVALID')
    blobs = captured['blobs']
    for path in blobs:
        _copy_path(path)
    _require(index_path in blobs, 'ARTIFACT_INDEX_MISSING')
    old = _index(blobs[index_path], tenant_id, project_id)
    _require(type(changes) is dict and 0 < len(changes) <= 100)
    security.canonical(changes)
    new_bytes = {}
    for path, text in changes.items():
        _path(path)
        _require(type(text) is str, 'DOCUMENT_FORMAT_INVALID')
        raw = text.encode('utf-8')
        _require(0 < len(raw) <= 256000, 'DOCUMENT_SIZE_LIMIT')
        _require(path not in blobs or raw != blobs[path], 'PROPOSAL_NO_CHANGE')
        new_bytes[path] = raw
    new = _index(new_bytes.get(index_path, blobs[index_path]), tenant_id, project_id)
    _require(new['requirements'] == old['requirements'], 'REQUIREMENTS_IMMUTABLE')
    _require(len(new['artifacts']) == len(old['artifacts']), 'ARTIFACT_SET_IMMUTABLE')
    old_arts = {a['id']: a for a in old['artifacts']}
    new_arts = {a['id']: a for a in new['artifacts']}
    _require(set(new_arts) == set(old_arts), 'ARTIFACT_SET_IMMUTABLE')
    allowed = {a['relative_path']: a for a in old['artifacts'] if a['artifact_kind'] == 'design'
               and PurePosixPath(a['relative_path']).suffix.lower() == '.md'}
    _require(set(changes) <= set(allowed) | {index_path}, 'DOCUMENT_PATH_FORBIDDEN')
    for name, before in old_arts.items():
        after = new_arts[name]
        _require({k: v for k, v in before.items() if k != 'content_digest'} ==
                 {k: v for k, v in after.items() if k != 'content_digest'}, 'ARTIFACT_IDENTITY_IMMUTABLE')
        path = before['relative_path']
        if path in blobs:
            _require(_sha(blobs[path]) == before['content_digest'], 'ARTIFACT_DIGEST_MISMATCH')
        else:
            _require(path in changes and path in allowed, 'ARTIFACT_MISSING')
        if path in changes:
            _markdown(changes[path])
            _require(_sha(new_bytes[path]) == after['content_digest'], 'ARTIFACT_DIGEST_MISMATCH')
        else:
            _require(after == before, 'ARTIFACT_DIGEST_MISMATCH')
    entities = {v['id']: v for v in new['requirements'] + new['artifacts']}
    refs = {name: dict(kind=v['kind'], id=name, version=v['version'], digest=c.digest(v))
            for name, v in entities.items()}
    original_links = {v['id']: v for v in old['traces']}
    revised_links = {v['id']: v for v in new['traces']}
    _require(set(original_links) <= set(revised_links), 'TRACE_REMOVAL_FORBIDDEN')
    for name, link in original_links.items():
        expected = json.loads(security.canonical(link))
        for field in ('from_ref', 'to_ref'):
            target = expected[field]['id']
            # Only content-derived reference digests may change for design edits.
            if target in old_arts and old_arts[target]['relative_path'] in changes:
                expected[field] = refs[target]
        _require(revised_links[name] == expected, 'TRACE_REWRITE_FORBIDDEN')
    relations = {('requirement_spec', 'design'): 'implements', ('design', 'test_plan'): 'verifies',
                 ('test_plan', 'test_result'): 'reports', ('test_result', 'review_record'): 'reviews'}
    edges = set()
    for link in new['traces']:
        a, b = link['from_ref']['id'], link['to_ref']['id']
        _require(a in refs and b in refs and link['from_ref'] == refs[a] and link['to_ref'] == refs[b],
                 'TRACE_REFERENCE_INVALID')
        ka, kb = (entities[v].get('artifact_kind', entities[v]['kind']) for v in (a, b))
        _require(relations.get((ka, kb)) == link['relation'] or
                 (link['relation'] == 'depends_on' and ka == kb), 'TRACE_RELATION_INVALID')
        edge = (a, b, link['relation'])
        _require(edge not in edges, 'TRACE_EDGE_DUPLICATE')
        edges.add(edge)
    # Old dependencies may remain, but no new dependency edge can weaken or redirect coverage.
    _require(all(link['id'] in original_links or link['relation'] != 'depends_on'
                 for link in new['traces']), 'DEPENDENCY_CHANGE_FORBIDDEN')
    _require(bool(set(changes) - {index_path}) or bool(set(revised_links) - set(original_links)),
             'PROPOSAL_NO_CHANGE')
    total = sum(len(raw) for name, raw in blobs.items() if name not in new_bytes) + sum(map(len, new_bytes.values()))
    _require(total <= 2000000 and len(set(blobs) | set(new_bytes)) <= 100, 'DOCUMENT_SIZE_LIMIT')
    return old, new, new_bytes


def _proposal(envelope, trust, now):
    value = envelope.get('payload') if type(envelope) is dict else None
    _header(value, PROPOSAL_FIELDS, 'project_document_proposal')
    value = security.verify(envelope, trust, 'author', value['tenant_id'], value['project_id'])
    _window(value, now)
    _require(type(value['source_commit']) is str and COMMIT.fullmatch(value['source_commit']) is not None)
    _path(value['index_path']); _digest(value['index_digest'])
    _require(type(value['changes']) is list and 0 < len(value['changes']) <= 100)
    paths = set()
    for change in value['changes']:
        _require(type(change) is dict and set(change) == CHANGE_FIELDS)
        path = _path(change['relative_path'])
        _require(path not in paths); paths.add(path)
        if change['old_digest'] is not None:
            _digest(change['old_digest'])
        _digest(change['new_digest'])
        _require(type(change['new_content']) is str and
                 _sha(change['new_content'].encode('utf-8')) == change['new_digest'])
        _require(0 < len(change['new_content'].encode('utf-8')) <= 256000, 'DOCUMENT_SIZE_LIMIT')
    _require(type(value['review_notes']) is list and value['aidocready_executed'] is False)
    _require(value['subject_digest'] == c.digest({k: v for k, v in value.items() if k != 'subject_digest'}),
             'PROPOSAL_SUBJECT_MISMATCH')
    return value


@_guard
def propose(repo, commit, index_path, changes, trust, now, *, tenant_id, project_id,
            private_path, key_id, expires_at):
    """Sign caller-provided private drafts without inventing facts or changing files."""
    captured = snapshot.capture(repo, commit)
    _clean_source(repo, commit)
    _validate_changes(captured, index_path, changes, tenant_id, project_id)
    value = _event('project_document_proposal', trust, key_id, now, expires_at, tenant_id, project_id)
    value.update(source_commit=commit, index_path=index_path, index_digest=_sha(captured['blobs'][index_path]),
        changes=[dict(relative_path=path, old_digest=_sha(captured['blobs'][path]) if path in captured['blobs'] else None,
                      new_content=text, new_digest=_sha(text.encode('utf-8'))) for path, text in sorted(changes.items())],
        review_notes=['원문 사실·수치·의미와 문서 내용을 대조해야 한다.',
                      '표·그림·문장·병합의 적절성은 독립 검토가 필요하다.',
                      '수정 후 새 commit에서 필수 검사를 다시 수행해야 한다.'], aidocready_executed=False)
    value['subject_digest'] = c.digest(value)
    envelope = security.sign(value, private_path, key_id)
    _proposal(envelope, trust, now)
    _clean_source(repo, commit)
    return envelope


@_guard
def approve(proposal, trust, now, *, private_path, key_id, expires_at, decision='approve',
            reason_ref='DOCUMENT-REVIEW-REFERENCE'):
    value = _proposal(proposal, trust, now)
    _require(decision in ('approve', 'reject'), 'APPROVAL_DECISION_INVALID')
    security.identifier(reason_ref)
    approval = _event('project_document_proposal_approval', trust, key_id, now, expires_at,
                      value['tenant_id'], value['project_id'])
    _require(approval['actor_id'] != value['actor_id'], 'SELF_APPROVAL')
    _require(c.timestamp(expires_at) <= c.timestamp(value['expires_at']), 'APPROVAL_WINDOW_INVALID')
    approval.update(proposal_digest=c.digest(proposal), decision=decision, reason_ref=reason_ref)
    envelope = security.sign(approval, private_path, key_id)
    security.verify(envelope, trust, 'approver', value['tenant_id'], value['project_id'])
    return envelope


def _inside(path, parent):
    if path.is_relative_to(parent):
        return True
    # Also reject casing/Unicode aliases on case-insensitive reference hosts.
    child = tuple(_normalized_component(part) for part in path.parts)
    ancestor = tuple(_normalized_component(part) for part in parent.parts)
    return child[:len(ancestor)] == ancestor


def _worktree_root(repo):
    source = security.safe_path(repo).resolve(strict=True)
    raw = snapshot.run_git(source, 'rev-parse', '--show-toplevel').decode('utf-8').strip()
    root = security.safe_path(raw).resolve(strict=True)
    _require(_inside(source, root), 'SOURCE_WORKTREE_MISMATCH')
    return root


def _output_paths(repo, output):
    # Check lexical ancestry for symlinks before resolving '..' and aliases.
    source = security.safe_path(repo).resolve(strict=True)
    out = security.safe_path(output).resolve(strict=False)
    _require(not out.exists(), 'OUTPUT_EXISTS')
    _require(not any(_normalized_component(part) == '.git' for part in out.parts),
             'OUTPUT_INSIDE_SOURCE')
    roots = [source, _worktree_root(source)]
    for option in ('--absolute-git-dir', '--git-common-dir'):
        raw = snapshot.run_git(source, 'rev-parse', option).decode('utf-8').strip()
        path = Path(raw)
        if not path.is_absolute():
            path = source / path
        roots.append(security.safe_path(path).resolve(strict=True))
    _require(not any(_inside(out, root) for root in roots), 'OUTPUT_INSIDE_SOURCE')
    return source, out


def _modes(repo, commit, captured):
    modes = {}
    for entry in snapshot.run_git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0')[:-1]:
        metadata, name = entry.split(b'\t', 1)
        mode, kind, _ = metadata.decode('ascii').split()
        _require(kind == 'blob' and mode in ('100644', '100755'))
        modes[name.decode('utf-8')] = mode
    _require(set(modes) == set(captured['blobs']))
    return modes


def _stage_blob(repo, path, raw, mode):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_bytes(raw)
    target.chmod(0o700 if mode == '100755' else 0o600)
    oid = snapshot.run_git(repo, 'hash-object', '-w', '--no-filters', '--', path).decode().strip()
    _require(snapshot.run_git(repo, 'cat-file', 'blob', oid) == raw, 'CANDIDATE_BYTES_CHANGED')
    snapshot.run_git(repo, 'update-index', '--add', '--cacheinfo', mode, oid, path)


@_guard
def apply(repo, proposal, approval, trust, now, *, output):
    """Create an isolated copy/new commit; existing source and output are never overwritten."""
    value = _proposal(proposal, trust, now)
    claims = approval.get('payload') if type(approval) is dict else None
    _header(claims, APPROVAL_FIELDS, 'project_document_proposal_approval')
    claims = security.verify(approval, trust, 'approver', value['tenant_id'], value['project_id'])
    _window(claims, now)
    _require(claims['actor_id'] != value['actor_id'], 'SELF_APPROVAL')
    _require(claims['proposal_digest'] == c.digest(proposal), 'APPROVAL_SUBJECT_MISMATCH')
    _require(claims['decision'] == 'approve', 'PROPOSAL_NOT_APPROVED')
    security.identifier(claims['reason_ref'])
    _require(c.timestamp(claims['created_at']) >= c.timestamp(value['created_at']) and
             c.timestamp(claims['expires_at']) <= c.timestamp(value['expires_at']), 'APPROVAL_WINDOW_INVALID')
    source, out = _output_paths(repo, output)
    commit = value['source_commit']
    captured = snapshot.capture(source, commit)
    _clean_source(source, commit)
    _require(_sha(captured['blobs'][value['index_path']]) == value['index_digest'], 'SOURCE_INDEX_CHANGED')
    changes = {row['relative_path']: row['new_content'] for row in value['changes']}
    for row in value['changes']:
        old = captured['blobs'].get(row['relative_path'])
        _require((_sha(old) if old is not None else None) == row['old_digest'], 'SOURCE_CONTENT_CHANGED')
    _, _, new_bytes = _validate_changes(captured, value['index_path'], changes, value['tenant_id'], value['project_id'])
    modes = _modes(source, commit, captured)
    temporary = Path(tempfile.mkdtemp(prefix='.document-candidate-', dir=out.parent))
    reserved = False
    try:
        snapshot.run_git(temporary, 'init', '-b', 'main')
        for path, raw in sorted(captured['blobs'].items()):
            _stage_blob(temporary, path, raw, modes[path])
        base_tree = snapshot.run_git(temporary, 'write-tree').decode().strip()
        expected_tree = snapshot.run_git(source, 'rev-parse', commit + '^{tree}').decode().strip()
        _require(base_tree == expected_tree, 'SOURCE_TREE_MISMATCH')
        # Import only this exact commit. Its parents are an explicit shallow
        # boundary; no fetch, alternates, external history or source config.
        raw_commit = snapshot.run_git(source, 'cat-file', 'commit', commit)
        _require(len(raw_commit) <= security.MAX_BYTES, 'SOURCE_COMMIT_TOO_LARGE')
        commit_file = temporary / '.git' / 'captured-source-commit'
        commit_file.write_bytes(raw_commit)
        commit_file.chmod(0o600)
        base_commit = snapshot.run_git(temporary, 'hash-object', '-t', 'commit', '-w',
                                       '--no-filters', '--', '.git/captured-source-commit').decode().strip()
        commit_file.unlink()
        _require(base_commit == commit, 'SOURCE_COMMIT_MISMATCH')
        shallow = temporary / '.git' / 'shallow'
        shallow.write_text(commit + '\n', encoding='ascii')
        shallow.chmod(0o600)
        for path, raw in sorted(new_bytes.items()):
            _stage_blob(temporary, path, raw, modes.get(path, '100644'))
        tree = snapshot.run_git(temporary, 'write-tree').decode().strip()
        changed = snapshot.run_git(temporary, 'diff-tree', '--no-commit-id', '--name-only', '-r', '-z', base_tree, tree)
        changed_paths = sorted(path.decode('utf-8') for path in changed.split(b'\0') if path)
        _require(changed_paths == sorted(changes), 'CANDIDATE_SCOPE_CHANGED')
        new_commit = snapshot.run_git(temporary, 'commit-tree', tree, '-p', base_commit,
                                      '-m', 'Apply independently approved document proposal').decode().strip()
        snapshot.run_git(temporary, 'update-ref', 'refs/heads/main', new_commit)
        artifact_snapshot.collect(temporary, new_commit, value['index_path'],
                                  tenant_id=value['tenant_id'], project_id=value['project_id'])
        _require(not snapshot.run_git(temporary, 'status', '--porcelain=v1', '--untracked-files=all'),
                 'CANDIDATE_WORKTREE_DIRTY')
        _clean_source(source, commit)
        out.mkdir(mode=0o700)
        reserved = True
        for path in temporary.iterdir():
            path.rename(out / path.name)
        return dict(kind='project_document_application', context=security.CONTEXT,
            tenant_id=value['tenant_id'], project_id=value['project_id'], operational_approval=False,
            source_commit=commit, new_commit=new_commit, proposal_digest=c.digest(proposal),
            approval_digest=c.digest(approval), changed_paths=changed_paths,
            requires_reinspection=True, requirements_evaluated=False, aidocready_executed=False)
    except Exception:
        if reserved:
            shutil.rmtree(out)
        raise
    finally:
        shutil.rmtree(temporary)
