"""Collect immutable Git objects without consulting or executing working files.

Only ``sources`` contains code and must remain private to the analysis process.
``manifest`` is the explicitly permitted, source-free evidence representation.
"""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import selectors
import signal
import subprocess
import time

FORMAT = 'govcode-snapshot-v1'
MAX_GIT_OUTPUT = 4_000_000
GIT_TIMEOUT = 20
DOC_SUFFIXES = {'.md', '.txt', '.json', '.toml', '.yaml', '.yml', '.ini', '.cfg', '.lock'}


class SnapshotError(Exception):
    """A public classification; never carries Git diagnostics or source text."""
    def __init__(self, code='GIT_FAILURE'):
        self.code = code
        super().__init__(code)


def run_git(repo, *args):
    """Run argv-only Git with bounded pipes and an owned process group.

    Callers choose trusted command names. Collection below only reads objects;
    runtime also uses this boundary to create its authored synthetic fixtures.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0',
               GIT_NO_REPLACE_OBJECTS='1', GIT_GRAFT_FILE=os.devnull,
               GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', LC_ALL='C')
    command = ['git', '--no-optional-locks', '--no-replace-objects',
               '-c', 'core.hooksPath=' + os.devnull, '-c', 'core.fsmonitor=false',
               '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false',
               '-c', 'protocol.allow=never', '-c', 'core.commitGraph=false',
               '-c', 'user.name=GovCode synthetic demo',
               '-c', 'user.email=demo@example.invalid', *args]
    proc = None
    try:
        proc = subprocess.Popen(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        deadline = time.monotonic() + GIT_TIMEOUT
        output = bytearray()
        count = 0
        with selectors.DefaultSelector() as selector:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SnapshotError('GIT_FAILURE')
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(chunk)
                    if count > MAX_GIT_OUTPUT:
                        raise SnapshotError('GIT_FAILURE')
                    if key.fileobj is proc.stdout:
                        output.extend(chunk)
            if proc.wait(timeout=max(0.001, deadline - time.monotonic())):
                raise SnapshotError('GIT_FAILURE')
        return bytes(output)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SnapshotError('GIT_FAILURE') from None
    finally:
        if proc is not None:
            # The leader may already have exited while a child retains a pipe.
            # Always terminate the owned group, including on successful exit.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
            proc.wait()


def validate_commit(repo, commit, *, git=None):
    if not isinstance(commit, str) or re.fullmatch(r'[a-f0-9]{40}', commit) is None:
        raise SnapshotError('COMMIT_INVALID')
    try:
        kind = (git or run_git)(repo, 'cat-file', '-t', commit)
    except Exception as exc:
        # Runtime may adapt this boundary into its own public error type.
        if getattr(exc, 'code', None) == 'GIT_FAILURE':
            raise SnapshotError('COMMIT_INVALID') from None
        raise
    if kind != b'commit\n':
        raise SnapshotError('COMMIT_INVALID')
    return commit


def collect(repo, commit, *, git=None, max_files=100, max_blob=256_000, max_total=2_000_000):
    """Read all tracked regular files at one exact commit, without exclusions."""
    if any(type(value) is not int or value <= 0 for value in (max_files, max_blob, max_total)):
        raise SnapshotError('SNAPSHOT_LIMIT_INVALID')
    git = git or run_git
    commit = validate_commit(repo, commit, git=git)
    listing = git(repo, 'ls-tree', '-rz', '--full-tree', commit)
    if len(listing) > MAX_GIT_OUTPUT or (listing and not listing.endswith(b'\0')):
        raise SnapshotError('SNAPSHOT_TOO_LARGE')
    entries = listing.split(b'\0')[:-1] if listing else []
    if len(entries) > max_files:
        raise SnapshotError('SNAPSHOT_TOO_LARGE')
    inventory, files, sources, issues, seen = [], [], [], [], set()
    total = 0
    for entry in entries:
        try:
            metadata, encoded_name = entry.split(b'\t', 1)
            mode, kind, oid = metadata.decode('ascii').split()
            name = encoded_name.decode('utf-8')
        except (ValueError, UnicodeError):
            raise SnapshotError('SOURCE_PATH_INVALID') from None
        if (not name or name.startswith('/') or '\\' in name or
                any(p in {'', '.', '..'} for p in name.split('/')) or
                any(ord(c) < 32 or ord(c) == 127 for c in name) or name in seen):
            raise SnapshotError('SOURCE_PATH_INVALID')
        seen.add(name)
        if mode not in {'100644', '100755'} or kind != 'blob':
            raise SnapshotError('SOURCE_TYPE_UNSUPPORTED')
        if re.fullmatch(r'[a-f0-9]{40}', oid) is None:
            raise SnapshotError('SOURCE_OBJECT_INVALID')
        try:
            size = int(git(repo, 'cat-file', '-s', oid))
        except (ValueError, TypeError):
            raise SnapshotError('SOURCE_OBJECT_INVALID') from None
        if size < 0 or size > max_blob or total + size > max_total:
            raise SnapshotError('SNAPSHOT_TOO_LARGE')
        raw = git(repo, 'cat-file', 'blob', oid)
        if len(raw) != size:
            raise SnapshotError('SNAPSHOT_TOO_LARGE')
        total += size
        sha = hashlib.sha256(raw).hexdigest()
        inventory.append({'path': name, 'sha256': sha})
        suffix = PurePosixPath(name).suffix.lower()
        if suffix == '.py':
            try:
                source = raw.decode('utf-8')
                sources.append((name, source))
                classification, reason = 'python_source', 'PYTHON_SOURCE'
            except UnicodeError:
                classification, reason = 'encoding_error', 'SOURCE_ENCODING_ERROR'
                issues.append({'path': name, 'line': 1, 'code': reason})
        elif suffix in DOC_SUFFIXES or name in {'.gitignore', 'LICENSE', 'Makefile'}:
            classification, reason = 'supporting_file', 'SUPPORTING_FILE_NOT_ANALYZED'
        else:
            classification, reason = 'unsupported_file', 'UNSUPPORTED_FILE_TYPE'
            issues.append({'path': name, 'line': 1, 'code': reason})
        files.append({'path': name, 'sha256': sha, 'size_bytes': size,
                      'classification': classification, 'reason_code': reason})
    if not sources:
        issues.append({'path': '.', 'line': 1, 'code': 'NO_SUPPORTED_SOURCE'})
    return {'format': FORMAT, 'commit_sha': commit,
            'inventory': sorted(inventory, key=lambda f: f['path']),
            'files': sorted(files, key=lambda f: f['path']),
            'sources': sorted(sources),
            'issues': sorted(issues, key=lambda f: (f['path'], f['line'], f['code'])),
            'total_bytes': total}


def manifest(collected):
    """Return a detached JSON manifest that cannot contain code or source values."""
    inventory = json.dumps(collected['inventory'], ensure_ascii=False, sort_keys=True,
                           separators=(',', ':'), allow_nan=False).encode('utf-8')
    value = {'format': FORMAT, 'commit_sha': collected['commit_sha'],
             'scope': 'all_tracked_files_at_commit',
             'inventory_digest': hashlib.sha256(inventory).hexdigest(),
             'files': collected['files'], 'total_bytes': collected['total_bytes'],
             'supported_files': len(collected['sources']), 'issues': collected['issues']}
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
