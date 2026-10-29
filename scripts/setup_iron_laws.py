#!/usr/bin/env python3
"""Install the approved optional PoC in its project-local environment only.

Usage: python3 scripts/setup_iron_laws.py --python /absolute/python3.12 --uv /absolute/uv
Network is used only here. Dependency resolution is frozen in the checked-in locks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid
import sys
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
PIN=json.loads((ROOT/'integrations/iron-laws/PIN.json').read_text())
RUNTIME=ROOT/'.runtime/iron-laws-poc'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',required=True)
    parser.add_argument('--uv',required=True)
    args=parser.parse_args()
    for path in [RUNTIME, *RUNTIME.parents]:
        if path.is_symlink(): raise RuntimeError('INSTALL_PATH_SYMLINK')
    RUNTIME.mkdir(parents=True,exist_ok=True,mode=0o700)
    installation_id=uuid.uuid4().hex
    target=RUNTIME/('env-'+installation_id)
    if target.exists() or target.is_symlink(): raise RuntimeError('INSTALLATION_ALREADY_EXISTS')
    build=RUNTIME/('build-'+installation_id)
    build.mkdir(mode=0o700)
    environment=dict(os.environ,UV_CACHE_DIR=str(RUNTIME/'uv-cache'),UV_PYTHON_DOWNLOADS='never')
    def uv(*arguments):
        subprocess.run([str(Path(args.uv).resolve()),*arguments],cwd=ROOT,env=environment,check=True,timeout=180)
    archive=RUNTIME/'source.tar.gz'
    if archive.is_symlink(): raise RuntimeError('SOURCE_ARCHIVE_UNSAFE')
    if not archive.exists():
        with urllib.request.urlopen(PIN['archive_url'],timeout=30) as response:
            data=response.read(20_000_001)
        if len(data)>20_000_000: raise RuntimeError('SOURCE_ARCHIVE_TOO_LARGE')
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=PIN['archive_sha256']:
        raise RuntimeError('SOURCE_ARCHIVE_DIGEST_MISMATCH')
    source=build/('iron-laws-'+PIN['source_commit'])
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            if not (member.isfile() or member.isdir()) or member.name.startswith('/') or '..' in Path(member.name).parts:
                raise RuntimeError('SOURCE_ARCHIVE_UNSAFE')
        bundle.extractall(build,filter='data')
    # Every setup gets a fresh path; an existing environment is never mutated.
    uv('venv','--python',str(Path(args.python).resolve()),str(target))
    python=str(target/'bin/python')
    uv('pip','sync','integrations/iron-laws/requirements.lock','integrations/iron-laws/build.lock','--python',python,'--require-hashes')
    uv('pip','install','--python',python,'--no-deps','--no-build-isolation',str(source))
    sys.path.insert(0,str(ROOT))
    from govcode_harness.iron_laws_adapter import canonical,measure_identity
    identity=measure_identity(target)
    with (target/'identity.json').open('xb') as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(canonical(identity))
    pointer=RUNTIME/('active-'+installation_id+'.json')
    with pointer.open('xb') as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(canonical({'environment':target.name}))
    os.replace(pointer,RUNTIME/'active.json')
    print('Installed pinned Iron Laws in the project-local environment.')


if __name__=='__main__': main()
