"""Create an exclusive project-local reference environment from hash-locked dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def safe(path):
    path=Path(os.path.abspath(os.fspath(path)))
    for part in [path,*path.parents]:
        if part.is_symlink():raise SystemExit('SYMLINK_PATH')
    return path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',required=True)
    parser.add_argument('--uv',default='uv')
    parser.add_argument('--environment',default='.runtime/reference-venv')
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args()
    python=shutil.which(args.python) or args.python
    uv=shutil.which(args.uv) or args.uv
    version=subprocess.run([python,'-I','-c','import sys; print(sys.version_info.major, sys.version_info.minor)'],check=True,capture_output=True,text=True,timeout=10)
    if tuple(map(int,version.stdout.strip().split()))<(3,12):raise SystemExit('PYTHON_3_12_REQUIRED')
    environment=safe(ROOT/args.environment)
    if ROOT/'.runtime' not in environment.parents:raise SystemExit('PROJECT_RUNTIME_PATH_REQUIRED')
    if environment.exists():raise SystemExit('ENVIRONMENT_EXISTS_USE_EXISTING_OR_NEW_PATH')
    cache=safe(ROOT/'.runtime/reference-uv-cache');cache.mkdir(parents=True,exist_ok=True)
    lock=ROOT/'requirements-reference.lock'
    env={**os.environ,'UV_CACHE_DIR':str(cache),'UV_PYTHON_DOWNLOADS':'never'}
    flags=['--offline'] if args.offline else []
    subprocess.run([uv,*flags,'venv',str(environment),'--python',python],cwd=ROOT,env=env,check=True,timeout=60)
    interpreter=environment/'bin/python'
    subprocess.run([uv,*flags,'pip','sync','--python',str(interpreter),'--require-hashes',str(lock),str(ROOT/'requirements-reference-build.lock')],cwd=ROOT,env=env,check=True,timeout=180)
    subprocess.run([uv,*flags,'pip','install','--python',str(interpreter),'--no-deps','--no-build-isolation',str(ROOT)],cwd=ROOT,env=env,check=True,timeout=120)
    proof=subprocess.run([str(interpreter),'-I','-B','-c','import json,cryptography,jsonschema,govcode_harness; from govcode_harness import runtime; assert runtime.PROFILE_PATH.is_file(); from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; k=Ed25519PrivateKey.generate(); k.public_key().verify(k.sign(b"reference-check"),b"reference-check"); print(json.dumps({"cryptography":cryptography.__version__,"signature_roundtrip":True,"harness":govcode_harness.__version__}))'],cwd=ROOT,capture_output=True,text=True,check=True,timeout=20)
    print(json.dumps({'environment':str(environment),'lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),'proof':json.loads(proof.stdout),'operational_approval':False}))

if __name__=='__main__':main()
