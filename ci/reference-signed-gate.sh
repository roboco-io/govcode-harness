#!/bin/sh
# Administrator-owned reference wrapper. All inputs come from trusted CI config.
set -eu
case "${GOVCODE_PYTHON:-}" in /*) ;; *) printf '%s\n' '{"outcome":"error","code":"TRUSTED_ABSOLUTE_INTERPRETER_REQUIRED","exit_code":4}'; exit 4 ;; esac
: "${GOVCODE_PYTHON:?trusted installed Python required}"
: "${GOVCODE_REPO:?absolute checkout required}"
: "${GOVCODE_EXPECTED_COMMIT:?trusted CI SHA required}"
: "${GOVCODE_ARTIFACTS:?new absolute output outside checkout required}"
: "${GOVCODE_BUNDLE:?signed policy bundle required}"
: "${GOVCODE_TRUST:?administrator public trust required}"
: "${GOVCODE_TENANT:?tenant required}"
: "${GOVCODE_PROJECT:?project required}"
: "${GOVCODE_MIN_SEQUENCE:?trusted policy sequence floor required}"
export GOVCODE_REPO GOVCODE_EXPECTED_COMMIT GOVCODE_ARTIFACTS GOVCODE_MIN_SEQUENCE GOVCODE_BUNDLE GOVCODE_TRUST GOVCODE_TENANT GOVCODE_PROJECT
if ! "$GOVCODE_PYTHON" -I - <<'PYVALIDATE'
import os,re
from pathlib import Path
try:
    repo=Path(os.environ['GOVCODE_REPO']);out=Path(os.environ['GOVCODE_ARTIFACTS'])
    assert repo.is_absolute() and out.is_absolute()
    assert re.fullmatch('[a-f0-9]{40}',os.environ['GOVCODE_EXPECTED_COMMIT'])
    assert os.environ['GOVCODE_MIN_SEQUENCE'].isdigit() and int(os.environ['GOVCODE_MIN_SEQUENCE'])>=1
    assert repo.resolve()!=out.resolve() and repo.resolve() not in out.resolve().parents
    from govcode_harness.security import safe_path
    safe_path(repo);safe_path(out)
    for key in ['GOVCODE_BUNDLE','GOVCODE_TRUST','GOVCODE_REVOCATIONS','GOVCODE_EXCEPTIONS','GOVCODE_EXISTING_EVIDENCE']:
        if not os.environ.get(key):continue
        path=Path(os.environ[key])
        assert path.is_absolute() and '..' not in path.parts
        assert path.is_dir() if key=='GOVCODE_EXISTING_EVIDENCE' else path.is_file()
        safe_path(path)
        assert path.resolve()!=repo.resolve() and repo.resolve() not in path.resolve().parents
    assert not out.exists()
    out.mkdir(parents=True,mode=0o700,exist_ok=False)
except Exception:raise SystemExit(4)
PYVALIDATE
then
  printf '%s\n' '{"outcome":"error","code":"SIGNED_PIPELINE_INPUT_INVALID","exit_code":4}'
  exit 4
fi
GOVCODE_SCAN_STATUS=0
if [ -n "${GOVCODE_EXISTING_EVIDENCE:-}" ];then
  GOVCODE_SELECTED_EVIDENCE=$GOVCODE_EXISTING_EVIDENCE
  printf '%s\n' '{"scan_performed":false,"existing_evidence_requested":true}' > "$GOVCODE_ARTIFACTS/scan.json"
else
  GOVCODE_SELECTED_EVIDENCE=$GOVCODE_ARTIFACTS/evidence
  "$GOVCODE_PYTHON" -I -m govcode_harness scan --repo "$GOVCODE_REPO" --commit "$GOVCODE_EXPECTED_COMMIT" --output "$GOVCODE_SELECTED_EVIDENCE" --local-demo --tenant-id "$GOVCODE_TENANT" --project-id "$GOVCODE_PROJECT" > "$GOVCODE_ARTIFACTS/scan.json" 2> "$GOVCODE_ARTIFACTS/scan-error.json" || GOVCODE_SCAN_STATUS=$?
fi
set --
if [ -n "${GOVCODE_REVOCATIONS:-}" ];then set -- "$@" --revocations "$GOVCODE_REVOCATIONS";fi
if [ -n "${GOVCODE_EXCEPTIONS:-}" ];then set -- "$@" --exceptions "$GOVCODE_EXCEPTIONS";fi
GOVCODE_GATE_STATUS=0
"$GOVCODE_PYTHON" -I -m govcode_harness gate --repo "$GOVCODE_REPO" --expected-commit "$GOVCODE_EXPECTED_COMMIT" --evidence "$GOVCODE_SELECTED_EVIDENCE" --local-demo --bundle "$GOVCODE_BUNDLE" --trust "$GOVCODE_TRUST" --tenant-id "$GOVCODE_TENANT" --project-id "$GOVCODE_PROJECT" --min-sequence "$GOVCODE_MIN_SEQUENCE" "$@" > "$GOVCODE_ARTIFACTS/gate.json" || GOVCODE_GATE_STATUS=$?
cat "$GOVCODE_ARTIFACTS/gate.json"
if [ "$GOVCODE_GATE_STATUS" -ne 0 ];then exit "$GOVCODE_GATE_STATUS";fi
case "$GOVCODE_SCAN_STATUS" in 0|2)exit 0;;*)exit 4;;esac
