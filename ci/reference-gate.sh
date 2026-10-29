#!/bin/sh
# Run this administrator-owned wrapper from a trusted location outside checkout.
# GOVCODE_PYTHON must name a trusted interpreter with the harness preinstalled.
# Do not install dependencies or execute scripts from the inspected repository.
# Caller must supply the expected full SHA from trusted CI metadata, never a file.
set -eu
: "${GOVCODE_PYTHON:?trusted Python required}"
: "${GOVCODE_REPO:?absolute checkout root required}"
: "${GOVCODE_EXPECTED_COMMIT:?trusted CI SHA required}"
: "${GOVCODE_ARTIFACTS:?new absolute artifact directory outside checkout required}"
GOVCODE_WITH_IRON_LAWS=${GOVCODE_WITH_IRON_LAWS:-0}
case "$GOVCODE_WITH_IRON_LAWS" in 0|1) ;; *) exit 4 ;; esac
export GOVCODE_REPO GOVCODE_ARTIFACTS GOVCODE_EXPECTED_COMMIT
# Isolated mode excludes checkout modules and PYTHONPATH. No source config read.
if ! "$GOVCODE_PYTHON" -I - <<'PY'
import os
from pathlib import Path
import re
try:
    repo = Path(os.environ['GOVCODE_REPO'])
    out = Path(os.environ['GOVCODE_ARTIFACTS'])
    assert repo.is_absolute() and out.is_absolute()
    assert re.fullmatch('[a-f0-9]{40}', os.environ['GOVCODE_EXPECTED_COMMIT'])
    assert out.resolve() != repo.resolve() and repo.resolve() not in out.resolve().parents
    assert not out.exists()
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
except Exception:
    raise SystemExit(4)
PY
then
    printf '%s\n' '{"outcome":"error","code":"PIPELINE_INPUT_INVALID","exit_code":4}'
    exit 4
fi
set --
if [ "$GOVCODE_WITH_IRON_LAWS" = 1 ]; then set -- --with-iron-laws; fi
GOVCODE_SCAN_STATUS=0
"$GOVCODE_PYTHON" -I -m govcode_harness scan \
    --repo "$GOVCODE_REPO" --commit "$GOVCODE_EXPECTED_COMMIT" \
    --output "$GOVCODE_ARTIFACTS/evidence" --local-demo "$@" \
    > "$GOVCODE_ARTIFACTS/scan.json" 2> "$GOVCODE_ARTIFACTS/scan-error.json" || GOVCODE_SCAN_STATUS=$?
GOVCODE_GATE_STATUS=0
"$GOVCODE_PYTHON" -I -m govcode_harness.gate \
    --repo "$GOVCODE_REPO" --expected-commit "$GOVCODE_EXPECTED_COMMIT" \
    --evidence "$GOVCODE_ARTIFACTS/evidence" --local-demo "$@" \
    > "$GOVCODE_ARTIFACTS/gate.json" || GOVCODE_GATE_STATUS=$?
cat "$GOVCODE_ARTIFACTS/gate.json"
if [ "$GOVCODE_GATE_STATUS" -ne 0 ]; then exit "$GOVCODE_GATE_STATUS"; fi
case "$GOVCODE_SCAN_STATUS" in 0|2|3|4) exit "$GOVCODE_SCAN_STATUS" ;; *) exit 4 ;; esac
