#!/usr/bin/env bash
# Unified verification sequence for local dev and CI.
# Usage: bash scripts/verify.sh [--js-test]
# Note: from M1 on, `apps/rules-validate` uses async/fs whose generated API is
# native-only, so `moon test --target js` no longer covers the whole workspace.
# Native test is the primary path; pass --js-test only for a partial JS check.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# GitHub windows runners ship `python`, not always `python3`.
export PY="${PY:-$(command -v python3 || command -v python)}"

echo "==> [1/12] resolve dependencies (best-effort check populates .mooncakes; strict check is step 4)"
# Newly fetched grammars carry the old to_string() form and fail check until
# step 2 patches them; that failure is expected on a cold cache.
moon check --target native >/dev/null 2>&1 || true

echo "==> [2/12] apply grammar compatibility patch (idempotent, needed once after fetch)"
$PY scripts/patch_grammars.py

echo "==> [3/12] grammar compatibility gate (fails CI if any binding is unpatched)"
$PY scripts/patch_grammars.py --check

echo "==> [4/12] moon check (native, full workspace)"
moon check --target native

echo "==> [5/12] moon test (native, primary path; needs Clang/MSVC+SDK)"
moon test --target native

echo "==> [6/12] moon fmt check"
moon fmt --check

echo "==> [7/12] rules-validate acceptance (exit codes 0 / 2 with line/column)"
bash scripts/check_rules_validate.sh

echo "==> [8/12] cram end-to-end (must pass the tests directory explicitly)"
moon build --target native apps/scan
moon cram test tests/cram/

echo "==> [9/12] golden rulepack check (64 rules, detection/FP thresholds)"
$PY scripts/gen_rulepack.py --check
$PY scripts/check_golden.py

echo "==> [10/12] line coverage gate (libs/** aggregate >= 90%, per-file >= 75%)"
$PY scripts/check_coverage.py

echo "==> [11/12] sharded scan equivalence (merged report byte-identical)"
$PY scripts/check_sharded.py

echo "==> [12/12] WASM target build (scan.wasm is produced, execution needs a host harness)"
moon build --target wasm apps/scan

if [[ "${1:-}" == "--js-test" ]]; then
  echo "==> EXTRA moon test (js backend, partial: async/fs packages are native-only)"
  moon test --target js || echo "NOTE: js target is expected to fail for async/fs packages"
fi

echo "ALL CHECKS PASSED"
