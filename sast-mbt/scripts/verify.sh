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
PY="$(command -v python3 || command -v python)"

echo "==> [1/9] resolve dependencies (moon check populates .mooncakes; no grammar compiled yet)"
moon check --target native

echo "==> [2/9] apply grammar compatibility patch (idempotent, needed once after fetch)"
$PY scripts/patch_grammars.py

echo "==> [3/9] grammar compatibility gate (fails CI if any binding is unpatched)"
$PY scripts/patch_grammars.py --check

echo "==> [4/9] moon check (native, full workspace)"
moon check --target native

echo "==> [5/9] moon test (native, primary path; needs Clang/MSVC+SDK)"
moon test --target native

echo "==> [6/9] moon fmt check"
moon fmt --check

echo "==> [7/9] rules-validate acceptance (exit codes 0 / 2 with line/column)"
bash scripts/check_rules_validate.sh

echo "==> [8/9] cram end-to-end (must pass the tests directory explicitly)"
moon build --target native apps/scan
moon cram test tests/cram/

echo "==> [9/9] golden rulepack check (50 rules, detection/FP thresholds)"
$PY scripts/gen_rulepack.py --check
$PY scripts/check_golden.py

if [[ "${1:-}" == "--js-test" ]]; then
  echo "==> EXTRA moon test (js backend, partial: async/fs packages are native-only)"
  moon test --target js || echo "NOTE: js target is expected to fail for async/fs packages"
fi

echo "ALL CHECKS PASSED"
