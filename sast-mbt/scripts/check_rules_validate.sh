#!/usr/bin/env bash
# M1 acceptance: rules-validate returns 0 for the official rulepack and 2 with
# line/column diagnostics for an intentionally broken rulepack.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXE="_build/native/debug/build/sast/rules-validate/rules-validate.exe"

echo "==> build rules-validate (native)"
moon build --target native apps/rules-validate >/dev/null

echo "==> case 1: official rulepack must pass (exit 0)"
set +e
"$EXE" rulepacks/official tests/fixtures > /tmp/rv-good.out 2>&1
GOOD=$?
set -e
cat /tmp/rv-good.out
if [[ $GOOD -ne 0 ]]; then
  echo "FAIL: official rulepack returned $GOOD, expected 0"
  exit 1
fi

echo "==> case 2: broken rulepack must fail (exit 2) with line/column"
BAD_DIR=".tmp-rules-validate-bad"
rm -rf "$BAD_DIR"
mkdir -p "$BAD_DIR/JS001"
printf 'x' > "$BAD_DIR/JS001/positive.js"
printf 'y' > "$BAD_DIR/JS001/negative.js"
printf '{}' > "$BAD_DIR/JS001/expected.json"
# invalid JSON with a deliberate syntax error on line 2
printf '[\n  { "id": "JS001", BAD JSON HERE }\n]' > "$BAD_DIR/rules.json"
SHA=$(sha256sum "$BAD_DIR/rules.json" | cut -d' ' -f1)
printf '{"name":"bad","version":"0.1.0","analyzer_min_version":"0.1.0","rules_file":"rules.json","rules_sha256":"%s"}' "$SHA" > "$BAD_DIR/manifest.json"

set +e
"$EXE" "$BAD_DIR" "$BAD_DIR" > /tmp/rv-bad.out 2>&1
BAD=$?
set -e
cat /tmp/rv-bad.out
if [[ $BAD -ne 2 ]]; then
  echo "FAIL: broken rulepack returned $BAD, expected 2"
  rm -rf "$BAD_DIR"
  exit 1
fi
if ! grep -q "line .*column" /tmp/rv-bad.out; then
  echo "FAIL: broken rulepack output lacks line/column diagnostics"
  rm -rf "$BAD_DIR"
  exit 1
fi
rm -rf "$BAD_DIR"

echo "RULES-VALIDATE ACCEPTANCE PASSED"
