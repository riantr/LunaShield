#!/usr/bin/env bash
# M1 acceptance: rules-validate returns 0 for the official rulepack and 2 with
# line/column diagnostics for an intentionally broken rulepack.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXE="_build/native/debug/build/sast/rules-validate/rules-validate.exe"
PY="${PY:-$(command -v python3 || command -v python)}"

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

# S4b-5: taint manifest must be schema-checked, cross-checked against rules and
# checksummed. Each case gets its own pack copy so manifest hashes stay honest.
make_taint_case() {
  local mode="$1"
  local d=".tmp-rv-taint-$mode"
  rm -rf "$d"
  mkdir -p "$d"
  cp rulepacks/official/rules.json rulepacks/official/taint.json rulepacks/official/manifest.json "$d/"
  $PY - "$d/taint.json" "$d/manifest.json" "$mode" <<'PY'
import hashlib
import json
import sys

taint_path, manifest_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
with open(taint_path, encoding="utf-8") as f:
    spec = json.load(f)
with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)

if mode in ("unknown-sink", "wrong-language"):
    for lang in spec["languages"]:
        if lang["language"] == "javascript":
            for sink in lang["sinks"]:
                if sink["rule_id"] == "JS001":
                    sink["rule_id"] = "JS999" if mode == "unknown-sink" else "PY001"

with open(taint_path, "w", encoding="utf-8") as f:
    json.dump(spec, f)
# sha-mismatch deliberately keeps the manifest's original hash.
if mode != "sha-mismatch":
    with open(taint_path, "rb") as f:
        manifest["taint_sha256"] = hashlib.sha256(f.read()).hexdigest()
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)
PY
  echo "$d"
}

check_taint_case() {
  local mode="$1" expect="$2"
  local d
  d="$(make_taint_case "$mode")"
  echo "==> taint case: $mode (expect exit 2 with '$expect')"
  set +e
  "$EXE" "$d" tests/fixtures > /tmp/rv-taint.out 2>&1
  local code=$?
  set -e
  cat /tmp/rv-taint.out
  if [[ $code -ne 2 ]]; then
    echo "FAIL: taint case $mode returned $code, expected 2"
    rm -rf "$d"
    exit 1
  fi
  if ! grep -q "$expect" /tmp/rv-taint.out; then
    echo "FAIL: taint case $mode output lacks '$expect'"
    rm -rf "$d"
    exit 1
  fi
  rm -rf "$d"
}

check_taint_case "unknown-sink" "unknown rule"
check_taint_case "wrong-language" "belongs to language"
check_taint_case "sha-mismatch" "SHA-256 mismatch"

echo "RULES-VALIDATE ACCEPTANCE PASSED"
