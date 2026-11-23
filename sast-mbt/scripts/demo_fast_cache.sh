#!/usr/bin/env bash
# Fast-cache walkthrough: build if needed, then show
#   1. cold -> warm runs with --fast-cache
#   2. the same with strict --incremental (no probes)
#   3. the mtime trade-off on an isolated single-file copy
#
# Usage: bash scripts/demo_fast_cache.sh [target-dir] [cache-dir]
#   target-dir  directory to scan (default: tests/fixtures)
#   cache-dir   scratch cache (default: .tmp-fastcache-demo)
#
# The rewrite step never touches the target directory: it always works on a
# private copy under the cache dir.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-tests/fixtures}"
CACHE="${2:-.tmp-fastcache-demo}"
RULES="${RULES:-rulepacks/official}"

if [[ ! -e "$TARGET" ]]; then
  echo "error: target '$TARGET' does not exist" >&2
  exit 2
fi

EXE="$ROOT/_build/native/release/build/sast/scan/scan.exe"
if [[ ! -x "$EXE" ]]; then
  EXE="$ROOT/_build/native/debug/build/sast/scan/scan.exe"
fi
if [[ ! -x "$EXE" ]]; then
  echo "==> no binary yet, building (debug) ..."
  moon build --target native apps/scan
  EXE="$ROOT/_build/native/debug/build/sast/scan/scan.exe"
fi

rm -rf "$CACHE"
mkdir -p "$CACHE/fast" "$CACHE/strict" "$CACHE/case/src"

# Console output only, so the "cache:" line is printed.
run() { # run <target> <cache> <mode-flags...>
  local target="$1" cache="$2"
  shift 2
  "$EXE" "$target" \
    --rules "$RULES" \
    --format console \
    --fail-on never \
    --cache-dir "$cache" \
    "$@" | grep -E '^(files|findings|cache):'
}

probe_count() {
  local dir="$1/probe"
  if [[ -d "$dir" ]]; then
    ls "$dir" | wc -l | tr -d '[:space:]'
  else
    echo 0
  fi
}

echo "target : $TARGET"
echo "cache  : $CACHE"
echo "binary : $EXE"
echo

echo "== 1. --fast-cache: cold then warm"
echo "-- run 1 (cold, writes entries + probes)"
run "$TARGET" "$CACHE/fast" --fast-cache
echo "-- run 2 (warm, replays without reading file bodies)"
run "$TARGET" "$CACHE/fast" --fast-cache
echo

echo "== 2. strict --incremental: cold then warm"
echo "-- run 1 (cold, hashes every file)"
run "$TARGET" "$CACHE/strict" --incremental
echo "-- run 2 (warm, but still reads + hashes every file)"
run "$TARGET" "$CACHE/strict" --incremental
echo

echo "== 3. probe accounting"
echo "fast-cache probes: $(probe_count "$CACHE/fast")"
echo "strict     probes: $(probe_count "$CACHE/strict")   (expected 0: strict never writes probes)"
echo

echo "== 4. mtime trade-off (isolated copy, same size, same mtime)"
CASE="$CACHE/case"
printf 'function f(req){ eval(req.query.x); }\n' > "$CASE/src/a.js"
echo "-- fast run 1 (cold)"
run "$CASE/src" "$CASE/fast" --fast-cache
echo "-- rewrite eval -> exec (same length) and restore mtime"
cp -p "$CASE/src/a.js" "$CASE/ref.js"
printf 'function f(req){ exec(req.query.x); }\n' > "$CASE/src/a.js"
touch -r "$CASE/ref.js" "$CASE/src/a.js"
echo "-- strict --incremental (hashes content, sees the rewrite)"
run "$CASE/src" "$CASE/strict" --incremental
echo "-- --fast-cache (probe still matches: serves the stale verdict)"
run "$CASE/src" "$CASE/fast" --fast-cache
echo "-- touch the file, then --fast-cache (probe invalidated)"
touch "$CASE/src/a.js"
run "$CASE/src" "$CASE/fast" --fast-cache
echo

echo "done. cache left at '$CACHE' (rm -rf '$CACHE' to clean up)."
echo "the IO saving only shows on large files; point the target at a real tree:"
echo "  bash scripts/demo_fast_cache.sh /path/to/your/repo"
