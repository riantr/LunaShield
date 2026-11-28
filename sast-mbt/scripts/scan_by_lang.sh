#!/usr/bin/env bash
# Sharded scan by language: one `scan --lang <id>` process per language, then
# merge the per-shard findings.json into a single byte-stable report.
#
# Why: each process materializes only its own grammar (~233ms) instead of all
# six (~1.33s). On a multi-language cold scan this cuts grammar setup ~5.8x.
# Total CPU is unchanged; wall time improves only when processes run in
# parallel. Single-language corpora see no benefit.
#
# Usage:
#   bash scripts/scan_by_lang.sh <root> [--out <dir>] [--langs <csv>] [scan opts...]
#
#   --out <dir>     write merged findings.json into <dir> (default: stdout)
#   --langs <csv>   override the seven default language ids
#   everything else is passed through to scan.exe (e.g. --rules, --taint,
#   --incremental, --cache-dir, --ignore). --format is forced to json because
#   the merger needs structured reports; --fail-on is forced to never so a
#   shard never exits 1 just for having findings.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXE="_build/native/debug/build/sast/scan/scan.exe"
PY="$(command -v python3 || command -v python)"
DEFAULT_LANGS="javascript,typescript,tsx,python,java,json,moonbit,csharp,go,rust,php"

usage() {
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

root=""
out_dir=""
langs="$DEFAULT_LANGS"
extra=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage 0 ;;
    --out)
      [[ $# -ge 2 ]] || { echo "error: --out needs a value" >&2; exit 2; }
      out_dir="$2"
      shift 2
      ;;
    --langs)
      [[ $# -ge 2 ]] || { echo "error: --langs needs a value" >&2; exit 2; }
      langs="$2"
      shift 2
      ;;
    --format)
      echo "note: --format forced to json for sharded merge" >&2
      shift 2
      ;;
    *)
      if [[ -z "$root" ]]; then
        root="$1"
      else
        extra+=("$1")
      fi
      shift
      ;;
  esac
done

[[ -n "$root" ]] || { echo "error: missing scan root" >&2; usage 2; }
[[ -x "$EXE" ]] || {
  echo "error: missing $EXE; run: moon build --target native apps/scan" >&2
  exit 2
}

# Keep shard output inside the project tree: scan.exe and Python must resolve
# the same paths, and Git Bash's /tmp mapping is not visible to native Python.
# One flat directory only: on Git Bash/Windows each mkdir/rmdir costs ~0.5s, so
# per-language subdirectories would dominate the scan. JSON goes to stdout.
work=".lunashield-shards-$$"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

IFS=',' read -r -a raw_langs <<< "$langs"
# Trim with bash parameter expansion, not `echo | tr`: on Git Bash/Windows each
# external process costs ~0.4s, so six forks here would dominate the whole scan.
lang_list=()
for lang in "${raw_langs[@]}"; do
  lang="${lang//[[:space:]]/}"
  [[ -n "$lang" ]] || continue
  lang_list+=("$lang")
done

pids=()
for lang in "${lang_list[@]}"; do
  (
    "$EXE" "$root" --lang "$lang" --format json --fail-on never \
      "${extra[@]}" >"$work/$lang.json" 2>"$work/$lang.err"
  ) &
  pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    status=1
  fi
done
if [[ $status -ne 0 ]]; then
  echo "error: a shard failed; per-language logs kept in $work" >&2
  # The EXIT trap would delete the logs, so disable it before reporting.
  trap - EXIT
  exit 1
fi

inputs=()
for lang in "${lang_list[@]}"; do
  report="$work/$lang.json"
  [[ -f "$report" ]] || {
    echo "error: shard '$lang' produced no findings.json" >&2
    exit 1
  }
  inputs+=("$report")
done

if [[ -n "$out_dir" ]]; then
  mkdir -p "$out_dir"
  "$PY" scripts/merge_reports.py "${inputs[@]}" -o "$out_dir/findings.json"
  echo "sharded merge written to $out_dir/findings.json (${#inputs[@]} shards)"
else
  "$PY" scripts/merge_reports.py "${inputs[@]}"
fi
