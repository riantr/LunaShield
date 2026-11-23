#!/usr/bin/env python3
"""Merge per-language shard reports into one byte-stable findings.json.

The sharded scan (`scan_by_lang.py`) runs `scan --lang <id>` once per language.
Each shard discovers the whole tree, so ignored/unregistered-language files are
reported by every shard. This merger reproduces the single-process report:

  findings      canonical (path, line, column, rule_id, fingerprint) order,
                deduped by (path, fingerprint) exactly like `finalize_findings`
  warnings      (path, line, column) stable order
  skipped_files string-sorted and deduped (discovery-level skips repeat)
  stats         scanned/bytes/raw_hits summed, skipped recomputed from the
                deduped list (otherwise discovery-level skips would be Nx)

Usage:
  python3 scripts/merge_reports.py out/js/findings.json out/py/findings.json \
      -o merged/findings.json
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def finding_key(f: dict) -> tuple:
    p = f["primary"]
    return (p["path"], p["line"], p["column"], f["rule_id"], f["fingerprint"])


def warning_key(w: dict) -> tuple:
    return (w["path"], w["line"], w["column"])


def merge(reports: list[dict]) -> dict:
    """Produce the single-process-equivalent report from per-shard reports."""
    if not reports:
        raise ValueError("no shard reports to merge")

    findings: list[dict] = []
    warnings: list[dict] = []
    skipped: list[str] = []
    files_scanned = 0
    bytes_scanned = 0
    raw_hits = 0

    for r in reports:
        findings.extend(r["findings"])
        warnings.extend(r["warnings"])
        skipped.extend(r["skipped_files"])
        stats = r["stats"]
        files_scanned += stats["files_scanned"]
        bytes_scanned += stats["bytes_scanned"]
        raw_hits += stats["raw_hits"]

    # Canonical order: MoonBit uses StringView::lexical_compare (code units),
    # which matches Python's code-point order for the ASCII paths we emit.
    # Stable sort keeps same-key warnings in shard order, as the native sorter.
    findings.sort(key=finding_key)
    seen: set[tuple] = set()
    unique_findings: list[dict] = []
    for f in findings:
        key = (f["primary"]["path"], f["fingerprint"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # A file of language A is `unregistered-language` in every shard except A.
    # Such a cross-language skip appears in N-1 reports; a genuinely unknown
    # extension appears in all N. Keep only the latter so the merged skipped
    # list matches a single-process scan. Scan-time reasons (binary, too-large,
    # ...) are reported by exactly one shard and must always survive.
    n_shards = len(reports)
    skip_count = Counter(skipped)
    filtered = []
    for s in skipped:
        if s.endswith(" (unregistered-language)") and skip_count[s] < n_shards:
            continue
        filtered.append(s)
    # The CLI sorts skipped files with `sort_by_key(fn(s) { s })`, i.e. the
    # MoonBit stdlib Compare for String: shortlex (length first, then code
    # units), NOT the lexical_compare used for findings/warnings. See the note
    # in discover.mbt. Use UTF-16 code-unit length to match exactly.
    skipped = sorted(set(filtered), key=lambda s: (len(s.encode("utf-16-le")) // 2, s))

    return {
        "version": reports[0]["version"],
        "stats": {
            "files_scanned": files_scanned,
            "files_skipped": len(skipped),
            "bytes_scanned": bytes_scanned,
            "raw_hits": raw_hits,
        },
        "warnings": warnings,
        "skipped_files": skipped,
        "findings": unique_findings,
    }


def serialize(merged: dict) -> str:
    # The CLI appends one newline both to --out files and stdout (println).
    return json.dumps(merged, separators=(",", ":"), ensure_ascii=False) + "\n"


def write_report(merged: dict, out: str | None) -> None:
    text = serialize(merged)
    if out:
        # write_bytes avoids Windows text-mode CRLF translation; the native CLI
        # writes a bare LF and byte-for-byte equality is part of the contract.
        Path(out).write_bytes(text.encode("utf-8"))
    else:
        sys.stdout.write(text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="per-shard findings.json files")
    ap.add_argument("-o", "--out", help="write here instead of stdout")
    args = ap.parse_args()
    reports = []
    for name in args.inputs:
        path = Path(name)
        if not path.exists():
            print(f"missing shard report: {path}", file=sys.stderr)
            return 2
        reports.append(json.loads(path.read_text(encoding="utf-8")))
    write_report(merge(reports), args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
