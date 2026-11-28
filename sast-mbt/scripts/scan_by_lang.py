#!/usr/bin/env python3
"""Sharded scan by language: one `scan --lang <id>` process per language, then
merge into a single byte-identical findings.json.

Why: each process materializes only its own grammar (~233ms) instead of all seven
(~1.33s). On a multi-language cold scan this is ~2.5x end to end. Total CPU is
unchanged; single-language corpora see no benefit.

Python is used as the orchestrator deliberately: on Git Bash/Windows every
forked shell command costs ~0.4s, so a bash loop erased the entire gain.

Usage:
  python3 scripts/scan_by_lang.py <root> [--out <dir>] [--langs <csv>] [scan opts...]

  --out <dir>     write merged findings.json into <dir> (default: stdout)
  --langs <csv>   override the seven default language ids
  everything else is passed through to scan.exe (e.g. --rules, --taint,
  --incremental, --cache-dir, --ignore). --format is forced to json because
  the merger needs structured reports; --fail-on is forced to never so a
  shard never exits 1 just for having findings.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from merge_reports import merge, write_report

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "_build/native/debug/build/sast/scan/scan.exe"
DEFAULT_LANGS = "javascript,typescript,tsx,python,java,json,moonbit,csharp,go,rust,php"


def passthrough(argv: list[str]) -> list[str]:
    """Drop flags the orchestrator owns, keep everything else for scan.exe."""
    owned = {"--format", "--fail-on", "--out", "--lang", "--langs"}
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] in owned:
            i += 2 if i + 1 < len(argv) and not argv[i + 1].startswith("--") else 1
        else:
            out.append(argv[i])
            i += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("root")
    ap.add_argument("--out")
    ap.add_argument("--langs", default=DEFAULT_LANGS)
    ap.add_argument("--help", "-h", action="store_true")
    args, rest = ap.parse_known_args()

    if args.help:
        print(__doc__)
        return 0
    if not EXE.exists():
        print(f"error: missing {EXE}; run `moon build --target native apps/scan`",
              file=sys.stderr)
        return 2

    langs = [x.strip() for x in args.langs.split(",") if x.strip()]
    if not langs:
        print("error: --langs needs at least one language", file=sys.stderr)
        return 2

    # scan.exe runs with cwd=ROOT so `--rules rulepacks/official` resolves;
    # make the scan root absolute so it still means what the caller meant.
    root = str(Path(args.root).resolve())
    cmd_base = [str(EXE), root, "--format", "json", "--fail-on", "never"]
    cmd_base += passthrough(rest)

    with tempfile.TemporaryDirectory(prefix="ls-shards-") as td:
        work = Path(td)
        jobs = []
        for lang in langs:
            out_path = work / f"{lang}.json"
            err_path = work / f"{lang}.err"
            # Keep the descriptors open until wait(): closing them here would
            # pull the file handle out from under the running child.
            fout = out_path.open("wb")
            ferr = err_path.open("wb")
            proc = subprocess.Popen(
                cmd_base[:1] + ["--lang", lang] + cmd_base[1:],
                cwd=ROOT, stdout=fout, stderr=ferr,
            )
            jobs.append((lang, proc, fout, ferr, out_path, err_path))

        reports = []
        failed = False
        for lang, proc, fout, ferr, out_path, err_path in jobs:
            rc = proc.wait()
            fout.close()
            ferr.close()
            if rc != 0:
                detail = err_path.read_text(encoding="utf-8", errors="replace")
                print(f"error: shard '{lang}' exited {rc}\n{detail}", file=sys.stderr)
                failed = True
                continue
            try:
                reports.append(json.loads(out_path.read_text(encoding="utf-8")))
            except (ValueError, OSError) as e:
                print(f"error: shard '{lang}' produced no valid JSON: {e}",
                      file=sys.stderr)
                failed = True
        if failed:
            return 1

        merged = merge(reports)
        if args.out:
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            write_report(merged, str(out_dir / "findings.json"))
            print(f"sharded merge written to {out_dir / 'findings.json'} "
                  f"({len(reports)} shards)")
        else:
            write_report(merged, None)
        return 0


if __name__ == "__main__":
    sys.exit(main())
