#!/usr/bin/env python3
"""Sharded-by-language scan, end to end and ready to run.

Builds the binary if needed, then shows:
  1. a single-process scan over all languages (baseline, timed)
  2. the same scan sharded one process per language (timed), merged back
  3. byte-for-byte equivalence of the two findings.json
  4. the observed speedup

The speedup comes from grammar cold start: each shard materializes only its
own grammar (~233ms) instead of all seven (~1.56s). Single-language corpora have
no gain, and total CPU is unchanged -- only wall time improves when the shards
run concurrently.

Usage:
  python3 scripts/demo_sharded_scan.py [target-dir] [--rules <pack>]
                                      [--langs <csv>] [--taint off|report|strict]
                                      [--out <dir>]

  target-dir  directory to scan (default: tests/fixtures)
  --out       where baseline/ + merged/ reports are kept
              (default: .tmp-sharded-demo; removed with `rm -rf`)
  --langs     override the seven default language ids
  everything else is forwarded to scan.exe

Examples:
  python3 scripts/demo_sharded_scan.py
  python3 scripts/demo_sharded_scan.py /path/to/your/repo
  python3 scripts/demo_sharded_scan.py --taint strict --out /tmp/shard-demo
"""
import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from merge_reports import merge, write_report

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LANGS = "javascript,typescript,tsx,python,java,json,moonbit,csharp,go,rust,php"


def find_exe() -> Path:
    """Release build preferred, debug fallback, build if neither exists."""
    for candidate in (
        ROOT / "_build/native/release/build/sast/scan/scan.exe",
        ROOT / "_build/native/debug/build/sast/scan/scan.exe",
    ):
        if candidate.exists():
            return candidate
    print("==> no binary found, building (debug) ...", flush=True)
    subprocess.run(
        ["moon", "build", "--target", "native", "apps/scan"],
        cwd=ROOT, check=True,
    )
    return ROOT / "_build/native/debug/build/sast/scan/scan.exe"


def elapsed_of(action) -> tuple[dict, float]:
    """Run `action` (returns a report dict) and time it."""
    t0 = time.perf_counter()
    report = action()
    return report, time.perf_counter() - t0


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("target", nargs="?", default="tests/fixtures")
    ap.add_argument("--rules", default="rulepacks/official")
    ap.add_argument("--langs", default=DEFAULT_LANGS)
    ap.add_argument("--taint", default="off")
    ap.add_argument("--out", default=".tmp-sharded-demo")
    ap.add_argument("--help", "-h", action="store_true")
    args, extra = ap.parse_known_args()

    if args.help:
        print(__doc__)
        return 0

    exe = find_exe()
    target = str(Path(args.target).resolve())
    if not Path(target).exists():
        print(f"error: target '{args.target}' does not exist", file=sys.stderr)
        return 2
    langs = [x.strip() for x in args.langs.split(",") if x.strip()]
    if not langs:
        print("error: --langs needs at least one language", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    (out_dir / "baseline").mkdir(parents=True, exist_ok=True)
    (out_dir / "merged").mkdir(parents=True, exist_ok=True)

    common = ["--rules", args.rules, "--taint", args.taint,
              "--format", "json", "--fail-on", "never"] + extra

    print(f"target : {args.target}")
    print(f"rules  : {args.rules}")
    print(f"binary : {exe.name}")
    print(f"langs  : {', '.join(langs)}")
    print(f"taint  : {args.taint}")
    print()

    # 1. Baseline: one process, all languages.
    baseline_path = out_dir / "baseline" / "findings.json"

    def baseline() -> dict:
        subprocess.run(
            [str(exe), target] + common + ["--out", str(out_dir / "baseline")],
            cwd=ROOT, check=True, capture_output=True,
        )
        return json.loads(baseline_path.read_text(encoding="utf-8"))

    base_report, base_time = elapsed_of(baseline)
    base_stats = base_report["stats"]
    print("== 1. single process (all languages)")
    print(f"   files {base_stats['files_scanned']}, findings {len(base_report['findings'])}, "
          f"skipped {base_stats['files_skipped']}")
    print(f"   elapsed {base_time:.3f}s")
    print()

    # 2. Sharded: one process per language, JSON to stdout, merged afterwards.
    with tempfile.TemporaryDirectory(prefix="ls-demo-shards-") as td:
        work = Path(td)
        jobs = []
        t0 = time.perf_counter()
        for lang in langs:
            out_path = work / f"{lang}.json"
            err_path = work / f"{lang}.err"
            # Keep descriptors open until wait(), as in scan_by_lang.py.
            fout = out_path.open("wb")
            ferr = err_path.open("wb")
            proc = subprocess.Popen(
                [str(exe), target, "--lang", lang] + common,
                cwd=ROOT, stdout=fout, stderr=ferr,
            )
            jobs.append((lang, proc, fout, ferr, out_path, err_path))

        reports = []
        for lang, proc, fout, ferr, out_path, err_path in jobs:
            rc = proc.wait()
            fout.close()
            ferr.close()
            if rc != 0:
                detail = err_path.read_text(encoding="utf-8", errors="replace")
                print(f"error: shard '{lang}' exited {rc}\n{detail}", file=sys.stderr)
                return 1
            reports.append(json.loads(out_path.read_text(encoding="utf-8")))
        merged = merge(reports)
        shard_time = time.perf_counter() - t0

    write_report(merged, str(out_dir / "merged" / "findings.json"))
    m_stats = merged["stats"]
    print("== 2. sharded (one process per language)")
    print(f"   {len(langs)} shards, files {m_stats['files_scanned']}, "
          f"findings {len(merged['findings'])}, skipped {m_stats['files_skipped']}")
    print(f"   elapsed {shard_time:.3f}s")
    print()

    # 3. Byte-for-byte equivalence -- the hard contract.
    same = baseline_path.read_bytes() == (out_dir / "merged" / "findings.json").read_bytes()
    print("== 3. equivalence")
    print(f"   findings.json byte-identical: {'YES' if same else 'NO'}")
    print(f"   speedup: {base_time / shard_time:.2f}x")
    print()
    print(f"reports kept at '{out_dir}/' (rm -rf '{out_dir}' to clean up).")
    print("the gain only shows on multi-language trees; point it at a real repo:")
    print("  python3 scripts/demo_sharded_scan.py /path/to/your/repo")

    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
