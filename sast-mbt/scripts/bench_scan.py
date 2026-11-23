#!/usr/bin/env python3
"""Reproducible scan benchmark: median wall time over N runs per taint mode.

Usage: python3 scripts/bench_scan.py [--runs N] [--corpus DIR] [--rules DIR]
Prints one machine-readable line per mode so runs can be diffed across commits.
"""
import argparse, json, statistics, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "_build/native/debug/build/sast/scan/scan.exe"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--corpus", default=str(ROOT / "tests/fixtures"))
    ap.add_argument("--rules", default=str(ROOT / "rulepacks/official"))
    ap.add_argument("--modes", default="off,report,strict")
    ap.add_argument("--copies", type=int, default=1,
                    help="replicate the corpus N times (throughput testing)")
    args = ap.parse_args()
    if not EXE.exists():
        print(f"missing {EXE}; run: moon build --target native apps/scan", file=sys.stderr)
        return 2
    out = {}
    with tempfile.TemporaryDirectory(prefix="ls-bench-") as td:
        base = Path(td)
        corpus = Path(args.corpus)
        if args.copies > 1:
            import shutil
            scaled = base / "corpus"
            for i in range(args.copies):
                shutil.copytree(corpus, scaled / f"c{i}", dirs_exist_ok=True)
            corpus = scaled
        for mode in args.modes.split(","):
            times, count = [], None
            for i in range(args.runs):
                o = base / f"{mode}-{i}"
                o.mkdir()
                cmd = [str(EXE), str(corpus), "--rules", args.rules,
                       "--format", "json", "--out", str(o),
                       "--fail-on", "never", "--taint", mode]
                t0 = time.perf_counter()
                p = subprocess.run(cmd, capture_output=True, text=True)
                dt = time.perf_counter() - t0
                if p.returncode != 0:
                    print(f"scan failed ({mode}): {p.stdout} {p.stderr}", file=sys.stderr)
                    return 1
                times.append(dt)
                count = len(json.loads((o / "findings.json").read_text())["findings"])
            med = statistics.median(times)
            out[mode] = med
            print(f"{mode:7s} median={med*1000:8.1f}ms findings={count} runs={args.runs}")
    if "off" in out:
        for mode, med in out.items():
            if mode != "off":
                print(f"{mode:7s} overhead_vs_off={(med/out['off']-1)*100:+.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
