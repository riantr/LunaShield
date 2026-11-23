#!/usr/bin/env python3
"""Reproducible scan benchmark.

Two groups of measurements:

  --cache-mode none    one line per taint mode, no cache at all (original mode).
  --cache-mode strict  cold vs warm for `--incremental`
  --cache-mode fast    cold vs warm for `--fast-cache`
  --cache-mode both    all four of the above

"cold" clears the cache before every timed run; "warm" primes the cache once and
then times runs that are fully cached. Cache measurements always use `--taint off`
because the warm/cold split is about IO, not analysis.

Usage:
  python3 scripts/bench_scan.py --runs 3 --modes off
  python3 scripts/bench_scan.py --runs 3 --modes off --copies 6 --cache-mode both
"""
import argparse
import json
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "_build/native/debug/build/sast/scan/scan.exe"

CACHE_LINE = re.compile(r"^cache:\s*(\d+) hit,\s*(\d+) miss\s*$", re.M)
FINDINGS_LINE = re.compile(r"^findings:\s*(\d+)", re.M)


def describe(seconds: float) -> str:
    return f"{seconds * 1000:8.1f}ms"


def run_scan(
    corpus: Path,
    rules: Path,
    taint: str,
    out_dir: Path,
    cache_dir: Path | None,
    cache_flags: list[str],
) -> tuple[float, int, tuple[int, int]]:
    """One timed scan. Returns (seconds, findings, (hits, misses))."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(EXE), str(corpus), "--rules", str(rules),
           "--format", "console,json", "--out", str(out_dir),
           "--fail-on", "never", "--taint", taint]
    if cache_dir is not None:
        cmd += ["--cache-dir", str(cache_dir)]
    cmd += cache_flags
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - t0
    if proc.returncode != 0:
        raise SystemExit(f"scan failed: {' '.join(cmd)}\n{proc.stdout}{proc.stderr}")
    findings = FINDINGS_LINE.search(proc.stdout)
    cache = CACHE_LINE.search(proc.stdout)
    return (
        elapsed,
        int(findings.group(1)) if findings else -1,
        (int(cache.group(1)), int(cache.group(2))) if cache else (0, 0),
    )


def median_run(times: list[float]) -> float:
    return statistics.median(times)


def bench_plain(base: Path, corpus: Path, rules: Path, modes: list[str], runs: int) -> None:
    plain = {}
    for mode in modes:
        times, findings = [], -1
        for i in range(runs):
            out = base / f"out-{mode}-{i}"
            dt, findings, _ = run_scan(corpus, rules, mode, out, None, [])
            times.append(dt)
        plain[mode] = median_run(times)
        print(f"{mode:7s} median={describe(median_run(times))} findings={findings} runs={runs}")
    if "off" in plain:
        for mode, med in plain.items():
            if mode != "off":
                print(f"{mode:7s} overhead_vs_off={(med / plain['off'] - 1) * 100:+.1f}%")


def bench_cache(
    base: Path,
    corpus: Path,
    rules: Path,
    label: str,
    cache_flags: list[str],
    runs: int,
) -> tuple[float, float, int]:
    """Measure cold and warm; returns (cold_median, warm_median, findings)."""
    cache_dir = base / f"cache-{label}"

    def once(tag: str, clear: bool) -> tuple[float, int, tuple[int, int]]:
        if clear:
            shutil.rmtree(cache_dir, ignore_errors=True)
        out = base / f"out-{label}-{tag}"
        return run_scan(corpus, rules, "off", out, cache_dir, cache_flags)

    cold_times, findings, cold_cache = [], -1, (0, 0)
    for i in range(runs):
        dt, findings, cold_cache = once(f"cold{i}", clear=True)
        cold_times.append(dt)

    # Prime once, then time fully cached runs.
    once("prime", clear=False)
    warm_times, warm_cache = [], (0, 0)
    for i in range(runs):
        dt, _, warm_cache = once(f"warm{i}", clear=False)
        warm_times.append(dt)

    cold, warm = median_run(cold_times), median_run(warm_times)
    print(f"{label:6s} cold median={describe(cold)} cache={cold_cache[0]}/{cold_cache[1]} hit/miss")
    print(f"{label:6s} warm median={describe(warm)} cache={warm_cache[0]}/{warm_cache[1]} hit/miss "
          f"findings={findings} runs={runs}")
    return cold, warm, findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--corpus", default=str(ROOT / "tests/fixtures"))
    ap.add_argument("--rules", default=str(ROOT / "rulepacks/official"))
    ap.add_argument("--modes", default="off,report,strict")
    ap.add_argument("--copies", type=int, default=1,
                    help="replicate the corpus N times (throughput testing)")
    ap.add_argument("--cache-mode", default="none",
                    choices=["none", "strict", "fast", "both"],
                    help="none = no cache; strict/fast/both = also measure cold vs warm")
    args = ap.parse_args()
    if not EXE.exists():
        print(f"missing {EXE}; run: moon build --target native apps/scan", file=sys.stderr)
        return 2

    modes = [m for m in args.modes.split(",") if m]
    with tempfile.TemporaryDirectory(prefix="ls-bench-") as td:
        base = Path(td)
        corpus = Path(args.corpus)
        if args.copies > 1:
            scaled = base / "corpus"
            for i in range(args.copies):
                shutil.copytree(corpus, scaled / f"c{i}", dirs_exist_ok=True)
            corpus = scaled
            print(f"corpus: {args.copies} copies of {args.corpus}")

        if args.cache_mode == "none":
            bench_plain(base, corpus, args.rules, modes, args.runs)
            return 0

        results = {}
        if args.cache_mode in ("strict", "both"):
            results["strict"] = bench_cache(
                base, corpus, Path(args.rules), "strict", ["--incremental"], args.runs)
        if args.cache_mode in ("fast", "both"):
            results["fast"] = bench_cache(
                base, corpus, Path(args.rules), "fast", ["--fast-cache"], args.runs)

        if "strict" in results and "fast" in results:
            strict_cold, strict_warm, _ = results["strict"]
            fast_cold, fast_warm, _ = results["fast"]
            print(f"fast warm vs strict warm = {strict_warm / fast_warm:.2f}x")
            print(f"fast cold vs strict cold = {strict_cold / fast_cold:.2f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
