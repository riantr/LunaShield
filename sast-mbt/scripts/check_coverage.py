#!/usr/bin/env python3
"""Line-coverage gate for the library packages.

Runs `moon coverage analyze` (which re-runs the unit tests with instrumentation)
and `moon coverage report -f summary`, then checks the aggregate line coverage of
`libs/**`. Application entry points (`apps/*/main.mbt`) are excluded on purpose:
they are covered by the cram end-to-end suite, which runs in a separate process
and is invisible to `moon coverage analyze`.

Usage:
  python3 scripts/check_coverage.py [--min-libs 0.90] [--min-file 0.75]

Exit codes: 0 = gate passed, 1 = coverage below threshold, 2 = tooling failure.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINE_RE = re.compile(r"^\s*(.+?):\s*(\d+)/(\d+)\s*$")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-libs", type=float, default=0.90,
                    help="minimum aggregate coverage for libs/** (0..1)")
    ap.add_argument("--min-file", type=float, default=0.75,
                    help="minimum coverage for any single lib file (0..1)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    analyze = run(["moon", "coverage", "analyze"])
    if analyze.returncode != 0:
        print("coverage analyze failed:", analyze.stderr[-800:], file=sys.stderr)
        return 2
    report = run(["moon", "coverage", "report", "-f", "summary"])
    if report.returncode != 0:
        print("coverage report failed:", report.stderr[-800:], file=sys.stderr)
        return 2

    rows: list[tuple[str, int, int]] = []
    for line in report.stdout.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        path, covered, total = m.group(1).strip(), int(m.group(2)), int(m.group(3))
        if total == 0:
            continue
        rows.append((path, covered, total))
    if not rows:
        print("coverage report produced no parseable rows", file=sys.stderr)
        return 2

    libs = [(p, c, t) for p, c, t in rows
            if p.replace("\\", "/").startswith("libs/")]
    if not libs:
        print("no libs/** rows in coverage report", file=sys.stderr)
        return 2

    total_covered = sum(c for _, c, _ in libs)
    total_lines = sum(t for _, _, t in libs)
    aggregate = total_covered / total_lines

    failures: list[str] = []
    if not args.quiet:
        for path, covered, total in sorted(libs, key=lambda r: r[1] / r[2]):
            pct = covered / total
            flag = "  <-- below file floor" if pct < args.min_file else ""
            print(f"  {pct*100:6.1f}%  {covered:4d}/{total:<4d}  {path}{flag}")
    for path, covered, total in libs:
        pct = covered / total
        if pct < args.min_file:
            failures.append(f"{path}: {pct*100:.1f}% < {args.min_file*100:.0f}%")

    print(f"libs aggregate: {total_covered}/{total_lines} "
          f"= {aggregate*100:.1f}% (floor {args.min_libs*100:.0f}%)")
    if aggregate < args.min_libs:
        failures.append(
            f"libs aggregate {aggregate*100:.1f}% < {args.min_libs*100:.0f}%")
    if failures:
        for f in failures:
            print("COVERAGE FAILURE:", f)
        return 1
    print("COVERAGE GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
