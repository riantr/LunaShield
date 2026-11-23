#!/usr/bin/env python3
"""Cold-start attribution for the scanner.

Separates the three costs that a scan pays before it touches many files:

  1. process start        — `scan --help`
  2. rules + Query compile— empty directory with a full rule pack
  3. grammar construction — one file per language (grammar tables are decoded
                            lazily, once per language per process)

Usage: python3 scripts/bench_coldstart.py [--runs N]
"""
import argparse
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "_build/native/debug/build/sast/scan/scan.exe"

JS = "function f(req){ eval(req.query.x); }\n"
PY = "eval(input())\n"
JAVA = 'class A { void f(){ Runtime.getRuntime().exec("x"); } }\n'
TS = "const x = eval(y);\n"
TSX = "const C = () => eval(y);\n"
JSONF = '{"a":1}\n'


def timed(cmd: list[str], runs: int) -> float:
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        samples.append(time.perf_counter() - t0)
        if proc.returncode != 0:
            raise SystemExit(f"failed: {cmd}\n{proc.stdout}{proc.stderr}")
    return statistics.median(samples)


def scan_once(corpus: Path, rules: Path, runs: int) -> float:
    samples = []
    for _ in range(runs):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o"
            out.mkdir()
            cmd = [str(EXE), str(corpus), "--rules", str(rules),
                   "--format", "json", "--out", str(out),
                   "--fail-on", "never", "--taint", "off"]
            t0 = time.perf_counter()
            proc = subprocess.run(cmd, capture_output=True, text=True)
            samples.append(time.perf_counter() - t0)
            if proc.returncode != 0:
                raise SystemExit(f"scan failed: {proc.stdout}{proc.stderr}")
    return statistics.median(samples)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()
    if not EXE.exists():
        print(f"missing {EXE}; run: moon build --target native apps/scan", file=sys.stderr)
        return 2

    pack = ROOT / "rulepacks" / "official"
    with tempfile.TemporaryDirectory(prefix="ls-cold-") as td:
        base = Path(td)
        empty = base / "empty"
        empty.mkdir()
        one_js = base / "one-js"
        one_js.mkdir()
        (one_js / "a.js").write_text(JS)
        one_py = base / "one-py"
        one_py.mkdir()
        (one_py / "a.py").write_text(PY)
        six = base / "six"
        six.mkdir()
        (six / "a.js").write_text(JS)
        (six / "b.py").write_text(PY)
        (six / "c.java").write_text(JAVA)
        (six / "d.json").write_text(JSONF)
        (six / "e.ts").write_text(TS)
        (six / "f.tsx").write_text(TSX)

        help_t = timed([str(EXE), "--help"], args.runs)
        empty_t = scan_once(empty, pack, args.runs)
        js_t = scan_once(one_js, pack, args.runs)
        py_t = scan_once(one_py, pack, args.runs)
        six_t = scan_once(six, pack, args.runs)
        fixtures_t = scan_once(ROOT / "tests/fixtures", pack, args.runs)

    rows = [
        ("scan --help (process start only)", help_t),
        ("empty dir, 50 rules", empty_t),
        ("1 JS file", js_t),
        ("1 Python file", py_t),
        ("6 languages x 1 file", six_t),
        ("tests/fixtures (150 files, 6 langs)", fixtures_t),
    ]
    print(f"runs={args.runs} (median)")
    for label, seconds in rows:
        print(f"  {seconds*1000:8.1f} ms  {label}")
    print()
    print(f"rules + Query compile (50 rules)   ~ {(empty_t-help_t)*1000:6.1f} ms")
    print(f"one grammar construction (JS)      ~ {(js_t-empty_t)*1000:6.1f} ms")
    print(f"one grammar construction (Python)  ~ {(py_t-empty_t)*1000:6.1f} ms")
    print(f"six grammar constructions          ~ {(six_t-empty_t)*1000:6.1f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
