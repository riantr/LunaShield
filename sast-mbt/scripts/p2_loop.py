#!/usr/bin/env python3
"""Loop over the remaining P2 acceptance gates.

Each gate is a small, deterministic check that answers one question: has this
P2 deliverable actually landed?  The script does not modify code.  Run it
between implementation steps, or with --watch while editing, to see which
gates are still open.

Usage:
    python3 scripts/p2_loop.py                 # one pass over all gates
    python3 scripts/p2_loop.py --gate s5       # one gate only
    python3 scripts/p2_loop.py --rounds 3      # re-evaluate up to 3 times
    python3 scripts/p2_loop.py --watch         # re-run when source files change
    python3 scripts/p2_loop.py --json          # machine-readable result

Exit code is 0 only when every selected gate passes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SAST = ROOT / "sast-mbt" if (ROOT / "sast-mbt").exists() else ROOT
# ROOT is already sast-mbt when this script lives in sast-mbt/scripts.
SPIKE = ROOT.parent / "p0-spike"
BENCH = ROOT.parent / "benchmarks" / "owasp-subset"

WATCH_SUFFIXES = {".mbt", ".json", ".py", ".sh", ".md", ".yml", ".yaml"}
IGNORED_PARTS = {"_build", ".mooncakes", ".git"}


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def contains_in_tree(base: Path, needle: str) -> bool:
    if not base.exists():
        return False
    for path in base.rglob("*.mbt"):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        if needle in read(path):
            return True
    return False


def check_s5_baseline() -> tuple[bool, str]:
    missing: list[str] = []
    cli = read(SAST / "apps" / "scan" / "main.mbt")
    if "--baseline" not in cli:
        missing.append("CLI option --baseline")

    if not contains_in_tree(SAST / "libs" / "report", "baselineState"):
        missing.append("SARIF baselineState")

    if not contains_in_tree(SAST / "libs" / "core-model", "baseline"):
        missing.append("Finding/baseline DTO field")

    note = ""
    exe = SAST / "_build" / "native" / "debug" / "build" / "sast" / "scan" / "scan.exe"
    if exe.exists():
        try:
            proc = subprocess.run(
                [str(exe), "--help"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if "--baseline" not in proc.stdout:
                missing.append("--baseline missing from scan --help")
        except (OSError, subprocess.TimeoutExpired) as exc:
            note = f" (help probe skipped: {exc})"
    else:
        note = " (help probe skipped: scan binary not built)"

    if missing:
        return False, "; ".join(missing)
    return True, "CLI / SARIF / DTO baseline fields present" + note


def check_s6_predicates() -> tuple[bool, str]:
    model = read(SAST / "libs" / "rule" / "model.mbt")
    names = sorted(set(re.findall(r'"([a-z0-9_]*ignore_case[a-z0-9_]*)"', model)))
    if not names:
        return False, "no case-insensitive predicate kind in libs/rule/model.mbt"

    engine = read(SAST / "libs" / "query-engine" / "engine.mbt")
    if "to_lowercase" not in engine and "lowercase" not in engine:
        return False, "query engine has no case-insensitive comparison"

    try:
        rules = json.loads(read(SAST / "rulepacks" / "official" / "rules.json"))
    except json.JSONDecodeError as exc:
        return False, f"rules.json unreadable: {exc}"

    used = {
        predicate.get("kind")
        for rule in rules
        for predicate in rule.get("predicates", [])
        if predicate.get("kind") in names
    }
    if not used:
        return False, f"kinds {names} declared but unused in the official rulepack"
    return True, f"case-insensitive kinds used: {', '.join(sorted(used))}"


def check_s4c_cfg() -> tuple[bool, str]:
    cfg_dir = SAST / "libs" / "dataflow"
    cfg = cfg_dir / "cfg.mbt"
    if not cfg.exists():
        return False, "libs/dataflow/cfg.mbt missing"
    tests = list(cfg_dir.glob("*_test.mbt"))
    if not tests:
        return False, "no libs/dataflow/*_test.mbt"
    text = read(cfg)
    if "CFG" not in text or "pub fn" not in text:
        return False, "cfg.mbt has no public CFG API"
    return True, f"CFG module present with {len(tests)} test file(s)"


def check_mcil() -> tuple[bool, str]:
    base = SPIKE / "mcil"
    document = base / "GO_NO_GO.md"
    sample = base / "sample.c"
    if not document.exists():
        return False, "p0-spike/mcil/GO_NO_GO.md missing"
    text = read(document)
    if not re.search(r"\b(GO|NO-GO|NO GO)\b", text, re.IGNORECASE):
        return False, "no explicit GO / NO-GO decision in GO_NO_GO.md"
    if not sample.exists():
        return False, "p0-spike/mcil/sample.c missing"
    return True, "MCIL spike has an explicit go/no-go decision and a C99 sample"


def check_benchmark() -> tuple[bool, str]:
    required = ["README.md", "check_fp.py", "report.json"]
    missing = [name for name in required if not (BENCH / name).exists()]
    if missing:
        return False, "benchmarks/owasp-subset missing: " + ", ".join(missing)
    try:
        report = json.loads(read(BENCH / "report.json"))
    except json.JSONDecodeError as exc:
        return False, f"report.json unreadable: {exc}"

    fp = report.get("false_positive_rate")
    p1 = report.get("p1_false_positive_rate")
    if not isinstance(fp, (int, float)) or not isinstance(p1, (int, float)):
        return False, "report.json needs numeric false_positive_rate and p1_false_positive_rate"
    if fp > 0.10:
        return False, f"false_positive_rate={fp} exceeds 0.10"
    if fp >= p1:
        return False, f"no FP reduction vs P1 ({fp} >= {p1})"
    return True, f"FP {p1} -> {fp} (threshold 0.10)"


def check_verify() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["bash", "scripts/verify.sh"],
            cwd=SAST,
            capture_output=True,
            text=True,
            timeout=900,
            env={**os.environ, "PY": sys.executable},
        )
    except FileNotFoundError:
        return False, "bash not found"
    except subprocess.TimeoutExpired:
        return False, "verify.sh timed out after 900s"
    if proc.returncode != 0:
        tail = (proc.stdout + "\n" + proc.stderr).strip().splitlines()[-12:]
        return False, "verify.sh exit " + str(proc.returncode) + ": " + " | ".join(tail)
    return True, "verify.sh ALL CHECKS PASSED"


@dataclass(frozen=True)
class Gate:
    id: str
    title: str
    check: Callable[[], tuple[bool, str]]


GATES = [
    Gate("s5", "S5 baseline", check_s5_baseline),
    Gate("s6", "S6 case-insensitive predicates", check_s6_predicates),
    Gate("s4c", "S4c CFG / dataflow", check_s4c_cfg),
    Gate("mcil", "MCIL go/no-go", check_mcil),
    Gate("benchmark", "Benchmark FP reduction", check_benchmark),
    Gate("verify", "Full verify gate", check_verify),
]


def evaluate(gates: list[Gate]) -> list[dict]:
    results: list[dict] = []
    for gate in gates:
        ok, detail = gate.check()
        results.append(
            {"id": gate.id, "gate": gate.title, "pass": ok, "detail": detail}
        )
    return results


def emit(results: list[dict], round_no: int, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {"round": round_no, "all_pass": all(r["pass"] for r in results), "gates": results},
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    print(f"== P2 LOOP round {round_no} ==")
    for result in results:
        status = "PASS" if result["pass"] else "OPEN"
        print(f"[{status}] {result['gate']}: {result['detail']}")
    # A passing subset must not be reported as the whole phase being done.
    label = "P2" if len(results) == len(GATES) else "SELECTED GATES"
    if all(result["pass"] for result in results):
        print(f"{label} COMPLETE")
    else:
        open_ids = ", ".join(r["id"] for r in results if not r["pass"])
        print(f"{label} INCOMPLETE: {open_ids}")


def snapshot() -> dict[str, tuple[int, int]]:
    data: dict[str, tuple[int, int]] = {}
    bases = [
        SAST / "libs",
        SAST / "apps",
        SAST / "rulepacks",
        SAST / "scripts",
        SPIKE / "mcil",
        BENCH,
    ]
    for base in bases:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in WATCH_SUFFIXES:
                continue
            if any(part in IGNORED_PARTS for part in path.parts):
                continue
            try:
                stat = path.stat()
                data[str(path)] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                pass
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--gate",
        action="append",
        choices=[gate.id for gate in GATES],
        help="run only this gate (repeatable)",
    )
    parser.add_argument("--rounds", type=int, default=1, help="number of passes (default: 1)")
    parser.add_argument("--watch", action="store_true", help="re-run when source files change")
    parser.add_argument("--interval", type=float, default=2.0, help="watch poll interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    selected = [gate for gate in GATES if not args.gate or gate.id in args.gate]
    if args.rounds < 1:
        parser.error("--rounds must be >= 1")

    if args.watch:
        last: dict[str, tuple[int, int]] | None = None
        while True:
            results = evaluate(selected)
            emit(results, 1, args.json)
            if all(result["pass"] for result in results):
                return 0
            current = snapshot()
            if last is not None and current != last and not args.json:
                print("[loop] source change detected, re-evaluating")
            last = current
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                return 130

    for round_no in range(1, args.rounds + 1):
        results = evaluate(selected)
        emit(results, round_no, args.json)
        if all(result["pass"] for result in results):
            return 0
        if round_no < args.rounds and not args.json:
            print(f"[loop] round {round_no}/{args.rounds} incomplete, re-checking")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
