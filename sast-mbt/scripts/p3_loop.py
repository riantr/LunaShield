#!/usr/bin/env python3
"""Loop over the P3 acceptance gates.

P3 originally meant engineering/ecosystem work: rule distribution, HTML
reporting, reusable CI, WASM, predicate/Reporter stabilization and more
languages.  In this project the first P3 batch became performance attribution
and a coverage gate; both are already implemented and are checked here too.

Like p2_loop.py, this script only checks.  It never modifies the repository.

Usage:
    python3 scripts/p3_loop.py                 # one pass over all gates
    python3 scripts/p3_loop.py --gate wasm     # one gate only
    python3 scripts/p3_loop.py --rounds 3      # re-evaluate up to 3 times
    python3 scripts/p3_loop.py --watch         # re-run when source files change
    python3 scripts/p3_loop.py --json          # machine-readable result

Exit code is 0 only when every selected gate passes.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from p2_loop import (  # type: ignore
    ROOT,
    SAST,
    check_s6_predicates as check_predicates,
    check_verify,
    evaluate,
    read,
)

GITHUB = ROOT.parent / ".github"
RULEPACK = SAST / "rulepacks" / "official"

WATCH_SUFFIXES = {".mbt", ".json", ".py", ".sh", ".md", ".yml", ".yaml"}
IGNORED_PARTS = {"_build", ".mooncakes", ".git"}


def check_perf_coverage() -> tuple[bool, str]:
    missing: list[str] = []
    if not (ROOT.parent / "P3_性能与覆盖率.md").exists():
        missing.append("P3_性能与覆盖率.md")
    verify = read(SAST / "scripts" / "verify.sh")
    if "check_coverage.py" not in verify:
        missing.append("verify.sh coverage gate")
    cli = read(SAST / "apps" / "scan" / "main.mbt")
    if "--fast-cache" not in cli:
        missing.append("CLI --fast-cache")
    if not (SAST / "scripts" / "scan_by_lang.py").exists():
        missing.append("scripts/scan_by_lang.py")
    if missing:
        return False, "; ".join(missing)
    return True, "perf attribution, coverage gate, fast-cache and sharding present"


def check_lint() -> tuple[bool, str]:
    exe = SAST / "apps" / "rules-validate"
    verify = read(SAST / "scripts" / "verify.sh")
    missing: list[str] = []
    if not exe.exists():
        missing.append("apps/rules-validate")
    if "check_rules_validate.sh" not in verify:
        missing.append("verify.sh rules-validate step")
    if missing:
        return False, "; ".join(missing)
    return True, "rules-validate wired into verify.sh"


def check_reporter() -> tuple[bool, str]:
    text = read(SAST / "libs" / "report" / "reporter.mbt")
    if "pub(open) trait Reporter" not in text:
        return False, "Reporter trait missing"
    reporters = ["ConsoleReporter", "JsonReporter", "JunitReporter", "SarifReporter"]
    missing = [name for name in reporters if name not in text]
    if missing:
        return False, "reporters missing: " + ", ".join(missing)
    return True, "Reporter trait with four built-in reporters"


def check_mooncakes() -> tuple[bool, str]:
    module = RULEPACK / "moon.mod"
    if not module.exists():
        return False, "rulepacks/official/moon.mod missing (not publishable)"
    text = read(module)
    if not re.search(r'(?m)^\s*version\s*=', text):
        return False, "rulepack module has no version field"
    return True, "versioned rulepack module present"


def check_html() -> tuple[bool, str]:
    renderer = SAST / "libs" / "report" / "html.mbt"
    cli = read(SAST / "apps" / "scan" / "main.mbt")
    missing: list[str] = []
    if not renderer.exists():
        missing.append("libs/report/html.mbt")
    if "html" not in cli:
        missing.append("--format html")
    if missing:
        return False, "; ".join(missing)
    return True, "HTML reporter present and registered"


def check_action() -> tuple[bool, str]:
    candidates = [
        GITHUB / "actions" / "lunashield" / "action.yml",
        GITHUB / "actions" / "lunashield" / "action.yaml",
        ROOT.parent / "action.yml",
        ROOT.parent / "action.yaml",
    ]
    found = [path for path in candidates if path.exists()]
    if not found:
        return False, "no reusable GitHub Action manifest"
    return True, "reusable action: " + str(found[0].relative_to(ROOT.parent))


def check_wasm() -> tuple[bool, str]:
    missing: list[str] = []
    verify = read(SAST / "scripts" / "verify.sh")
    if "--target wasm" not in verify and "wasm" not in read(SAST / "moon.work"):
        missing.append("no WASM gate in verify.sh / moon.work")
    if not (SAST / "_build" / "wasm").exists():
        missing.append("no WASM build artifact")
    if missing:
        return False, "; ".join(missing)
    return True, "WASM target verified"


def check_languages() -> tuple[bool, str]:
    text = read(SAST / "libs" / "lang-registry" / "registry.mbt")
    expected = ["csharp", "go", "rust", "php"]
    missing = [name for name in expected if f'"{name}"' not in text]
    if missing:
        return False, "languages not registered: " + ", ".join(missing)
    return True, "C#/Go/Rust/PHP fixture grammars registered"


@dataclass(frozen=True)
class Gate:
    id: str
    title: str
    check: Callable[[], tuple[bool, str]]


GATES = [
    Gate("perf", "Performance and coverage gate", check_perf_coverage),
    Gate("lint", "Rule lint / rules-validate", check_lint),
    Gate("reporter", "Reporter trait stability", check_reporter),
    Gate("predicates", "Extended predicates", check_predicates),
    Gate("mooncakes", "Rulepack distribution", check_mooncakes),
    Gate("html", "HTML report", check_html),
    Gate("action", "Reusable GitHub Action", check_action),
    Gate("wasm", "WASM target verification", check_wasm),
    Gate("languages", "C#/Go/Rust/PHP expansion", check_languages),
    Gate("verify", "Full verify gate", check_verify),
]


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

    print(f"== P3 LOOP round {round_no} ==")
    for result in results:
        status = "PASS" if result["pass"] else "OPEN"
        print(f"[{status}] {result['gate']}: {result['detail']}")
    # A passing subset must not be reported as the whole phase being done.
    label = "P3" if len(results) == len(GATES) else "SELECTED GATES"
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
        GITHUB,
        ROOT.parent / "P3_性能与覆盖率.md",
    ]
    for base in bases:
        if base.is_file():
            paths = [base]
        elif base.exists():
            paths = [path for path in base.rglob("*") if path.is_file()]
        else:
            paths = []
        for path in paths:
            if path.suffix not in WATCH_SUFFIXES:
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
