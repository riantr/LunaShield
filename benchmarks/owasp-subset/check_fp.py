#!/usr/bin/env python3
"""Measure false positives on the local OWASP-style subset.

P1 is the AST-only policy (`--taint off`); P2 is the taint-aware policy
(`--taint strict`). Both scans use the same official rule pack and the same
corpus, so the only difference is the P2 analysis gate under test.

The script writes benchmarks/owasp-subset/report.json without timestamps so
the result is reviewable in git. Exits non-zero when P2 is not strictly better
than P1 or exceeds the 10% FP threshold from the plan.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent.parent / "sast-mbt"
PACK = ROOT / "rulepacks" / "official"
EXE = ROOT / "_build" / "native" / "debug" / "build" / "sast" / "scan" / "scan.exe"
FP_MAX = 0.10


def scan(tmp: Path, mode: str) -> dict:
    out = tmp / mode
    proc = subprocess.run(
        [
            str(EXE),
            str(BENCH),
            "--rules",
            str(PACK),
            "--taint",
            mode,
            "--format",
            "json",
            "--out",
            str(out),
            "--fail-on",
            "never",
            "--max-concurrency",
            "1",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"scan --taint {mode} failed with exit {proc.returncode}")
    return json.loads((out / "findings.json").read_text(encoding="utf-8"))


def main() -> int:
    if not EXE.exists():
        raise SystemExit(f"missing {EXE} — run `moon build --target native apps/scan`")

    safe = sorted((BENCH / "safe").glob("*.js"))
    vulnerable = sorted((BENCH / "vulnerable").glob("*.js"))
    if not safe or not vulnerable:
        raise SystemExit("benchmark corpus is empty")

    with tempfile.TemporaryDirectory(prefix="lunashield-fp-") as name:
        tmp = Path(name)
        p1 = scan(tmp, "off")
        p2 = scan(tmp, "strict")

    def on(files: list[Path], report: dict) -> list[dict]:
        names = {str(p.relative_to(BENCH)).replace("\\", "/") for p in files}
        return [
            f for f in report["findings"] if f["primary"]["path"] in names
        ]

    p1_fp = on(safe, p1)
    p2_fp = on(safe, p2)
    p1_tp = on(vulnerable, p1)
    p2_tp = on(vulnerable, p2)
    rate_p1 = len(p1_fp) / len(safe)
    rate_p2 = len(p2_fp) / len(safe)

    report = {
        "corpus": "owasp-subset",
        "p1_policy": "AST-only (--taint off)",
        "p2_policy": "AST + taint strict (--taint strict)",
        "safe_files": len(safe),
        "vulnerable_files": len(vulnerable),
        "p1_false_positives": len(p1_fp),
        "p2_false_positives": len(p2_fp),
        "p1_false_positive_rate": round(rate_p1, 4),
        "false_positive_rate": round(rate_p2, 4),
        "p1_true_positives": len(p1_tp),
        "p2_true_positives": len(p2_tp),
    }
    (BENCH / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(
        "benchmark: P1 FP {p1} -> P2 FP {p2} "
        "(safe {s}, vulnerable {v}, detection {d1}/{d2})".format(
            p1=report["p1_false_positive_rate"],
            p2=report["false_positive_rate"],
            s=len(safe),
            v=len(vulnerable),
            d1=len(p1_tp),
            d2=len(p2_tp),
        )
    )
    ok = rate_p2 <= FP_MAX and rate_p2 < rate_p1
    print("BENCHMARK CHECK " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
