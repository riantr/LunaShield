#!/usr/bin/env python3
"""M5 golden check: run the shipped CLI over tests/fixtures and compare each
rule's positive/negative findings against its expected.json.

Reports the two hard metrics from the MVP plan (§8.3):
    detection rate  = rules whose positive fixture is detected / rules   (>= 90%)
    false positive  = findings on negative fixtures / negative files     (<= 10%)

Exits non-zero on any mismatch so CI fails on regressions, not just on the
aggregate thresholds.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
PACK = ROOT / "rulepacks" / "official"
EXE = ROOT / "_build" / "native" / "debug" / "build" / "sast" / "scan" / "scan.exe"

DETECTION_MIN = 0.90
FP_MAX = 0.10


def run_scan(out_dir: Path) -> dict:
    cmd = [
        str(EXE),
        str(FIXTURES),
        "--rules",
        str(PACK),
        "--format",
        "json",
        "--out",
        str(out_dir),
        "--fail-on",
        "never",
        "--max-concurrency",
        "4",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit("scan.exe failed with exit %d" % proc.returncode)
    return json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))


def main() -> int:
    if not EXE.exists():
        raise SystemExit("missing %s — run `moon build --target native apps/scan`" % EXE)

    tmp = Path(tempfile.mkdtemp(prefix="golden-"))
    report = run_scan(tmp)
    findings = report["findings"]

    rules = sorted(p for p in FIXTURES.iterdir() if p.is_dir() and (p / "expected.json").exists())
    detected = 0
    false_positives = 0
    problems = []
    for rule_dir in rules:
        expected = json.loads((rule_dir / "expected.json").read_text(encoding="utf-8"))
        rid = expected["rule_id"]
        pos_path = next(rule_dir.glob("positive.*")).name
        neg_path = next(rule_dir.glob("negative.*")).name

        def hits(name):
            prefix = "%s/%s" % (rid, name)
            return [f for f in findings if f["rule_id"] == rid and f["primary"]["path"] == prefix]

        pos_hits = hits(pos_path)
        neg_hits = hits(neg_path)
        false_positives += len(neg_hits)

        if len(pos_hits) == expected["positive_findings"]:
            detected += 1
            got_lines = [f["primary"]["line"] for f in pos_hits]
            if got_lines != expected["positive_lines"]:
                problems.append(
                    "%s: positive lines %s, expected %s" % (rid, got_lines, expected["positive_lines"])
                )
        else:
            problems.append(
                "%s: detected %d, expected %d" % (rid, len(pos_hits), expected["positive_findings"])
            )
        if len(neg_hits) != expected["negative_findings"]:
            problems.append(
                "%s: negative hits %d, expected %d (%s)"
                % (rid, len(neg_hits), expected["negative_findings"], neg_hits[0]["primary"]["path"])
            )

    total = len(rules)
    detection = detected / total if total else 0.0
    fp_rate = false_positives / total if total else 0.0
    print("golden: %d rules, detection %.1f%%, false-positive %.1f%%" % (total, detection * 100, fp_rate * 100))
    print("golden: stats %s" % json.dumps(report["stats"], sort_keys=True))
    for problem in problems:
        print("  MISMATCH %s" % problem)

    ok = not problems and detection >= DETECTION_MIN and fp_rate <= FP_MAX
    print("GOLDEN CHECK %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
