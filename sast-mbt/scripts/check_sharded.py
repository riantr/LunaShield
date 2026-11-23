#!/usr/bin/env python3
"""Regression guard for the sharded scan: merged output must be byte-identical
to a single-process scan over the same tree.

Covers the parts that are easy to get wrong when merging:
  - ignored files (reported by every shard)
  - unregistered-language files (reported by every shard)
  - cross-language files (reported as skipped by all but their own shard)
  - findings order / dedupe / stats
Runs the comparison for taint off, report and strict.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "_build/native/debug/build/sast/scan/scan.exe"
PACK = ROOT / "rulepacks/official"
FIXTURES = ROOT / "tests/fixtures"
SHARD_SCRIPT = ROOT / "scripts/scan_by_lang.py"
SHARD_SCRIPT_SH = ROOT / "scripts/scan_by_lang.sh"
PY = sys.executable


def build_corpus(tmp: Path) -> Path:
    corpus = tmp / "corpus"
    shutil.copytree(FIXTURES, corpus)
    # No extension: skipped as unregistered-language by every shard.
    (corpus / "README.md").write_text("# fixture corpus\n", encoding="utf-8")
    # Ignored by config: skipped as ignored by every shard.
    (corpus / ".sastignore").write_text("CFG010/positive.json\n", encoding="utf-8")
    return corpus


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def compare(corpus: Path, tmp: Path, taint: str, tag: str, script: Path) -> bool:
    base = tmp / f"base-{tag}"
    sharded = tmp / f"sharded-{tag}"
    one = run([str(EXE), str(corpus), "--rules", str(PACK), "--format", "json",
               "--out", str(base), "--fail-on", "never", "--taint", taint])
    if one.returncode != 0:
        print(f"  {tag}: baseline scan failed\n{one.stdout}\n{one.stderr}", file=sys.stderr)
        return False
    sharded_cmd = ([PY, str(script)] if script.suffix == ".py"
                   else ["bash", str(script)])
    many = run(sharded_cmd + [str(corpus), "--out", str(sharded),
                              "--rules", str(PACK), "--taint", taint])
    if many.returncode != 0:
        print(f"  {tag}: sharded scan failed\n{many.stdout}\n{many.stderr}", file=sys.stderr)
        return False

    a = (base / "findings.json").read_bytes()
    b = (sharded / "findings.json").read_bytes()
    if a != b:
        ja, jb = json.loads(a), json.loads(b)
        print(f"  {tag}: MISMATCH stats={ja['stats']} vs {jb['stats']} "
              f"findings={len(ja['findings'])} vs {len(jb['findings'])} "
              f"skipped={len(ja['skipped_files'])} vs {len(jb['skipped_files'])}")
        return False
    report = json.loads(a)
    print(f"  {tag}: byte-identical ({len(report['findings'])} findings, "
          f"{len(report['skipped_files'])} skipped)")
    return True


def main() -> int:
    if not EXE.exists():
        raise SystemExit(f"missing {EXE}; run `moon build --target native apps/scan`")
    tmp = Path(tempfile.mkdtemp(prefix="ls-sharded-"))
    corpus = build_corpus(tmp)
    ok = True
    for taint in ("off", "report", "strict"):
        ok = compare(corpus, tmp, taint, f"py-{taint}", SHARD_SCRIPT) and ok
    # The bash wrapper is a portability fallback; one mode is enough to guard
    # that its merge inputs stay in sync with the Python orchestrator.
    ok = compare(corpus, tmp, "off", "sh", SHARD_SCRIPT_SH) and ok

    # The official pack declares every positive fixture as a sink and supplies
    # a source for it, so strict must not prune any of them. Pin that contract:
    # a future edit that drops a source would otherwise still pass the
    # byte-identity checks above (off/report/strict would all just agree).
    off_report = json.loads((tmp / "base-py-off" / "findings.json").read_text(encoding="utf-8"))
    strict_report = json.loads((tmp / "base-py-strict" / "findings.json").read_text(encoding="utf-8"))
    off_ids = {f["primary"]["path"] for f in off_report["findings"]}
    strict_ids = {f["primary"]["path"] for f in strict_report["findings"]}
    missing = sorted(off_ids - strict_ids)
    if missing:
        print(f"  strict pruned declared positives: {missing}")
        ok = False
    else:
        print(f"  strict keeps all {len(off_ids)} positive findings (no taint pruning)")

    print("SHARDED CHECK %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
