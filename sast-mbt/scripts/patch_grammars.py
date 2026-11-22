#!/usr/bin/env python3
"""Idempotent compatibility patch for moonbit-community tree-sitter grammars.

Verified against moonc v0.10.21+06da1ed44 (2026-11-22). All five MVP grammars
are emitted by the same generator, which writes `e => abort(e.to_string())`
in `binding.mbt`; moonc 0.10 no longer promotes `Show::to_string` into a
method call, so each binding needs one line changed to `Show::to_string(e)`.

Upstreamed from p0-spike/t11-t12-grammar/scripts/patch_grammars.py. Extended
to discover grammar dependencies across every module listed in moon.work,
since sast-mbt is a multi-module workspace (the P0 spike was single-module).

Usage:
    python3 scripts/patch_grammars.py                 # apply
    python3 scripts/patch_grammars.py --root <dir>    # apply to given project
    python3 scripts/patch_grammars.py --check         # CI gate, no writes

The script looks in BOTH <root>/.mooncakes (single-module layout) and each
workspace member's .mooncakes (in case moon caches dependencies per module).
Exit codes: 0 = all discovered grammars compatible, 1 = missing/unpatched.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BROKEN = "e.to_string()"
FIXED = "Show::to_string(e)"
GRAMMAR_RE = re.compile(r'moonbit-community/(tree-sitter-[\w-]+)')
MEMBER_RE = re.compile(r'"([^"\n]+)"')

DEFAULT_ROOT = Path(__file__).resolve().parent.parent


def discover(root: Path) -> tuple[list[str], list[Path]]:
    """Return (grammar names, cache dirs) from moon.mod files in the project.

    Scans the root moon.mod (if any) plus every member listed in moon.work.
    """
    manifests = [root / "moon.mod"]
    work = root / "moon.work"
    if work.is_file():
        for m in MEMBER_RE.findall(work.read_text(encoding="utf-8")):
            manifests.append(root / m / "moon.mod")

    names: set[str] = set()
    found: list[Path] = []
    for manifest in manifests:
        if not manifest.is_file():
            continue
        found.append(manifest)
        names.update(GRAMMAR_RE.findall(manifest.read_text(encoding="utf-8")))
    return sorted(names), found


def cache_dirs(root: Path, manifests: list[Path]) -> list[Path]:
    """Candidate .mooncakes/moonbit-community directories, deduplicated."""
    candidates = [root / ".mooncakes" / "moonbit-community"]
    for m in manifests:
        candidates.append(m.parent / ".mooncakes" / "moonbit-community")
    out: list[Path] = []
    for c in candidates:
        if c not in out:
            out.append(c)
    return out


def patch_binding(path: Path, root: Path, check_only: bool) -> tuple[int, int, list[str]]:
    if not path.is_file():
        return 0, 0, [f"missing: {path}"]
    lines = path.read_text(encoding="utf-8").splitlines()
    applied = already = 0
    problems: list[str] = []
    for i, line in enumerate(lines):
        if FIXED in line:
            already += 1
        if BROKEN not in line:
            continue
        if check_only:
            problems.append(f"{path.relative_to(root)}:{i + 1}: unpatched `{BROKEN}`")
        else:
            lines[i] = line.replace(BROKEN, FIXED)
            applied += 1
    if applied and not check_only:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if already == 0 and applied == 0 and not check_only:
        problems.append(
            f"{path.relative_to(root)}: neither `{BROKEN}` nor `{FIXED}`; "
            "upstream generator changed, re-verify"
        )
    return applied, already, problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    root = args.root.resolve()
    grammars, manifests = discover(root)
    if not grammars:
        print(f"ERROR: no moonbit-community grammars in {root}", file=sys.stderr)
        return 1

    caches = cache_dirs(root, manifests)
    problems: list[str] = []
    total_applied = total_fixed = 0
    mode = "CHECK" if args.check else "PATCH"

    for name in grammars:
        locations = [c / name / "binding.mbt" for c in caches
                     if (c / name / "binding.mbt").is_file()]
        if not locations:
            problems.append(f"no binding.mbt found for {name} (run moon fetch/check first)")
            if not args.quiet:
                print(f"[{mode}] {name}: NOT FETCHED")
            continue
        per_applied = per_fixed = 0
        for binding in locations:
            applied, already, issues = patch_binding(binding, root, args.check)
            problems.extend(issues)
            per_applied += applied
            per_fixed += already
        total_applied += per_applied
        total_fixed += per_fixed
        if not args.quiet:
            print(f"[{mode}] {name}: fixed={per_fixed} pending/applied={per_applied}")

    if problems:
        print("\nFAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(f"OK: {len(grammars)} grammar(s) compatible "
          f"(fixed={total_fixed}, {'pending' if args.check else 'applied'}={total_applied})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
