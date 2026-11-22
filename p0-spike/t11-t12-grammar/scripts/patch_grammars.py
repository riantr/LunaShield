#!/usr/bin/env python3
"""Idempotent compatibility patch for moonbit-community tree-sitter grammars.

Problem
-------
moonc >= 0.10.20 no longer promotes `impl` methods into method-call syntax
unless explicitly promoted via `extend`. Every `moonbit-community/tree-sitter-*`
grammar module is emitted by the same generator (tools/grammars/update.sh),
which writes this line in `binding.mbt`:

    e => abort(e.to_string())

Under the current compiler it fails with:

    Type ...CompactError has no method to_string.
    (hint: did you mean `Show::to_string`?)

Scope (verified 2026-11-22, moonc v0.10.21+06da1ed44)
-----------------------------------------------------
All five MVP grammars are affected, one occurrence each:
    tree-sitter-javascript@0.25.0  binding.mbt:29
    tree-sitter-typescript@0.23.2  binding.mbt:41
    tree-sitter-python@0.23.6      binding.mbt:29
    tree-sitter-java@0.23.5        binding.mbt:27
    tree-sitter-json@0.24.8        binding.mbt:27

Why in-place on .mooncakes
--------------------------
`moon.work` local-source override was evaluated and REJECTED: in workspace
mode moon compiles every package of the `treesitter` dependency, which
surfaces additional genuine errors in its CLI subpackages (Fd type mismatch,
regex_syntax ErrorKind, OsString). Global rewriting of `.to_string()` is not
safe -- the treesitter tree contains 321 occurrences, most of them valid.

Patching the single generated line in each grammar binding is therefore the
minimal, exact fix. `.mooncakes` is a download cache, so this script must run
after every `moon add` / CI checkout and before `moon check|build|test`.

Usage
-----
    python3 scripts/patch_grammars.py                 # apply to current project
    python3 scripts/patch_grammars.py --root <dir>    # apply to given project
    python3 scripts/patch_grammars.py --check         # CI gate, no writes

Dependencies are discovered from the project's moon.mod, so any project using
moonbit-community grammar modules can share this one script.

Exit codes: 0 = all discovered grammars compatible, 1 = missing/unpatched line.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BROKEN = "e.to_string()"
FIXED = "Show::to_string(e)"
GRAMMAR_RE = re.compile(r'moonbit-community/(tree-sitter-[\w-]+)')

DEFAULT_ROOT = Path(__file__).resolve().parent.parent


def discover(root: Path) -> list[str]:
    """Find grammar modules declared in moon.mod (deduplicated, sorted)."""
    manifest = root / "moon.mod"
    if not manifest.is_file():
        raise FileNotFoundError(f"no moon.mod in {root}")
    names = sorted(set(GRAMMAR_RE.findall(manifest.read_text(encoding="utf-8"))))
    # treesitter is the runtime, not a generated grammar binding.
    return [n for n in names if n != "treesitter"]


def patch_binding(path: Path, root: Path, check_only: bool):
    """Return (applied, already_fixed, problems) for one binding.mbt."""
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

    # Neither form present means upstream changed the generator: require a
    # human decision rather than pretending the patch applied.
    if already == 0 and applied == 0 and not check_only:
        problems.append(
            f"{path.relative_to(root)}: neither `{BROKEN}` nor `{FIXED}` found; "
            "upstream generator changed, re-verify compatibility"
        )
    return applied, already, problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT,
                    help="project root containing moon.mod (default: parent of scripts/)")
    ap.add_argument("--check", action="store_true", help="verify only; fail if unpatched")
    ap.add_argument("--quiet", action="store_true", help="only print the final status")
    args = ap.parse_args()

    root = args.root.resolve()
    cache = root / ".mooncakes" / "moonbit-community"

    try:
        grammars = discover(root)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not grammars:
        print(f"ERROR: no moonbit-community grammars declared in {root / 'moon.mod'}",
              file=sys.stderr)
        return 1

    problems: list[str] = []
    mode = "CHECK" if args.check else "PATCH"
    total_applied = total_fixed = 0

    for name in grammars:
        binding = cache / name / "binding.mbt"
        applied, already, found = patch_binding(binding, root, args.check)
        problems.extend(found)
        total_applied += applied
        total_fixed += already
        if not args.quiet:
            print(f"[{mode}] {name}: fixed={already} applied={applied}")

    if problems:
        print("\nFAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        if args.check:
            print(f"  hint: run `python3 {Path(__file__).name} --root {root}` first",
                  file=sys.stderr)
        return 1

    print(f"OK: {len(grammars)} grammar(s) compatible with current moonc "
          f"(fixed={total_fixed}, applied={total_applied})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
