#!/usr/bin/env python3
"""Verify that Claude compatibility files are regular byte-for-byte mirrors."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pairs = [(root / "AGENTS.md", root / "CLAUDE.md")]
    for mirror in sorted((root / ".claude").rglob("*")):
        if mirror.is_dir():
            continue
        relative = mirror.relative_to(root / ".claude")
        pairs.append((root / ".agents" / relative, mirror))

    failures: list[str] = []
    for canonical, mirror in pairs:
        if canonical.is_symlink() or mirror.is_symlink():
            failures.append(f"symlink is forbidden: {mirror.relative_to(root)}")
            continue
        if not canonical.is_file() or not mirror.is_file():
            failures.append(f"missing regular-file pair: {canonical.relative_to(root)} -> {mirror.relative_to(root)}")
            continue
        if canonical.read_bytes() != mirror.read_bytes():
            failures.append(f"content differs: {canonical.relative_to(root)} -> {mirror.relative_to(root)}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"agent_mirror_pairs={len(pairs)} mismatches=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
