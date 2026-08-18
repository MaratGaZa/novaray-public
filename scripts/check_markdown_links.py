#!/usr/bin/env python3
"""Fail when a repository Markdown file references a missing local path."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)\n]+)\)")
EXCLUDED_PARTS = {".git", "graphify-out", "target"}
EXTERNAL_SCHEMES = {"http", "https", "mailto", "file"}


def extract_path(raw_target: str) -> str | None:
    """Return a decoded local path without query or fragment components."""

    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None

    if target.startswith("<"):
        closing_bracket = target.find(">")
        if closing_bracket == -1:
            return target
        target = target[1:closing_bracket]
    else:
        target = target.split(maxsplit=1)[0]

    parsed = urlsplit(target)
    if parsed.scheme.lower() in EXTERNAL_SCHEMES:
        return None

    return unquote(parsed.path) or None


def find_broken_links(root: Path) -> tuple[int, list[str]]:
    """Scan Markdown files below root and return missing local references."""

    markdown_count = 0
    broken: list[str] = []

    for markdown_file in sorted(root.rglob("*.md")):
        if any(part in EXCLUDED_PARTS for part in markdown_file.parts):
            continue

        markdown_count += 1
        content = markdown_file.read_text(encoding="utf-8")
        for match in LINK_PATTERN.finditer(content):
            local_path = extract_path(match.group("target"))
            if local_path is None:
                continue

            if local_path.startswith("/"):
                candidate = root / local_path.lstrip("/")
            else:
                candidate = markdown_file.parent / local_path

            if not candidate.resolve().exists():
                relative_file = markdown_file.relative_to(root)
                broken.append(f"{relative_file}: missing local target {local_path}")

    return markdown_count, broken


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    markdown_count, broken = find_broken_links(root)

    if broken:
        print("\n".join(broken))
        print(f"checked_markdown_files={markdown_count} broken_links={len(broken)}")
        return 1

    print(f"checked_markdown_files={markdown_count} broken_links=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
