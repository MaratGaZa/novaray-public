#!/usr/bin/env python3
"""Resolve a safe outer-capsule artifact root without writing anything."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


MARKER = ".novaray-capsule.json"


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def fail(message: str) -> int:
    print(f"artifact-root error: {message}", file=sys.stderr)
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True, type=Path)
    args = parser.parse_args()

    project_root = args.project_root.resolve(strict=True)
    if not project_root.is_dir():
        return fail("project root is not a directory")

    markers = [parent / MARKER for parent in (project_root, *project_root.parents) if (parent / MARKER).is_file()]
    if len(markers) != 1:
        return fail(f"expected exactly one ancestor marker, found {len(markers)}")

    marker = markers[0]
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return fail(f"invalid marker: {error}")

    project_value = data.get("project_path")
    artifact_value = data.get("artifact_root")
    if not isinstance(project_value, str) or not project_value or Path(project_value).is_absolute():
        return fail("project_path must be a non-empty relative path")
    if not isinstance(artifact_value, str) or not artifact_value or Path(artifact_value).is_absolute():
        return fail("artifact_root must be a non-empty relative path")

    capsule_root = marker.parent.resolve()
    declared_project = (capsule_root / project_value).resolve()
    artifact_root = (capsule_root / artifact_value).resolve()
    if declared_project != project_root:
        return fail("marker project_path does not resolve to the current project root")
    if not is_within(artifact_root, capsule_root):
        return fail("artifact_root escapes the capsule root")
    if is_within(artifact_root, project_root):
        return fail("artifact_root resolves inside the project root")

    print(artifact_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
