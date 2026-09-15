#!/usr/bin/env python3
"""Validate RULE-001 execution task metadata in IMPLEMENTATION_PLAN.md."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "docs" / "IMPLEMENTATION_PLAN.md"
VALID_STATUSES = {"[x]", "[~]", "[ ]"}
TASK_REGISTRY_HEADER = "| Task ID |"
SECTION_6_HEADING = re.compile(r"^##\s+6\.\s+", re.MULTILINE)
SECTION_7_HEADING = re.compile(r"^##\s+7\.\s+", re.MULTILINE)
TASK_ENTRY = re.compile(
    r"^(?P<id>\d+)\.\s+(?P<status>\[[ x~]\])\s+(?P<title>.+?)\s+—",
    re.MULTILINE,
)
ISSUE_OR_PR = re.compile(r"(?:\[#\d+\]\(https://github\.com/[^)]+\)|TBD)$")
REFERENCE_NUMBER = re.compile(r"\[#(?P<number>\d+)\]\(https://github\.com/[^)]+\)")
TASK_ENTRY_REFERENCES = re.compile(
    r"\bissue\s+#(?P<issue>\d+),\s+PR\s+#(?P<pr>\d+)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RegistryRow:
    task_id: int
    status: str
    title: str
    description: str
    issue: str
    pr: str

    @property
    def issue_number(self) -> str | None:
        return reference_number(self.issue)

    @property
    def pr_number(self) -> str | None:
        return reference_number(self.pr)


@dataclass(frozen=True)
class TaskEntry:
    task_id: int
    status: str
    title: str
    issue_number: str | None
    pr_number: str | None


def reference_number(value: str) -> str | None:
    if value == "TBD":
        return None
    match = REFERENCE_NUMBER.fullmatch(value)
    if match is None:
        return None
    return match.group("number")


def table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def normalize_status(value: str) -> str:
    return value.strip().strip("`")


def extract_registry_rows(content: str) -> list[RegistryRow]:
    lines = content.splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if line.startswith(TASK_REGISTRY_HEADER)),
        None,
    )
    if header_index is None:
        raise ValueError("task metadata registry table is missing")

    rows: list[RegistryRow] = []
    for line_number, line in enumerate(lines[header_index + 2 :], start=header_index + 3):
        if not line.startswith("|"):
            break
        cells = table_cells(line)
        if len(cells) != 6:
            raise ValueError(f"registry row at line {line_number} must have 6 columns")

        raw_task_id, raw_status, title, description, issue, pr = cells
        try:
            task_id = int(raw_task_id)
        except ValueError as error:
            raise ValueError(f"registry row at line {line_number} has invalid Task ID") from error

        status = normalize_status(raw_status)
        if status not in VALID_STATUSES:
            raise ValueError(f"registry task {task_id} has invalid status {raw_status!r}")
        for label, value in (
            ("title", title),
            ("description", description),
            ("issue", issue),
            ("PR", pr),
        ):
            if value in {"", "-", "—"}:
                raise ValueError(f"registry task {task_id} has empty {label}")
        if ISSUE_OR_PR.fullmatch(issue) is None:
            raise ValueError(f"registry task {task_id} has invalid issue reference {issue!r}")
        if ISSUE_OR_PR.fullmatch(pr) is None:
            raise ValueError(f"registry task {task_id} has invalid PR reference {pr!r}")

        rows.append(
            RegistryRow(
                task_id=task_id,
                status=status,
                title=title,
                description=description,
                issue=issue,
                pr=pr,
            )
        )

    if not rows:
        raise ValueError("task metadata registry has no task rows")

    seen: set[int] = set()
    duplicates = sorted({row.task_id for row in rows if row.task_id in seen or seen.add(row.task_id)})
    if duplicates:
        raise ValueError(f"duplicate registry Task ID(s): {duplicates}")

    return rows


def extract_section_6(content: str) -> str:
    start = SECTION_6_HEADING.search(content)
    end = SECTION_7_HEADING.search(content)
    if start is None or end is None or end.start() <= start.end():
        raise ValueError("could not isolate IMPLEMENTATION_PLAN section 6")
    return content[start.end() : end.start()]


def extract_task_entries(content: str) -> dict[int, TaskEntry]:
    entries: dict[int, TaskEntry] = {}
    section = extract_section_6(content)
    for match in TASK_ENTRY.finditer(section):
        task_id = int(match.group("id"))
        if task_id in entries:
            raise ValueError(f"duplicate numbered task entry {task_id}")
        line_end = section.find("\n", match.start())
        line = section[match.start() :] if line_end == -1 else section[match.start() : line_end]
        references = TASK_ENTRY_REFERENCES.search(line)
        entries[task_id] = TaskEntry(
            task_id=task_id,
            status=match.group("status"),
            title=match.group("title").strip(),
            issue_number=references.group("issue") if references is not None else None,
            pr_number=references.group("pr") if references is not None else None,
        )
    return entries


def validate_content(content: str) -> tuple[int, int]:
    rows = extract_registry_rows(content)
    entries = extract_task_entries(content)
    registry_ids = {row.task_id for row in rows}
    first_registry_id = min(registry_ids)
    uncovered_entries = sorted(
        task_id for task_id in entries if task_id >= first_registry_id and task_id not in registry_ids
    )
    if uncovered_entries:
        raise ValueError(f"numbered task entries missing from registry: {uncovered_entries}")

    for row in rows:
        entry = entries.get(row.task_id)
        if entry is None:
            raise ValueError(f"registry task {row.task_id} has no numbered task entry")
        if entry.status != row.status:
            raise ValueError(
                f"task {row.task_id} status mismatch: registry={row.status} entry={entry.status}"
            )
        if entry.title != row.title:
            raise ValueError(
                f"task {row.task_id} title mismatch: registry={row.title!r} entry={entry.title!r}"
            )
        if row.issue_number is None:
            raise ValueError(f"registry task {row.task_id} issue is still TBD")
        if row.pr_number is None:
            raise ValueError(f"registry task {row.task_id} PR is still TBD")
        if entry.issue_number is None or entry.pr_number is None:
            raise ValueError(f"numbered task entry {row.task_id} is missing issue/PR references")
        if entry.issue_number != row.issue_number:
            raise ValueError(
                f"task {row.task_id} issue mismatch: registry=#{row.issue_number} "
                f"entry=#{entry.issue_number}"
            )
        if entry.pr_number != row.pr_number:
            raise ValueError(
                f"task {row.task_id} PR mismatch: registry=#{row.pr_number} entry=#{entry.pr_number}"
            )
    return len(rows), len(entries)


def run_self_test() -> None:
    valid = """# Plan

| Task ID | Статус | Title | Description | Issue | PR |
|---|---|---|---|---|---|
| 64 | `[x]` | Good task | Has scope. | [#98](https://github.com/org/repo/issues/98) | [#99](https://github.com/org/repo/pull/99) |

## 6. Task log

64. [x] Good task — issue #98, PR #99:
    Has scope.

## 7. Dependencies
"""
    validate_content(valid)

    cases = {
        "missing-entry": valid.replace("64. [x] Good task", "65. [x] Good task"),
        "missing-registry-row": valid.replace(
            "| 64 | `[x]` | Good task | Has scope. | [#98](https://github.com/org/repo/issues/98) | [#99](https://github.com/org/repo/pull/99) |\n",
            "",
        ),
        "status-mismatch": valid.replace("64. [x] Good task", "64. [ ] Good task"),
        "wrong-pr": valid.replace(
            "[#99](https://github.com/org/repo/pull/99)",
            "[#9999](https://github.com/org/repo/pull/9999)",
            1,
        ),
        "missing-pr": valid.replace("[#99](https://github.com/org/repo/pull/99)", ""),
        "duplicate-row": valid.replace(
            "| 64 | `[x]` | Good task | Has scope. | [#98](https://github.com/org/repo/issues/98) | [#99](https://github.com/org/repo/pull/99) |",
            "| 64 | `[x]` | Good task | Has scope. | [#98](https://github.com/org/repo/issues/98) | [#99](https://github.com/org/repo/pull/99) |\n| 64 | `[x]` | Other task | Has scope. | [#98](https://github.com/org/repo/issues/98) | [#99](https://github.com/org/repo/pull/99) |",
        ),
    }
    for name, content in cases.items():
        try:
            validate_content(content)
        except ValueError:
            continue
        raise AssertionError(f"self-test case {name!r} unexpectedly passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=DEFAULT_PLAN, type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            run_self_test()
        registry_count, entry_count = validate_content(args.plan.read_text(encoding="utf-8"))
    except (OSError, AssertionError, ValueError) as error:
        print(f"execution task metadata validation failed: {error}", file=sys.stderr)
        return 1

    print(
        f"task_registry_rows={registry_count} numbered_task_entries={entry_count} validation=ok"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
