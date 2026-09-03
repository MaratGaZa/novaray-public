#!/usr/bin/env python3
"""Validate FR/NFR identifier parity and canonical traceability coverage."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC_RU = ROOT / "docs" / "SPEC_RU.md"
SPEC_EN = ROOT / "docs" / "SPEC_EN.md"
TRACEABILITY = ROOT / "docs" / "TRACEABILITY.md"
EXPECTED_IDS = {f"FR-{index:03}" for index in range(1, 12)} | {
    f"NFR-{index:03}" for index in range(1, 6)
}
ALLOWED_STATES = {"implemented", "partial", "missing", "contradicted", "unverified"}
REQUIREMENT_HEADING = re.compile(r"^###\s+((?:FR|NFR)-\d{3})(?:\s|[.\-—])", re.MULTILINE)
REQUIREMENT_ID = re.compile(r"^(?:FR|NFR)-\d{3}$")
PLACEHOLDERS = {"", "-", "—", "tbd", "todo"}


def extract_requirement_ids(path: Path) -> list[str]:
    return REQUIREMENT_HEADING.findall(path.read_text(encoding="utf-8"))


def require_unique_expected(label: str, identifiers: list[str]) -> None:
    duplicates = sorted(
        {identifier for identifier in identifiers if identifiers.count(identifier) > 1}
    )
    if duplicates:
        raise ValueError(f"{label}: duplicate requirement IDs: {', '.join(duplicates)}")

    actual = set(identifiers)
    missing = sorted(EXPECTED_IDS - actual)
    unknown = sorted(actual - EXPECTED_IDS)
    if missing or unknown:
        raise ValueError(f"{label}: missing={missing} unknown={unknown}")


def extract_traceability_rows(path: Path) -> dict[str, tuple[int, list[str]]]:
    rows: dict[str, tuple[int, list[str]]] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.startswith("|"):
            continue

        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        identifier = cells[0].strip("`") if cells else ""
        if REQUIREMENT_ID.fullmatch(identifier) is None:
            continue
        if identifier in rows:
            raise ValueError(f"traceability: duplicate row for {identifier} at line {line_number}")
        if len(cells) != 7:
            raise ValueError(
                f"traceability: {identifier} at line {line_number} must have 7 columns, got {len(cells)}"
            )

        normalized = [cell.strip().lower() for cell in cells]
        required_cells = (
            (1, "scope"),
            (2, "work"),
            (3, "verification"),
            (5, "evidence"),
            (6, "gap"),
        )
        for index, label in required_cells:
            if normalized[index] in PLACEHOLDERS:
                raise ValueError(f"traceability: {identifier} has empty {label} at line {line_number}")
        if "](" not in cells[2]:
            raise ValueError(f"traceability: {identifier} work mapping must contain a link")
        if "](" not in cells[3]:
            raise ValueError(f"traceability: {identifier} verification must contain a link")

        state = cells[4].strip("`")
        if state not in ALLOWED_STATES:
            raise ValueError(f"traceability: {identifier} has invalid state {state!r}")
        rows[identifier] = (line_number, cells)
    return rows


def validate() -> None:
    ru_ids = extract_requirement_ids(SPEC_RU)
    en_ids = extract_requirement_ids(SPEC_EN)
    require_unique_expected("SPEC_RU", ru_ids)
    require_unique_expected("SPEC_EN", en_ids)
    if set(ru_ids) != set(en_ids):
        raise ValueError("SPEC_RU and SPEC_EN requirement ID sets differ")

    rows = extract_traceability_rows(TRACEABILITY)
    actual_rows = set(rows)
    missing = sorted(EXPECTED_IDS - actual_rows)
    unknown = sorted(actual_rows - EXPECTED_IDS)
    if missing or unknown:
        raise ValueError(f"traceability rows: missing={missing} unknown={unknown}")


def main() -> int:
    try:
        validate()
    except (OSError, ValueError) as error:
        print(f"requirements traceability validation failed: {error}", file=sys.stderr)
        return 1

    print("requirements_ru=16 requirements_en=16 traceability_rows=16 validation=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
