#!/usr/bin/env python3
"""Validate the public native-right readiness template remains non-authorizing."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE = ROOT / "docs" / "native-right-readiness.template.json"
FORMAT = "novaray-native-right-readiness-v1"
PURPOSE = "TEMPLATE_ONLY_NOT_APPROVAL"
REAL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
REAL_SHA256 = re.compile(r"^[0-9a-f]{64}$")
GENERATED_TEST_RIGHT = re.compile(r"^org\.novaray\.validation\.runtime-right\.[0-9a-f]{32}$")
REQUIRED_TOP_LEVEL = {
    "format",
    "purpose",
    "environment",
    "restore",
    "writer_control",
    "binary_review",
    "run_boundary",
    "operator_notes",
}


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def validate_template(data: Any) -> None:
    root = require_object(data, "template")
    keys = set(root)
    if keys != REQUIRED_TOP_LEVEL:
        missing = sorted(REQUIRED_TOP_LEVEL - keys)
        unknown = sorted(keys - REQUIRED_TOP_LEVEL)
        raise ValueError(f"top-level keys mismatch: missing={missing} unknown={unknown}")

    if root["format"] != FORMAT:
        raise ValueError("format mismatch")
    if root["purpose"] != PURPOSE:
        raise ValueError("purpose must mark the file as template-only")

    environment = require_object(root["environment"], "environment")
    if require_bool(environment.get("disposable"), "environment.disposable"):
        raise ValueError("public template must not claim a disposable environment")
    if require_bool(
        environment.get("current_machine_is_disposable"),
        "environment.current_machine_is_disposable",
    ):
        raise ValueError("public template must not bless the current machine")
    require_string(environment.get("reference"), "environment.reference")
    require_string(environment.get("os_build"), "environment.os_build")
    require_string(environment.get("hardware"), "environment.hardware")

    restore = require_object(root["restore"], "restore")
    if require_bool(restore.get("restore_tested"), "restore.restore_tested"):
        raise ValueError("public template must not claim restore evidence")
    require_string(restore.get("evidence_reference"), "restore.evidence_reference")
    require_string(restore.get("restore_method"), "restore.restore_method")

    writer_control = require_object(root["writer_control"], "writer_control")
    if require_bool(writer_control.get("exclusive_writers"), "writer_control.exclusive_writers"):
        raise ValueError("public template must not claim exclusive writer control")
    require_string(writer_control.get("scope"), "writer_control.scope")

    binary_review = require_object(root["binary_review"], "binary_review")
    reviewed_commit = require_string(binary_review.get("reviewed_commit"), "binary_review.reviewed_commit")
    reviewed_sha256 = require_string(binary_review.get("reviewed_sha256"), "binary_review.reviewed_sha256")
    if REAL_COMMIT.fullmatch(reviewed_commit):
        raise ValueError("public template must not contain a real-looking reviewed commit")
    if REAL_SHA256.fullmatch(reviewed_sha256):
        raise ValueError("public template must not contain a real-looking reviewed SHA-256")
    require_string(binary_review.get("sdk"), "binary_review.sdk")

    run_boundary = require_object(root["run_boundary"], "run_boundary")
    if run_boundary.get("allowed_command") != "--preflight-only":
        raise ValueError("public template must only allow --preflight")
    if require_bool(
        run_boundary.get("allow_authorization_interaction"),
        "run_boundary.allow_authorization_interaction",
    ):
        raise ValueError("public template must not allow authorization interaction")
    generated_test_name = require_string(
        run_boundary.get("generated_test_name"),
        "run_boundary.generated_test_name",
    )
    if GENERATED_TEST_RIGHT.fullmatch(generated_test_name):
        raise ValueError("public template must not contain a generated test right name")
    if run_boundary.get("confirmation") != "NOT A RUN APPROVAL":
        raise ValueError("confirmation must remain non-authorizing")

    operator_notes = require_object(root["operator_notes"], "operator_notes")
    if not require_bool(operator_notes.get("no_secrets"), "operator_notes.no_secrets"):
        raise ValueError("operator_notes.no_secrets must stay true")
    if not require_bool(operator_notes.get("private_copy_only"), "operator_notes.private_copy_only"):
        raise ValueError("operator_notes.private_copy_only must stay true")
    if not require_bool(
        operator_notes.get("do_not_commit_completed_evidence"),
        "operator_notes.do_not_commit_completed_evidence",
    ):
        raise ValueError("operator_notes.do_not_commit_completed_evidence must stay true")


def run_self_test() -> None:
    valid = {
        "format": FORMAT,
        "purpose": PURPOSE,
        "environment": {
            "reference": "PRIVATE-ENVIRONMENT-REFERENCE",
            "disposable": False,
            "os_build": "DISPLAYED-BUILD",
            "hardware": "APPLE-SILICON-DISPOSABLE-MAC-OR-VM",
            "current_machine_is_disposable": False,
        },
        "restore": {
            "evidence_reference": "PRIVATE-RESTORE-DRILL-REFERENCE",
            "restore_tested": False,
            "restore_method": "SNAPSHOT-OR-REIMAGE-METHOD",
        },
        "writer_control": {
            "exclusive_writers": False,
            "scope": "AUTHORIZATION-DATABASE-WRITERS-CONTROLLED-FOR-ONE-RUN",
        },
        "binary_review": {
            "reviewed_commit": "40-lowercase-hex-placeholder",
            "reviewed_sha256": "64-lowercase-hex-placeholder",
            "sdk": "REVIEWED-SDK-TOOLCHAIN",
        },
        "run_boundary": {
            "allowed_command": "--preflight-only",
            "allow_authorization_interaction": False,
            "generated_test_name": "GENERATED-BY-RUNNER-DO-NOT-PREFILL",
            "confirmation": "NOT A RUN APPROVAL",
        },
        "operator_notes": {
            "no_secrets": True,
            "private_copy_only": True,
            "do_not_commit_completed_evidence": True,
        },
    }
    validate_template(valid)

    cases: dict[str, Any] = {
        "missing-key": {key: value for key, value in valid.items() if key != "restore"},
        "approved-run": {**valid, "run_boundary": {**valid["run_boundary"], "confirmation": "CREATE READ REMOVE NAME 120"}},
        "authorization-allowed": {
            **valid,
            "run_boundary": {**valid["run_boundary"], "allow_authorization_interaction": True},
        },
        "real-commit": {
            **valid,
            "binary_review": {**valid["binary_review"], "reviewed_commit": "a" * 40},
        },
        "real-sha": {
            **valid,
            "binary_review": {**valid["binary_review"], "reviewed_sha256": "b" * 64},
        },
        "generated-test-name": {
            **valid,
            "run_boundary": {
                **valid["run_boundary"],
                "generated_test_name": "org.novaray.validation.runtime-right." + "c" * 32,
            },
        },
        "disposable-claim": {**valid, "environment": {**valid["environment"], "disposable": True}},
        "restore-claim": {**valid, "restore": {**valid["restore"], "restore_tested": True}},
        "writers-claim": {
            **valid,
            "writer_control": {**valid["writer_control"], "exclusive_writers": True},
        },
    }
    for name, candidate in cases.items():
        try:
            validate_template(candidate)
        except ValueError:
            continue
        raise AssertionError(f"self-test case {name!r} unexpectedly passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            run_self_test()
        data = json.loads(args.template.read_text(encoding="utf-8"))
        validate_template(data)
    except (OSError, AssertionError, ValueError, json.JSONDecodeError) as error:
        print(f"native right readiness template validation failed: {error}", file=sys.stderr)
        return 1

    print(f"native_right_readiness_template={args.template} validation=ok non_authorizing=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
