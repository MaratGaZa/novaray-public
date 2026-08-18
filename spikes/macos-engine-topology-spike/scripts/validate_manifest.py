#!/usr/bin/env python3
"""Validate the offline evidence contract for the macOS engine topology spike."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


MANIFEST = Path(__file__).resolve().parents[1] / "engine-evidence.json"
EXPECTED_ENGINES = {"xray-core", "sing-box"}
EXPECTED_TOPOLOGIES = {
    "helper-owned-subprocess",
    "host-app-subprocess",
    "network-system-extension-embedded",
    "network-system-extension-subprocess",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
TASK_REFERENCE = re.compile(r"^development-task-[1-9][0-9]*$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_https(url: str, label: str) -> None:
    parsed = urlparse(url)
    require(parsed.scheme == "https" and bool(parsed.netloc), f"{label} must be an HTTPS URL")


def validate() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))

    require(data.get("schema_version") == 1, "schema_version must be 1")
    require(data.get("status") == "evidence-only", "status must remain evidence-only")
    require(data.get("selected_engine") is None, "this spike must not select an engine")
    require(
        TASK_REFERENCE.fullmatch(data["task_reference"]) is not None,
        "task_reference must be a sanitized development-task-N identifier",
    )

    candidates = data.get("candidates", [])
    require({candidate.get("id") for candidate in candidates} == EXPECTED_ENGINES, "candidate set drifted")
    for candidate in candidates:
        engine_id = candidate["id"]
        require(REVISION.fullmatch(candidate["revision"]) is not None, f"{engine_id}: invalid revision")
        require(candidate["release"].startswith("v"), f"{engine_id}: release must be pinned")
        require_https(candidate["upstream"], f"{engine_id}: upstream")

        license_data = candidate["license"]
        require(bool(license_data["upstream_declaration"]), f"{engine_id}: missing license declaration")
        require(license_data["legal_review_complete"] is False, f"{engine_id}: legal review must remain open")

        artifact = candidate["macos_arm64_artifact"]
        require_https(artifact["url"], f"{engine_id}: artifact")
        require(SHA256.fullmatch(artifact["sha256"]) is not None, f"{engine_id}: invalid SHA-256")
        require(artifact["downloaded_or_executed_in_this_spike"] is False, f"{engine_id}: execution claim drifted")

        for field in ("build_path", "config_validation", "readiness", "logging", "graceful_stop"):
            require(bool(candidate["subprocess"].get(field)), f"{engine_id}: missing subprocess.{field}")
        require(candidate["embedding"]["api_stability_guaranteed"] is False, f"{engine_id}: API stability claim drifted")
        require(len(candidate["embedding"]["constraints"]) >= 3, f"{engine_id}: embedding gaps are incomplete")
        require(len(candidate["sources"]) >= 4, f"{engine_id}: insufficient primary sources")
        for index, source in enumerate(candidate["sources"]):
            require_https(source, f"{engine_id}: source[{index}]")

    topologies = data.get("topologies", [])
    require({topology.get("id") for topology in topologies} == EXPECTED_TOPOLOGIES, "topology set drifted")
    for topology in topologies:
        require(topology.get("status") in {"plausible", "unverified"}, f"{topology.get('id')}: invalid status")
        require(bool(topology.get("remaining_gate")), f"{topology.get('id')}: missing gate")

    gates = data.get("gates", {})
    require(gates and all(value is False for value in gates.values()), "no production gate may be closed by this spike")
    for index, source in enumerate(data.get("apple_sources", [])):
        require_https(source, f"apple_sources[{index}]")


def main() -> int:
    try:
        validate()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"engine evidence validation failed: {error}", file=sys.stderr)
        return 1
    print(f"engine evidence validation OK: {MANIFEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
