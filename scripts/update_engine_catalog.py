#!/usr/bin/env python3
"""Build a reviewable, offline engine-catalog candidate from explicit release assets.

This tool is for maintainers. It never runs in NovaRay's runtime path and never
changes the checked-in catalog in place: `--output` must name a new candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_asset(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "NovaRay-catalog-updater/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def binary_from_archive(name: str, content: bytes, binary_path: str) -> bytes:
    if name.endswith(".zip"):
        with zipfile.ZipFile(__import__("io").BytesIO(content)) as archive:
            return archive.read(binary_path)
    if name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=__import__("io").BytesIO(content), mode="r:gz") as archive:
            member = archive.getmember(binary_path)
            if not member.isfile():
                raise ValueError(f"{binary_path} is not a regular file")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot extract {binary_path}")
            return extracted.read()
    raise ValueError(f"unsupported archive type: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--assets-file", type=Path, required=True,
                        help="JSON list: target_os, target_arch, url, archive_sha256, binary_path")
    parser.add_argument("--engine", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--status", choices=("recommended", "supported", "deprecated", "yanked"), required=True)
    parser.add_argument("--replace-recommended", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    args = parser.parse_args()

    if args.output.resolve() == args.catalog.resolve():
        parser.error("--output must be a new review candidate, not --catalog")
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    assets = json.loads(args.assets_file.read_text(encoding="utf-8"))
    declared = {(item["target_os"], item["target_arch"]) for item in catalog["declared_targets"]}
    seen = set()
    candidate = []
    evidence = []
    for asset in assets:
        target = (asset["target_os"], asset["target_arch"])
        if target not in declared or target in seen:
            raise ValueError(f"invalid or duplicate target: {target[0]}/{target[1]}")
        seen.add(target)
        archive = fetch_asset(asset["url"])
        actual_archive = sha256_bytes(archive)
        if actual_archive != asset["archive_sha256"]:
            raise ValueError(f"archive hash mismatch for {asset['url']}: {actual_archive}")
        archive_name = Path(urllib.parse.urlparse(asset["url"]).path).name
        binary = binary_from_archive(archive_name, archive, asset["binary_path"])
        binary_sha256 = sha256_bytes(binary)
        candidate.append({
            "engine_name": args.engine, "version": args.version, "revision": args.revision,
            "status": args.status, "target_os": target[0], "target_arch": target[1],
            "archive_name": archive_name, "archive_sha256": actual_archive,
            "binary_sha256": binary_sha256,
        })
        evidence.append((target, archive_name, actual_archive, asset["binary_path"], binary_sha256))
    if seen != declared:
        raise ValueError("assets-file must cover every declared target")
    if any(item["engine_name"] == args.engine and item["version"] == args.version for item in catalog["releases"]):
        raise ValueError("catalog already contains this engine/version")
    if args.status == "recommended":
        existing = [item for item in catalog["releases"] if item["engine_name"] == args.engine and item["status"] == "recommended"]
        if existing and not args.replace_recommended:
            raise ValueError("changing the default requires --replace-recommended and a dedicated review")
        for item in existing:
            item["status"] = "supported"
    catalog["releases"].extend(candidate)
    args.output.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    lines = ["# Candidate engine artifact evidence", "", f"Engine: `{args.engine}` `{args.version}` ({args.status})", "", "| Target | Archive | Archive SHA-256 | Binary path | Binary SHA-256 |", "|---|---|---|---|---|"]
    lines.extend(f"| {os}/{arch} | `{name}` | `{archive}` | `{path}` | `{binary}` |" for (os, arch), name, archive, path, binary in evidence)
    lines.extend(["", "Generated by `scripts/update_engine_catalog.py`; review the candidate catalog and evidence before copying either into the repository."])
    args.evidence_output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
