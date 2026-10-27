#!/usr/bin/env python3
"""Generate and verify NEXUS-Q release provenance, manifest and SHA256SUMS.

The release directory must already contain every payload, including native
runtime assets and SBOM. This script does not publish, attest, or create tags.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get("RELEASE_DIRECTORY", "release"))
VERSION = os.environ.get("RELEASE_VERSION", "")
COMMIT = os.environ.get("RELEASE_SHA") or os.environ.get("GITHUB_SHA", "")
REF = os.environ.get("RELEASE_REF") or os.environ.get("GITHUB_REF", "")
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")
WORKFLOW = os.environ.get("GITHUB_WORKFLOW", "")
STATUS = "Audit-Ready Release. No production-readiness claim, no FIPS validation, external audit pending."
PROVENANCE_NAME = f"nexusq-v{VERSION}-provenance.json"
MANIFEST_NAME = "release-manifest.json"
SUMS_NAME = "SHA256SUMS"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def regular_files() -> list[Path]:
    return sorted(path for path in ROOT.iterdir() if path.is_file())


def main() -> None:
    if not VERSION or not COMMIT or not REPOSITORY or not REF:
        raise SystemExit("RELEASE_VERSION, commit (RELEASE_SHA/GITHUB_SHA), GITHUB_REPOSITORY and ref are required")
    if not ROOT.is_dir():
        raise SystemExit(f"release directory does not exist: {ROOT}")
    files = regular_files()
    if not files:
        raise SystemExit("release directory has no payload files")

    excluded = {PROVENANCE_NAME, MANIFEST_NAME, SUMS_NAME}
    payload = [path for path in files if path.name not in excluded]
    if not payload:
        raise SystemExit("release directory has no payload after excluding generated evidence")

    provenance = {
        "schema": "nexusq-release-provenance-v1",
        "release": VERSION,
        "commit": COMMIT,
        "repository": REPOSITORY,
        "ref": REF,
        "workflow": WORKFLOW,
        "runner": os.environ.get("RUNNER_OS", "local-or-unspecified"),
        "artifact_checksums": [
            {"name": path.name, "sha256": digest(path), "size_bytes": path.stat().st_size}
            for path in payload
        ],
        "status": STATUS,
        "external_audit": "pending",
        "production_readiness_claimed": False,
        "fips_validation_claimed": False,
    }
    (ROOT / PROVENANCE_NAME).write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    manifest_payload = [path for path in regular_files() if path.name not in {MANIFEST_NAME, SUMS_NAME}]
    manifest = {
        "schema": "nexusq-release-manifest-v1",
        "version": VERSION,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "ref": REF,
        "status": STATUS,
        "assets": [
            {"name": path.name, "size_bytes": path.stat().st_size, "sha256": digest(path)}
            for path in manifest_payload
        ],
        "manifest_self_reference": "release-manifest.json is covered by SHA256SUMS, but excluded from its own assets list",
        "checksum_coverage": "SHA256SUMS covers every regular file in release/ except SHA256SUMS itself",
    }
    (ROOT / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    checksum_files = [path for path in regular_files() if path.name != SUMS_NAME]
    (ROOT / SUMS_NAME).write_text(
        "".join(f"{digest(path)}  {path.name}\n" for path in checksum_files), encoding="utf-8"
    )

    expected = [path.name for path in checksum_files]
    lines = (ROOT / SUMS_NAME).read_text(encoding="utf-8").splitlines()
    listed = [line.split("  ", 1)[1] for line in lines]
    if listed != expected or len(listed) != len(set(listed)):
        raise SystemExit(f"SHA256SUMS coverage mismatch: expected={expected}, listed={listed}")
    for line in lines:
        expected_digest, name = line.split("  ", 1)
        if digest(ROOT / name) != expected_digest:
            raise SystemExit(f"SHA-256 verification failed for {name}")
    saved_manifest = json.loads((ROOT / MANIFEST_NAME).read_text(encoding="utf-8"))
    if saved_manifest["commit"] != COMMIT or saved_manifest["version"] != VERSION:
        raise SystemExit("release manifest commit/version mismatch")
    print(f"Generated provenance and manifest for {VERSION} at {COMMIT}; SHA256SUMS covers {len(listed)} files.")


if __name__ == "__main__":
    main()
