#!/usr/bin/env python3
"""Generate a CycloneDX SBOM from Cargo.lock, including dependency relationships."""

import argparse
import hashlib
import json
import os
import re
import tomllib
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

REPOSITORY = "https://github.com/lecodev-26/nexus-q"


def dependency_parts(value: str) -> tuple[str, str | None, str | None]:
    match = re.fullmatch(r"([^\s]+)(?:\s+([^\s(]+))?(?:\s+\(([^)]+)\))?", value)
    if not match:
        raise ValueError(f"unrecognized Cargo.lock dependency entry: {value!r}")
    return match.group(1), match.group(2), match.group(3)


def package_purl(package: dict, duplicate_name_versions: set[tuple[str, str]]) -> str:
    name = package["name"]
    version = package["version"]
    purl = f"pkg:cargo/{quote(name, safe='._-')}@{quote(version, safe='.+-~')}"
    if (name, version) in duplicate_name_versions:
        source = package.get("source") or "workspace-path"
        purl += f"?source={quote(source, safe='')}"
    return purl


def generate(lockfile: Path, manifest: Path, output: Path, commit: str, ref: str) -> dict:
    lock_bytes = lockfile.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    with manifest.open("rb") as stream:
        cargo_manifest = tomllib.load(stream)
    root_info = cargo_manifest.get("package") or cargo_manifest.get("workspace", {}).get("package")
    if not root_info or not root_info.get("version"):
        raise ValueError("root Cargo.toml must declare a package/workspace version")
    # The root is a virtual workspace; its public metacrate is the `nexusq` member.
    root_name = root_info.get("name") or "nexusq"
    root_version = root_info["version"]

    packages = lock.get("package", [])
    if not packages:
        raise ValueError("Cargo.lock has no package entries")
    key_to_package = {}
    name_version_counts = Counter((p["name"], p["version"]) for p in packages)
    duplicates = {key for key, count in name_version_counts.items() if count > 1}
    refs = {}
    for package in packages:
        key = (package["name"], package["version"], package.get("source"))
        if key in key_to_package:
            raise ValueError(f"duplicate Cargo.lock package identity: {key}")
        key_to_package[key] = package
        refs[key] = package_purl(package, duplicates)

    root_key = (root_name, root_version, None)
    if root_key not in key_to_package:
        raise ValueError(f"root package {root_name} {root_version} is missing from Cargo.lock")

    def resolve_dependency(value: str) -> str:
        name, version, source = dependency_parts(value)
        candidates = [
            key for key in key_to_package
            if key[0] == name and (version is None or key[1] == version)
            and (source is None or key[2] == source)
        ]
        if len(candidates) != 1:
            raise ValueError(f"cannot uniquely resolve Cargo.lock dependency {value!r}: {candidates}")
        return refs[candidates[0]]

    components = []
    dependency_nodes = []
    for key, package in key_to_package.items():
        bom_ref = refs[key]
        component = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": package["name"],
            "version": package["version"],
            "purl": bom_ref,
        }
        if package.get("checksum"):
            component["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
        if key != root_key:
            components.append(component)
        dependencies = sorted({resolve_dependency(dep) for dep in package.get("dependencies", [])})
        dependency_nodes.append({"ref": bom_ref, "dependsOn": dependencies})

    root_ref = refs[root_key]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPOSITORY}@{commit}:{hashlib.sha256(lock_bytes).hexdigest()}")),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": root_name,
                "version": root_version,
                "purl": root_ref,
            },
            "properties": [
                {"name": "nexusq:source-repository", "value": REPOSITORY},
                {"name": "nexusq:source-commit", "value": commit},
                {"name": "nexusq:source-ref", "value": ref},
                {"name": "nexusq:sbom-scope", "value": "Cargo.lock inventory including locked optional and target-specific dependencies; not a per-platform compiled-file manifest"},
                {"name": "nexusq:cargo-lock-sha256", "value": hashlib.sha256(lock_bytes).hexdigest()},
            ],
        },
        "components": sorted(components, key=lambda c: (c["name"], c["version"], c["bom-ref"])),
        "dependencies": sorted(dependency_nodes, key=lambda d: d["ref"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    return bom


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", "unknown"))
    args = parser.parse_args()
    bom = generate(args.lockfile, args.manifest, args.output, args.commit, args.ref)
    print(f"Generated {args.output}: {len(bom['components']) + 1} packages, {len(bom['dependencies'])} dependency nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
