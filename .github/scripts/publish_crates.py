#!/usr/bin/env python3
"""Publish the NEXUS-Q workspace crates to crates.io in dependency order.

Skips any crate whose exact (manifest) version is already on crates.io, so
re-running the workflow only publishes new crates or versions. Expects the
CARGO_REGISTRY_TOKEN environment variable (crates.io API token) and to run
from the repository root.
"""

import os
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request

CRATES = [
    "nexusq-kernels",
    "nexusq-ml-kem",
    "nexusq-ml-dsa",
    "nexusq-native-backend",
    "nexusq-core",
    "nexusq-c",
    "nexusq-py",
    "nexusq-cli",
    "nexusq-server",
    "nexusq",
]

USER_AGENT = "nexus-q-publish-workflow (github.com/lecodev-26/nexus-q)"


def manifest_version(crate: str) -> str:
    with open(f"crates/{crate}/Cargo.toml", "rb") as f:
        pkg = tomllib.load(f)["package"]
    ver = pkg.get("version")
    if not isinstance(ver, str):  # { workspace = true } inheritance
        with open("Cargo.toml", "rb") as f:
            ver = tomllib.load(f)["workspace"]["package"]["version"]
    return ver


def published(crate: str, version: str) -> bool:
    req = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate}/{version}",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        urllib.request.urlopen(req)
        return True
    except urllib.error.HTTPError:
        return False


def main() -> int:
    if not os.environ.get("CARGO_REGISTRY_TOKEN"):
        print("error: CARGO_REGISTRY_TOKEN is not set", file=sys.stderr)
        return 1
    for crate in CRATES:
        version = manifest_version(crate)
        if published(crate, version):
            print(f"=== Skipping {crate} v{version} (already on crates.io) ===")
            continue
        print(f"=== Publishing {crate} v{version} ===")
        if crate == "nexusq-native-backend":
            command = ["cargo", "publish", "--manifest-path", "crates/nexusq-native-backend/Cargo.toml"]
        else:
            command = ["cargo", "publish", "-p", crate]
        result = subprocess.run(command)
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
