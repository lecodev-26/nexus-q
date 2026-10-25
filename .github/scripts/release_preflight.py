#!/usr/bin/env python3
"""Read-only registry/version preflight. Never publishes or approves a release."""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

REPO = "lecodev-26/nexus-q"
USER_AGENT = "nexus-q-release-preflight (read-only; github.com/lecodev-26/nexus-q)"
CRATES = [
    "nexusq-kernels", "nexusq-ml-kem", "nexusq-ml-dsa", "nexusq-native-backend",
    "nexusq-ha", "nexusq-core", "nexusq-c", "nexusq-py", "nexusq-cli",
    "nexusq-server", "nexusq-x509", "nexusq-ocsp", "nexusq-enrollment",
    "nexusq-hsm", "nexusq-tsa", "nexusq-admin", "nexusq-pki-cluster", "nexusq",
]

@dataclass
class Result:
    destination: str
    state: str  # present, absent, mismatch, unknown
    detail: str


def get_json(url: str) -> tuple[int, Any | None, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            raw = response.read().decode("utf-8")
            try:
                return response.status, json.loads(raw), ""
            except (json.JSONDecodeError, UnicodeDecodeError):
                return response.status, None, "response was not valid JSON"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None, "not found"
        return exc.code, None, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, None, str(exc)


def version_result(name: str, url: str, version: str, *, check: str = "exists") -> Result:
    status, data, error = get_json(url)
    if status == 404:
        return Result(name, "absent", f"{version} not found")
    if status != 200 or data is None:
        return Result(name, "unknown", error or f"unexpected HTTP {status}")
    if check == "maven":
        try:
            docs = data["response"]["docs"]
            if not isinstance(docs, list):
                raise ValueError("response.docs is not a list")
            exact = any(isinstance(item, dict) and item.get("v") == version for item in docs)
        except (KeyError, TypeError, ValueError):
            return Result(name, "unknown", "unexpected Maven Central response schema")
        return Result(name, "present" if exact else "absent", "exact version listed" if exact else "exact version not listed")
    if check == "pypi":
        if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
            return Result(name, "unknown", "unexpected PyPI response schema")
        actual = data["info"].get("version")
        return Result(name, "present" if actual == version else "mismatch", f"API reports version {actual!r}")
    if check == "nuget":
        if not isinstance(data, dict) or not isinstance(data.get("versions"), list) or not all(isinstance(v, str) for v in data["versions"]):
            return Result(name, "unknown", "unexpected NuGet version-index schema")
        exact = version.lower() in [v.lower() for v in data["versions"]]
        return Result(name, "present" if exact else "absent", "exact version listed" if exact else "exact version not listed")
    if check == "packagist":
        try:
            packages = data["packages"]["lecodev-26/nexusq"]
            exact = any(isinstance(item, dict) and item.get("version", "").lstrip("v") == version for item in packages)
        except (KeyError, TypeError):
            return Result(name, "unknown", "unexpected Packagist response schema")
        return Result(name, "present" if exact else "absent", "exact version listed" if exact else "exact version not listed")
    return Result(name, "present", "version endpoint returned HTTP 200; content identity not verified")


def github_ref(ref: str) -> Result:
    status, data, error = get_json(f"https://api.github.com/repos/{REPO}/git/ref/tags/{ref}")
    if status == 404:
        return Result(f"Git tag {ref}", "absent", "tag ref not found")
    if status != 200 or not isinstance(data, dict):
        return Result(f"Git tag {ref}", "unknown", error or "unexpected GitHub ref response")
    obj = data.get("object")
    if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str):
        return Result(f"Git tag {ref}", "unknown", "missing object SHA")
    sha, kind = obj["sha"], obj.get("type")
    if kind == "tag":
        tag_status, tag_data, tag_error = get_json(f"https://api.github.com/repos/{REPO}/git/tags/{sha}")
        if tag_status != 200 or not isinstance(tag_data, dict) or not isinstance(tag_data.get("object"), dict):
            return Result(f"Git tag {ref}", "unknown", tag_error or "could not dereference annotated tag")
        sha = tag_data["object"].get("sha", "")
    if not isinstance(sha, str) or len(sha) != 40:
        return Result(f"Git tag {ref}", "unknown", "could not resolve tag to a commit SHA")
    return Result(f"Git tag {ref}", "present", f"resolves to {sha}")


def inspect(version: str) -> list[Result]:
    out: list[Result] = []
    # GitHub release and both tag spellings are separate identities.
    status, data, error = get_json(f"https://api.github.com/repos/{REPO}/releases/tags/v{version}")
    if status == 404:
        out.append(Result(f"GitHub Release v{version}", "absent", "release not found"))
    elif status != 200 or not isinstance(data, dict):
        out.append(Result(f"GitHub Release v{version}", "unknown", error or "unexpected release response"))
    else:
        out.append(Result(f"GitHub Release v{version}", "present", f"published={not data.get('draft', True)}, prerelease={bool(data.get('prerelease'))}; assets={len(data.get('assets', [])) if isinstance(data.get('assets'), list) else 'unknown'}"))
    tag_results = [github_ref(version), github_ref(f"v{version}")]
    out.extend(tag_results)
    if all(item.state == "present" for item in tag_results):
        bare_sha = tag_results[0].detail.removeprefix("resolves to ")
        v_sha = tag_results[1].detail.removeprefix("resolves to ")
        if bare_sha != v_sha:
            out.append(Result("Tag identity comparison", "mismatch", f"{version} -> {bare_sha}; v{version} -> {v_sha}"))
        else:
            out.append(Result("Tag identity comparison", "present", f"both tags resolve to {bare_sha}"))
    else:
        out.append(Result("Tag identity comparison", "unknown", "one or both tags could not be resolved"))

    for crate in CRATES:
        crate_version = version
        try:
            with open(f"crates/{crate}/Cargo.toml", "rb") as f:
                manifest = tomllib.load(f)["package"]
            if isinstance(manifest.get("version"), str):
                crate_version = manifest["version"]
        except (OSError, KeyError, tomllib.TOMLDecodeError):
            # The native backend is maintained outside the workspace's crate directory.
            if crate == "nexusq-native-backend":
                try:
                    with open("crates/nexusq-native-backend/Cargo.toml", "rb") as f:
                        crate_version = tomllib.load(f)["package"]["version"]
                except (OSError, KeyError, tomllib.TOMLDecodeError):
                    out.append(Result(f"crates.io {crate}", "unknown", "could not read package version from manifest"))
                    continue
            else:
                out.append(Result(f"crates.io {crate}", "unknown", "could not read package version from manifest"))
                continue
        out.append(version_result(f"crates.io {crate} v{crate_version}", f"https://crates.io/api/v1/crates/{crate}/{crate_version}", crate_version))
    out.append(version_result("PyPI nexusq", f"https://pypi.org/pypi/nexusq/{version}/json", version, check="pypi"))
    out.append(version_result("npm nexusq", f"https://registry.npmjs.org/nexusq/{version}", version))
    out.append(version_result("RubyGems nexusq", f"https://rubygems.org/api/v2/rubygems/nexusq/versions/{version}.json", version))
    out.append(version_result("pub.dev nexusq", f"https://pub.dev/api/packages/nexusq/versions/{version}", version))
    out.append(version_result("NuGet nexusq", "https://api.nuget.org/v3-flatcontainer/nexusq/index.json", version, check="nuget"))
    out.append(version_result("Packagist lecodev-26/nexusq", "https://repo.packagist.org/p2/lecodev-26/nexusq.json", version, check="packagist"))
    for artifact in ("nexusq", "nexusq-kotlin"):
        url = ("https://search.maven.org/solrsearch/select?q=g:%22io.github.lecodev-26%22%20AND%20a:%22"
               + artifact + "%22%20AND%20v:%22" + version + "%22&rows=20&wt=json")
        out.append(version_result(f"Maven Central {artifact}", url, version, check="maven"))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="version to inspect (defaults to workspace Cargo.toml)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    try:
        with open("Cargo.toml", "rb") as f:
            workspace_version = tomllib.load(f)["workspace"]["package"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"error: cannot read workspace version from Cargo.toml: {exc}", file=sys.stderr)
        return 2
    version = args.version or workspace_version
    if version != workspace_version:
        print(f"error: requested version {version} differs from workspace version {workspace_version}; run from the intended source checkout", file=sys.stderr)
        return 2
    results = inspect(version)
    if args.json:
        print(json.dumps({"version": version, "read_only": True, "results": [asdict(item) for item in results]}, indent=2))
    else:
        print(f"NEXUS-Q v{version} — READ-ONLY PUBLICATION PREFLIGHT")
        print("No registry writes, credentials, builds, or release approvals are performed.\n")
        for item in results:
            print(f"[{item.state.upper():8}] {item.destination}: {item.detail}")
        counts = {state: sum(item.state == state for item in results) for state in ("present", "absent", "mismatch", "unknown")}
        print(f"\nSummary: {counts}")
        print("This is an inventory aid, not publication authorization; HTTP presence does not prove artifact bytes match the approved source.")
    return 0 if all(item.state not in ("unknown", "mismatch") for item in results) else 1

if __name__ == "__main__":
    raise SystemExit(main())
