#!/usr/bin/env python3
"""Fail closed unless a maintainer explicitly approves this exact release commit."""

import os
import re
import subprocess
import sys

REPOSITORY_URLS = {
    "git@github.com:lecodev-26/nexus-q.git",
    "https://github.com/lecodev-26/nexus-q.git",
    "https://github.com/lecodev-26/nexus-q",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


def verify(version: str) -> None:
    if os.environ.get("NEXUSQ_RELEASE_IDENTITY_APPROVED") != "true":
        raise SystemExit(
            "release blocked: set NEXUSQ_RELEASE_IDENTITY_APPROVED=true only after the "
            "release identity has been reviewed and approved"
        )

    expected = os.environ.get("NEXUSQ_APPROVED_RELEASE_COMMIT", "").lower()
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise SystemExit(
            "release blocked: NEXUSQ_APPROVED_RELEASE_COMMIT must contain the approved full 40-character commit SHA"
        )

    try:
        remote = git("remote", "get-url", "origin")
        head = git("rev-parse", "HEAD^{commit}")
        tag = git("rev-parse", f"refs/tags/v{version}^{{commit}}")
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() if exc.stderr else str(exc)
        raise SystemExit(f"release blocked: cannot verify repository/tag identity: {detail}") from exc

    if remote not in REPOSITORY_URLS:
        raise SystemExit(f"release blocked: unexpected origin remote {remote!r}")

    dirty = git("status", "--porcelain", "--untracked-files=all")
    if dirty:
        raise SystemExit("release blocked: working tree is not clean; commit or remove all local changes first")

    if head != expected:
        raise SystemExit(f"release blocked: HEAD {head} does not equal approved commit {expected}")
    if tag != expected:
        raise SystemExit(f"release blocked: v{version} resolves to {tag}, not approved commit {expected}")

    print(f"Release identity gate passed: v{version} at approved commit {expected}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} VERSION")
    verify(sys.argv[1])
