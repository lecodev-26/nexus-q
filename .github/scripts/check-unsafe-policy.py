#!/usr/bin/env python3
"""Require a nearby, site-specific SAFETY justification for project-owned Rust unsafe sites."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED_DIRECTORIES = {".git", "target", "vendor", "node_modules"}
UNSAFE_SITE = re.compile(
    r"\bunsafe\s*(?:\{|fn\b|impl\b|extern\b|trait\b|static\b|union\b)"
)
SAFETY_COMMENT = re.compile(r"//\s*SAFETY\s*:")


def rust_sources():
    for source in sorted(ROOT.rglob("*.rs")):
        relative_parts = source.relative_to(ROOT).parts
        if any(part in EXCLUDED_DIRECTORIES for part in relative_parts):
            continue
        yield source


def main() -> int:
    errors: list[str] = []
    checked_sites = 0
    files_with_unsafe: set[str] = set()

    for source in rust_sources():
        lines = source.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith(("//", "/*", "*")):
                continue
            if not UNSAFE_SITE.search(line):
                continue

            checked_sites += 1
            relative = source.relative_to(ROOT).as_posix()
            files_with_unsafe.add(relative)
            context = lines[max(0, index - 5) : index + 1]
            if not any(SAFETY_COMMENT.search(candidate) for candidate in context):
                errors.append(
                    f"{relative}:{index + 1}: unsafe site lacks a // SAFETY: justification within the preceding five lines"
                )

    if errors:
        print("NEXUS-Q unsafe-code policy failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        "NEXUS-Q unsafe-code policy passed: "
        f"{checked_sites} unsafe sites across {len(files_with_unsafe)} Rust files have nearby SAFETY justifications."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
