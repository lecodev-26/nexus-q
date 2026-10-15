#!/usr/bin/env python3
"""Enforce the NEXUS-Q kernel unsafe-code review boundary in CI."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
UNSAFE_CODE = re.compile(
    r"\bunsafe\s*(?:\{|fn\b|impl\b|extern\b|trait\b|static\b|union\b)"
)


def rust_sources(directory: Path):
    return sorted(directory.rglob("*.rs"))


def main() -> int:
    errors: list[str] = []
    kernel_root = ROOT / "crates/nexusq-kernels/src"
    core_root = ROOT / "crates/nexusq-core/src"

    for source in rust_sources(kernel_root):
        lines = source.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not UNSAFE_CODE.search(line):
                continue
            start = max(0, index - 5)
            context = "\n".join(lines[start : index + 1])
            if "// SAFETY:" not in context:
                errors.append(
                    f"{source.relative_to(ROOT)}:{index + 1}: unsafe code lacks a nearby // SAFETY: justification"
                )

    for source in rust_sources(core_root):
        lines = source.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if UNSAFE_CODE.search(line):
                errors.append(
                    f"{source.relative_to(ROOT)}:{index + 1}: unsafe code is forbidden in nexusq-core"
                )

    if errors:
        print("Kernel unsafe-code policy failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Kernel unsafe-code policy passed: kernel unsafe sites require SAFETY comments; nexusq-core remains safe-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
