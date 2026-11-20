#!/usr/bin/env python3
"""Summarize LCOV line coverage and enforce versioned NEXUS-Q thresholds."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import PurePosixPath


def parse_lcov(path: str) -> dict[str, tuple[int, int]]:
    records: dict[str, dict[int, int]] = defaultdict(dict)
    source: str | None = None
    current_lines: dict[int, int] = {}

    def finish() -> None:
        if source is not None:
            merged = records[source]
            for line_number, count in current_lines.items():
                merged[line_number] = max(merged.get(line_number, 0), count)

    with open(path, encoding="utf-8") as report:
        for raw_line in report:
            line = raw_line.strip()
            if line.startswith("SF:"):
                finish()
                source = line[3:].replace("\\", "/")
                current_lines = {}
            elif line.startswith("DA:") and source is not None:
                fields = line[3:].split(",", 2)
                if len(fields) >= 2:
                    line_number = int(fields[0])
                    current_lines[line_number] = max(current_lines.get(line_number, 0), int(fields[1]))
            elif line == "end_of_record":
                finish()
                source = None
                current_lines = {}
    finish()
    return {
        source_path: (sum(count > 0 for count in line_counts.values()), len(line_counts))
        for source_path, line_counts in records.items()
    }


def repo_source_path(path: str) -> str | None:
    normalized = PurePosixPath(path)
    parts = normalized.parts
    try:
        index = parts.index("crates")
    except ValueError:
        return None
    relative = PurePosixPath(*parts[index:]).as_posix()
    if relative.startswith("crates/nexusq-native-backend/"):
        return None
    if "/src/" not in relative or not relative.endswith(".rs"):
        return None
    if any(part in {"tests", "benches", "examples"} for part in PurePosixPath(relative).parts):
        return None
    return relative


def percentage(hit: int, found: int) -> float:
    return (100.0 * hit / found) if found else 0.0


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check-coverage.py <lcov.info> <thresholds.json>", file=sys.stderr)
        return 2

    report_path, thresholds_path = sys.argv[1:]
    raw_files = parse_lcov(report_path)
    files: dict[str, tuple[int, int]] = {}
    for path, counts in raw_files.items():
        normalized = repo_source_path(path)
        if normalized is not None:
            files[normalized] = counts

    total_hit = sum(hit for hit, _ in files.values())
    total_found = sum(found for _, found in files.values())
    module_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    thresholds = None
    try:
        with open(thresholds_path, encoding="utf-8") as config:
            thresholds = json.load(config)
    except FileNotFoundError:
        pass

    lines = [
        "# NEXUS-Q line coverage",
        "",
        f"- Production workspace Rust source: **{percentage(total_hit, total_found):.2f}%** ({total_hit}/{total_found} executable lines)",
        f"- Instrumented source files: **{len(files)}**",
        "",
        "## Critical security modules",
        "",
        "| Module | Line coverage | Covered / executable lines |",
        "|---|---:|---:|",
    ]

    configured_modules = (thresholds or {}).get("modules", {})
    for name, settings in configured_modules.items():
        prefixes = tuple(settings["path_prefixes"])
        hit = sum(value[0] for path, value in files.items() if path.startswith(prefixes))
        found = sum(value[1] for path, value in files.items() if path.startswith(prefixes))
        module_counts[name] = [hit, found]

    default_modules = {
        "vault": ("crates/nexusq-core/src/vault/",),
        "policy": ("crates/nexusq-core/src/policy/",),
        "audit_log": ("crates/nexusq-core/src/storage/audit_event.rs", "crates/nexusq-core/src/storage/audit_log.rs", "crates/nexusq-core/src/storage/audit_segment.rs"),
    }
    for name, prefixes in default_modules.items():
        if name not in module_counts:
            hit = sum(value[0] for path, value in files.items() if path.startswith(prefixes))
            found = sum(value[1] for path, value in files.items() if path.startswith(prefixes))
            module_counts[name] = [hit, found]

    for name in ("vault", "policy", "audit_log"):
        hit, found = module_counts[name]
        lines.append(f"| {name} | {percentage(hit, found):.2f}% | {hit}/{found} |")

    failures: list[str] = []
    if thresholds is None:
        lines.extend(["", "> Baseline collection only: version-controlled thresholds have not yet been set from a measured CI run."])
    else:
        global_minimum = float(thresholds["global_minimum_percent"])
        actual = percentage(total_hit, total_found)
        if actual < global_minimum:
            failures.append(f"Global coverage {actual:.2f}% is below {global_minimum:.2f}%")
        for name, settings in thresholds.get("modules", {}).items():
            hit, found = module_counts.get(name, [0, 0])
            actual = percentage(hit, found)
            minimum = float(settings["minimum_percent"])
            if found == 0:
                failures.append(f"Module {name} has no executable lines in the report")
            elif actual < minimum:
                failures.append(f"Module {name} coverage {actual:.2f}% is below {minimum:.2f}%")
        lines.extend(["", "## Enforced thresholds", "", f"- Global minimum: **{global_minimum:.2f}%**"])
        for name, settings in thresholds.get("modules", {}).items():
            lines.append(f"- {name} minimum: **{float(settings['minimum_percent']):.2f}%**")
        if failures:
            lines.extend(["", "## Threshold failures", ""])
            lines.extend(f"- {failure}" for failure in failures)
        else:
            lines.extend(["", "All configured coverage thresholds passed."])

    lines.extend([
        "",
        "## Scope and exclusions",
        "",
        "Counts executable lines in Rust source under workspace `crates/*/src/`. Excludes test, benchmark, and example directories; fuzz targets; vendored dependencies; standalone native/Arena workspaces; SDK projects outside the Rust workspace; build-script output outside the crate source tree; and documentation. These exclusions are deliberate and are not represented as covered code.",
        "",
        "Coverage is a regression signal, not evidence of cryptographic correctness, constant-time behavior, or security certification.",
    ])
    output = "\n".join(lines) + "\n"
    print(output, end="")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
