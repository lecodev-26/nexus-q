#!/usr/bin/env python3
"""Generate report.json for one fuzz-soak campaign result directory.

Hardened contract: this script must never fail before the artifact
upload step. Every input is validated, problems are recorded in the
report's "warnings" array (with nulls for unavailable fields), the
report is written atomically, and the process exits 0 even on internal
errors.

Outcome classification is evidence-based, keyed off libFuzzer's
documented artifact naming (crash-*, timeout-*, oom-*, leak-*):
  - no exit_status.txt            -> "interrupted"
  - exit status 0                 -> "completed"
  - non-zero exit + issue artifact -> "crash" (kinds in issue_kinds)
  - non-zero exit, no issue artifact -> "failed"

A crash is never classified from file presence alone; a missing or
partial report.json inside an uploaded artifact means finalization did
not run (runner terminated), which "finalization" distinguishes from a
normally finished campaign ("completed").

Inputs come from the result directory (written by the campaign step)
and the runner environment (GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT,
GITHUB_JOB, GITHUB_SHA, RUNNER_OS, RUNNER_ARCH).
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKFLOW = "fuzz-soak.yml"
ISSUE_PREFIXES = ("crash", "timeout", "oom", "leak")
STAT_RE = re.compile(r"^stat::([a-z0-9_]+):\s*(\S+)")
MAX_TOTAL_TIME_SECONDS = 14400
UNIT_TIMEOUT_SECONDS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_optional(path: Path, warnings: list[str], label: str) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip() or None
    except OSError:
        warnings.append(f"{label}: missing or unreadable ({path})")
        return None


def parse_int(raw: str | None, warnings: list[str], label: str) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        warnings.append(f"{label}: unparseable integer {raw!r}")
        return None


def env_int(name: str, warnings: list[str]) -> int | None:
    raw = os.environ.get(name)
    if raw is None:
        warnings.append(f"{name}: not set")
        return None
    return parse_int(raw, warnings, name)


def tool_version(cmd: list[str], warnings: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        version = out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        version = ""
    if not version:
        warnings.append(f"tool version unavailable: {' '.join(cmd)}")
        return None
    return version


def coerce_stat(raw: str) -> int | float | str:
    try:
        return int(raw)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            return raw


def base_report(target: str, log_file: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "run_timestamp": None,
        "completed_at": utc_now(),
        "duration_seconds": None,
        "workflow": WORKFLOW,
        "workflow_run_id": None,
        "workflow_run_attempt": None,
        "job": os.environ.get("GITHUB_JOB"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "target": target,
        "command": None,
        "exit_status": None,
        "outcome": "interrupted",
        "issue_kinds": [],
        "classification_evidence": "report generation failed before classification",
        "crash_reproducers": [],
        "log_file": log_file,
        "fuzzer_stats": {},
        "config": {
            "max_total_time_seconds": MAX_TOTAL_TIME_SECONDS,
            "unit_timeout_seconds": UNIT_TIMEOUT_SECONDS,
            "log_cap_bytes": None,
            "rustc_version": None,
            "cargo_fuzz_version": None,
        },
        "finalization": "completed",
        "warnings": [],
    }


def build_report(
    results_dir: Path, target: str, log_file: str, log_cap_bytes: int
) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    report = base_report(target, log_file)
    report["config"]["log_cap_bytes"] = log_cap_bytes

    report["workflow_run_id"] = env_int("GITHUB_RUN_ID", warnings)
    report["workflow_run_attempt"] = env_int("GITHUB_RUN_ATTEMPT", warnings)
    if not os.environ.get("GITHUB_JOB"):
        warnings.append("GITHUB_JOB: not set")
    if not os.environ.get("GITHUB_SHA"):
        warnings.append("GITHUB_SHA: not set")

    report["run_timestamp"] = read_optional(
        results_dir / "started_at.txt", warnings, "run_timestamp"
    )
    report["command"] = read_optional(
        results_dir / "command.txt", warnings, "command"
    )
    report["exit_status"] = parse_int(
        read_optional(results_dir / "exit_status.txt", warnings, "exit_status"),
        warnings,
        "exit_status",
    )

    if report["run_timestamp"] is not None:
        try:
            started = datetime.strptime(
                report["run_timestamp"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            report["duration_seconds"] = int(
                (datetime.now(timezone.utc) - started).total_seconds()
            )
        except ValueError:
            warnings.append(
                f"run_timestamp: unparseable value {report['run_timestamp']!r}"
            )

    artifact_names: list[str] = []
    try:
        artifact_names = sorted(
            p.name for p in (results_dir / "artifacts").iterdir() if p.is_file()
        )
    except OSError:
        warnings.append(f"artifacts: directory missing ({results_dir / 'artifacts'})")
    report["crash_reproducers"] = ["artifacts/" + n for n in artifact_names]
    report["issue_kinds"] = sorted(
        {
            n.split("-", 1)[0]
            for n in artifact_names
            if n.split("-", 1)[0] in ISSUE_PREFIXES
        }
    )

    log_path = results_dir / log_file
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                match = STAT_RE.match(line)
                if not match:
                    continue
                report["fuzzer_stats"][match.group(1)] = coerce_stat(match.group(2))
    except OSError:
        warnings.append(f"fuzzer_stats: log missing ({log_path})")

    report["config"]["rustc_version"] = tool_version(["rustc", "--version"], warnings)
    report["config"]["cargo_fuzz_version"] = tool_version(
        ["cargo", "fuzz", "--version"], warnings
    )

    exit_status = report["exit_status"]
    listed = f"artifacts=[{', '.join(artifact_names)}]"
    if exit_status is None:
        report["outcome"] = "interrupted"
        report["classification_evidence"] = (
            f"exit_status=unavailable, {listed}, rule=missing_exit_status"
        )
    elif exit_status == 0:
        report["outcome"] = "completed"
        report["classification_evidence"] = (
            f"exit_status=0, {listed}, rule=zero_exit"
        )
    elif report["issue_kinds"]:
        report["outcome"] = "crash"
        kinds = "_".join(report["issue_kinds"])
        report["classification_evidence"] = (
            f"exit_status={exit_status}, {listed}, "
            f"rule=nonzero_exit_with_{kinds}_artifact"
        )
    else:
        report["outcome"] = "failed"
        report["classification_evidence"] = (
            f"exit_status={exit_status}, {listed}, "
            "rule=nonzero_exit_without_issue_artifact"
        )

    return report, warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a hardened report.json for one fuzz-soak campaign."
    )
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--log-file", default="logs/libfuzzer.log")
    parser.add_argument("--log-cap-bytes", type=int, default=10485760)
    args = parser.parse_args()

    warnings: list[str] = []
    try:
        args.results_dir.mkdir(parents=True, exist_ok=True)
        report, warnings = build_report(
            args.results_dir, args.target, args.log_file, args.log_cap_bytes
        )
    except Exception as exc:  # never fail before the artifact upload
        warnings.append(f"internal error while building report: {exc!r}")
        report = base_report(args.target, args.log_file)
        report["classification_evidence"] = (
            "report generation failed before classification"
        )

    report["warnings"] = warnings
    report_path = args.results_dir / "report.json"
    tmp_path = args.results_dir / "report.json.tmp"
    try:
        tmp_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp_path, report_path)
        print(f"wrote {report_path}")
    except OSError as exc:
        print(f"error: could not write {report_path}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
