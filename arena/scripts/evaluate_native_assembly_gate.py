#!/usr/bin/env python3
"""Fail closed unless every required PQC operation meets the 1.5x median+p95 gate."""
from __future__ import annotations
import json, math, statistics, sys
from pathlib import Path

LIMIT = 1.5
EXPECTED = {(a, p, o) for a, p, ops in [
    ("ml-kem", "768", ("keygen", "encaps", "decaps")),
    ("ml-kem", "1024", ("keygen", "encaps", "decaps")),
    ("ml-dsa", "65", ("keygen", "sign", "verify")),
] for o in ops}

def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]

def read_rows(paths: list[Path], expected_id: str) -> dict[tuple[str, str, str], list[int]]:
    result: dict[tuple[str, str, str], list[int]] = {}
    for path in paths:
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip().startswith("{")]
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            impl = row.get("implementation", {}).get("id")
            if impl != expected_id:
                raise ValueError(f"{path}: expected implementation {expected_id!r}, got {impl!r}")
            algorithm = row.get("algorithm", {})
            key = (algorithm.get("id", ""), str(algorithm.get("parameter_set", "")), row.get("operation", ""))
            if key not in EXPECTED:
                continue
            if key in seen:
                raise ValueError(f"{path}: duplicate operation row {key}")
            seen.add(key)
            samples = row.get("measurement", {}).get("samples_ns")
            if not isinstance(samples, list) or not samples or any(not isinstance(x, (int, float)) or x <= 0 for x in samples):
                raise ValueError(f"{path}: {key} lacks valid raw samples_ns")
            if len(samples) < 1000:
                raise ValueError(f"{path}: {key} has only {len(samples)} samples; minimum is 1000")
            result.setdefault(key, []).extend(int(x) for x in samples)
        if seen != EXPECTED:
            raise ValueError(f"{path}: missing required operations: {sorted(EXPECTED - seen)}")
    if set(result) != EXPECTED:
        raise ValueError(f"{expected_id}: missing operations: {sorted(EXPECTED - set(result))}")
    return result

def main() -> int:
    if len(sys.argv) < 4:
        print("usage: evaluator REPORT.json nexusq-round1.jsonl nexusq-round2.jsonl nexusq-round3.jsonl -- aws-round1.jsonl aws-round2.jsonl aws-round3.jsonl", file=sys.stderr)
        return 64
    report_path = Path(sys.argv[1])
    try:
        separator = sys.argv.index("--", 2)
    except ValueError:
        print("missing -- separator between NEXUS-Q and AWS-LC files", file=sys.stderr)
        return 64
    nexus_paths = [Path(x) for x in sys.argv[2:separator]]
    aws_paths = [Path(x) for x in sys.argv[separator + 1:]]
    if len(nexus_paths) != 3 or len(aws_paths) != 3:
        print("gate requires exactly three NEXUS-Q rounds and three AWS-LC rounds", file=sys.stderr)
        return 64
    try:
        nexus = read_rows(nexus_paths, "nexusq")
        aws = read_rows(aws_paths, "aws-lc")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BENCHMARK INPUT INVALID: {exc}", file=sys.stderr)
        return 2
    results, passed = [], True
    for key in sorted(EXPECTED):
        ns, aws_samples = nexus[key], aws[key]
        nm, am = statistics.median(ns), statistics.median(aws_samples)
        n_stddev, a_stddev = statistics.pstdev(ns), statistics.pstdev(aws_samples)
        np95, ap95 = percentile(ns, 0.95), percentile(aws_samples, 0.95)
        mr, pr = nm / am, np95 / ap95
        op_pass = mr <= LIMIT and pr <= LIMIT
        passed &= op_pass
        results.append({
            "algorithm": key[0], "parameter_set": key[1], "operation": key[2],
            "nexusq_samples": len(ns), "aws_lc_samples": len(aws_samples),
            "nexusq_median_ns": nm, "aws_lc_median_ns": am, "median_ratio_nexusq_over_aws_lc": mr,
            "nexusq_stddev_ns": n_stddev, "aws_lc_stddev_ns": a_stddev,
            "nexusq_p95_ns": np95, "aws_lc_p95_ns": ap95, "p95_ratio_nexusq_over_aws_lc": pr,
            "median_pass": mr <= LIMIT, "p95_pass": pr <= LIMIT, "pass": op_pass,
        })
    report = {
        "schema": "nexusq-native-assembly-performance-gate-v1",
        "gate": {"comparator": "AWS-LC", "max_median_ratio": LIMIT, "max_p95_ratio": LIMIT,
                 "rounds_per_implementation": 3, "required_operations": len(EXPECTED),
                 "aggregation": "pool raw samples from three alternating suite rounds; nearest-rank p95"},
        "status": "PASS" if passed else "FAIL", "results": results,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1

if __name__ == "__main__":
    raise SystemExit(main())
