#!/usr/bin/env python3
"""Fail closed on per-operation median and p95 ratios for native PQC kernels."""
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

def read_rows(paths: list[Path], expected_id: str, *, require_all: bool = True, host_registry: set[tuple[str, str, str]] | None = None, eligible_scopes: set[str] | None = None) -> dict[tuple[str, str, str], list[int]]:
    result: dict[tuple[str, str, str], list[int]] = {}
    hosts: set[tuple[str, str, str]] = set()
    for path in paths:
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip().startswith("{")]
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            impl = row.get("implementation", {}).get("id")
            if impl != expected_id:
                raise ValueError(f"{path}: expected implementation {expected_id!r}, got {impl!r}")
            env = row.get("environment", {})
            if env.get("target") and env.get("os") and env.get("cpu"):
                host = (str(env["target"]).split("-")[0].lower(), str(env["os"]).lower(), str(env["cpu"]))
                hosts.add(host)
                if host_registry is not None: host_registry.add(host)
            algorithm = row.get("algorithm", {})
            key = (algorithm.get("id", ""), str(algorithm.get("parameter_set", "")), row.get("operation", ""))
            if key not in EXPECTED:
                continue
            if eligible_scopes is not None and row.get("measurement", {}).get("measurement_scope") not in eligible_scopes:
                continue
            if key in seen:
                raise ValueError(f"{path}: duplicate operation row {key}")
            seen.add(key)
            samples = row.get("measurement", {}).get("samples_ns")
            if not isinstance(samples, list) or not samples or any(not isinstance(x, (int, float)) or not math.isfinite(x) or x <= 0 for x in samples):
                raise ValueError(f"{path}: {key} lacks valid raw samples_ns")
            if len(samples) < 1000:
                raise ValueError(f"{path}: {key} has only {len(samples)} samples; minimum is 1000")
            result.setdefault(key, []).extend(int(x) for x in samples)
        if require_all and seen != EXPECTED:
            raise ValueError(f"{path}: missing required operations: {sorted(EXPECTED - seen)}")
        if not seen:
            raise ValueError(f"{path}: no recognized operations for {expected_id}")
    if require_all and set(result) != EXPECTED:
        raise ValueError(f"{expected_id}: missing operations: {sorted(EXPECTED - set(result))}")
    if len(hosts) > 1:
        raise ValueError(f"{expected_id}: benchmark inputs mix hosts: {sorted(hosts)}")
    return result

def main() -> int:
    args = sys.argv[1:]
    limit = LIMIT
    if "--limit" in args:
        index = args.index("--limit")
        if index + 1 >= len(args):
            print("--limit requires a positive ratio (for example 1.0)", file=sys.stderr); return 64
        try: limit = float(args[index + 1])
        except ValueError:
            print("--limit requires a numeric ratio (for example 1.0)", file=sys.stderr); return 64
        if not math.isfinite(limit) or limit <= 0:
            print("--limit must be a finite positive ratio", file=sys.stderr); return 64
        del args[index:index + 2]
    if not args:
        print("usage: evaluator REPORT [--limit RATIO] [--best-of N1 N2 N3 --comparator ID C1 C2 C3 ...]", file=sys.stderr); return 64
    report_path = Path(args.pop(0))
    best_mode = "--best-of" in args
    try:
        if best_mode:
            pos = args.index("--best-of")
            if pos != 0:
                raise ValueError(f"unexpected arguments before --best-of: {args[:pos]}")
            if len(args) < pos + 4:
                raise ValueError("--best-of requires exactly three NEXUS-Q round files")
            nexus_paths = [Path(x) for x in args[pos + 1:pos + 4]]
            # Comparator groups follow the three candidate round paths.
            original = sys.argv[1:]
            if "--limit" in original:
                oi = original.index("--limit"); del original[oi:oi + 2]
            oi = original.index("--best-of")
            tail = original[oi + 4:]
            comparators: dict[str, dict[tuple[str, str, str], list[int]]] = {}
            common_hosts: set[tuple[str, str, str]] = set()
            i = 0
            while i < len(tail):
                if tail[i] != "--comparator" or i + 4 >= len(tail):
                    raise ValueError("comparator syntax: --comparator IMPLEMENTATION ROUND1 ROUND2 ROUND3")
                ident = tail[i + 1]
                if ident in comparators:
                    raise ValueError(f"duplicate comparator group: {ident}")
                paths = [Path(x) for x in tail[i + 2:i + 5]]
                comparators[ident] = read_rows(paths, ident, require_all=False, host_registry=common_hosts, eligible_scopes={"reference_implementation_operation"})
                i += 5
            if not comparators:
                raise ValueError("--best-of requires at least one --comparator group")
            nexus = read_rows(nexus_paths, "nexusq", host_registry=common_hosts)
            if len(common_hosts) > 1: raise ValueError(f"benchmark inputs mix hosts: {sorted(common_hosts)}")
            all_keys = set().union(*(set(rows) for rows in comparators.values()))
            missing = EXPECTED - all_keys
            if missing:
                raise ValueError(f"comparators collectively lack required operations: {sorted(missing)}")
        else:
            if "--" not in args:
                raise ValueError("missing -- separator between NEXUS-Q and AWS-LC files")
            sep = args.index("--")
            nexus_paths = [Path(x) for x in args[:sep]]
            aws_paths = [Path(x) for x in args[sep + 1:]]
            if len(nexus_paths) != 3 or len(aws_paths) != 3:
                raise ValueError("gate requires exactly three NEXUS-Q rounds and three AWS-LC rounds")
            common_hosts: set[tuple[str, str, str]] = set()
            nexus = read_rows(nexus_paths, "nexusq", host_registry=common_hosts)
            comparators = {"aws-lc": read_rows(aws_paths, "aws-lc", host_registry=common_hosts)}
            if len(common_hosts) > 1: raise ValueError(f"benchmark inputs mix hosts: {sorted(common_hosts)}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BENCHMARK INPUT INVALID: {exc}", file=sys.stderr); return 2

    results, passed = [], True
    for key in sorted(EXPECTED):
        ns = nexus[key]
        available = {name: rows[key] for name, rows in comparators.items() if key in rows}
        if not available:
            print(f"BENCHMARK INPUT INVALID: no comparator for {key}", file=sys.stderr); return 2
        best_median_id = min(available, key=lambda name: statistics.median(available[name]))
        best_p95_id = min(available, key=lambda name: percentile(available[name], 0.95))
        nm, np95 = statistics.median(ns), percentile(ns, 0.95)
        best_median, best_p95 = available[best_median_id], available[best_p95_id]
        bm, bp = statistics.median(best_median), percentile(best_p95, 0.95)
        mr, pr = nm / bm, np95 / bp
        op_pass = mr <= limit and pr <= limit
        passed &= op_pass
        row = {"algorithm":key[0],"parameter_set":key[1],"operation":key[2],"nexusq_samples":len(ns),
               "nexusq_median_ns":nm,"nexusq_p95_ns":np95,"nexusq_stddev_ns":statistics.pstdev(ns),"best_median_comparator":best_median_id,
               "best_median_comparator_samples":len(best_median),"best_comparator_median_ns":bm,
               "best_comparator_median_stddev_ns":statistics.pstdev(best_median),"median_ratio_nexusq_over_best":mr,"best_p95_comparator":best_p95_id,
               "best_p95_comparator_samples":len(best_p95),"best_comparator_p95_ns":bp,
               "best_comparator_p95_stddev_ns":statistics.pstdev(best_p95),"p95_ratio_nexusq_over_best":pr,"median_pass":mr<=limit,"p95_pass":pr<=limit,"pass":op_pass}
        if not best_mode:
            row["aws_lc_median_ns"] = bm; row["aws_lc_p95_ns"] = bp
            row["aws_lc_stddev_ns"] = statistics.pstdev(best_median)
            row["median_ratio_nexusq_over_aws_lc"] = mr; row["p95_ratio_nexusq_over_aws_lc"] = pr
        results.append(row)
    report = {"schema":"nexusq-native-assembly-performance-gate-v1",
              "gate":{"comparator":"best-per-operation median and p95" if best_mode else "AWS-LC",
                      "comparator_implementations":sorted(comparators),"max_median_ratio":limit,"max_p95_ratio":limit,
                      "rounds_per_implementation":3,"required_operations":len(EXPECTED),
                      "aggregation":"pool raw samples from three rounds; nearest-rank p95",
                      "best_selection":"minimum median and minimum p95 selected independently per operation" if best_mode else "AWS-LC median and p95",
                      "eligible_comparator_scope":"reference_implementation_operation; comparators that pre-import keys outside timed samples are excluded for those operations" if best_mode else "legacy AWS-LC gate scope"},
              "status":"PASS" if passed else "FAIL","results":results}
    report_path.parent.mkdir(parents=True, exist_ok=True); report_path.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, indent=2)); return 0 if passed else 1

if __name__ == "__main__": raise SystemExit(main())
