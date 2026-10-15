#!/usr/bin/env python3
"""Extended, informational statistics for the native-backend gate.

This does NOT replace evaluate_native_assembly_gate.py (the official, fail-closed
3-round gate). It quantifies how robust the 1.5x verdict is on the same runner:
  * pooled median / p95 ratios over N alternating rounds (official percentile rule),
  * 95% cluster-bootstrap confidence intervals (resampling whole rounds),
  * per-round ratios and how many rounds exceed 1.5x,
  * how many disjoint 3-round windows would fail the official gate.
Usage: native_backend_stats.py OUT.json OUT.md DIR NROUNDS
DIR must contain nexusq-round-{i}.jsonl and aws-lc-round-{i}.jsonl.
"""
from __future__ import annotations
import json, math, random, statistics, sys
from pathlib import Path

LIMIT = 1.5
OPS = [("ml-kem", "768", "keygen"), ("ml-kem", "768", "encaps"), ("ml-kem", "768", "decaps"),
       ("ml-kem", "1024", "keygen"), ("ml-kem", "1024", "encaps"), ("ml-kem", "1024", "decaps"),
       ("ml-dsa", "65", "keygen"), ("ml-dsa", "65", "sign"), ("ml-dsa", "65", "verify")]

def p95(sorted_values):
    return sorted_values[max(0, math.ceil(0.95 * len(sorted_values)) - 1)]

def load(path: Path):
    out = {}
    for line in path.read_text().splitlines():
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        if row["measurement"].get("comparison_contract") != "fips_operation_v1":
            continue
        key = (row["algorithm"]["id"], str(row["algorithm"]["parameter_set"]), row["operation"])
        out[key] = row["measurement"]["samples_ns"]
    return out

def stats(rounds_n, rounds_a, idx, key):
    n = sorted(x for i in idx for x in rounds_n[i][key])
    a = sorted(x for i in idx for x in rounds_a[i][key])
    return statistics.median(n) / statistics.median(a), p95(n) / p95(a), statistics.median(n), p95(n), statistics.median(a), p95(a)

def main():
    out_json, out_md, d, n = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
    rn = [load(d / f"nexusq-round-{i}.jsonl") for i in range(1, n + 1)]
    ra = [load(d / f"aws-lc-round-{i}.jsonl") for i in range(1, n + 1)]
    rng = random.Random(20261015)
    B = 1000
    res = []
    for key in OPS:
        mr, pr, nm, np_, am, ap = stats(rn, ra, range(n), key)
        bm, bp = [], []
        for _ in range(B):
            idx = [rng.randrange(n) for _ in range(n)]
            m, p, *_ = stats(rn, ra, idx, key)
            bm.append(m); bp.append(p)
        bm.sort(); bp.sort()
        ci = lambda v: [v[int(0.025 * B)], v[int(0.975 * B) - 1]]
        per = [stats(rn, ra, [i], key)[:2] for i in range(n)]
        windows = [stats(rn, ra, range(w, w + 3), key)[:2] for w in range(0, n - 2, 3)]
        res.append({
            "operation": "-".join(key[:2]) + " " + key[2],
            "nexusq_median_us": nm / 1e3, "nexusq_p95_us": np_ / 1e3, "aws_lc_median_us": am / 1e3, "aws_lc_p95_us": ap / 1e3,
            "ratio_median": mr, "ratio_median_ci95": ci(bm), "ratio_p95": pr, "ratio_p95_ci95": ci(bp),
            "rounds": n, "rounds_median_over_limit": sum(m > LIMIT for m, _ in per),
            "rounds_p95_over_limit": sum(p > LIMIT for _, p in per),
            "max_round_ratio_median": max(m for m, _ in per), "max_round_ratio_p95": max(p for _, p in per),
            "gate_windows": len(windows), "gate_windows_failing": sum(m > LIMIT or p > LIMIT for m, p in windows),
            "robust": ci(bm)[1] <= LIMIT and ci(bp)[1] <= LIMIT,
        })
    out_json.write_text(json.dumps({"limit": LIMIT, "bootstrap_resamples": B, "results": res}, indent=1))
    lines = [f"Extended statistics ({n} alternating rounds, cluster bootstrap B={B}; informational, the official verdict is the 3-round gate)", "",
             "| Operation | NEXUS-Q med (us) | AWS-LC med (us) | Median ratio [CI95] | p95 ratio [CI95] | Rounds >1.5 (med/p95) | 3-round windows failing | Robust |",
             "|---|---|---|---|---|---|---|---|"]
    for r in res:
        lines.append(f"| {r['operation']} | {r['nexusq_median_us']:.1f} | {r['aws_lc_median_us']:.1f} | "
                     f"{r['ratio_median']:.3f} [{r['ratio_median_ci95'][0]:.3f}, {r['ratio_median_ci95'][1]:.3f}] | "
                     f"{r['ratio_p95']:.3f} [{r['ratio_p95_ci95'][0]:.3f}, {r['ratio_p95_ci95'][1]:.3f}] | "
                     f"{r['rounds_median_over_limit']}/{r['rounds_p95_over_limit']} of {n} | {r['gate_windows_failing']}/{r['gate_windows']} | "
                     f"{'yes' if r['robust'] else 'NO'} |")
    out_md.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0

if __name__ == "__main__":
    sys.exit(main())
