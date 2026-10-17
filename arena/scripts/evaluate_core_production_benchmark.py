#!/usr/bin/env python3
"""Fail-closed evaluator for matched-run nexusq-core production-path benchmarks."""
import json
import math
import sys
from pathlib import Path

OPS = [(a, p, o) for a, p, ops in (
    ("ml-kem", "768", ("keygen", "encaps", "decaps")),
    ("ml-kem", "1024", ("keygen", "encaps", "decaps")),
    ("ml-dsa", "65", ("keygen", "sign", "verify")),
) for o in ops]
LIMIT = 1.5


def load(path, expected_impl):
    records = {}
    for line_no, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        key = (row["algorithm"]["id"], str(row["algorithm"]["parameter_set"]), row["operation"])
        if key in records:
            raise SystemExit(f"duplicate operation in {path}:{line_no}: {key}")
        if row["implementation"]["id"] != expected_impl:
            raise SystemExit(f"unexpected implementation in {path}:{line_no}: {row['implementation']['id']} != {expected_impl}")
        measurement = row["measurement"]
        samples = measurement.get("samples_ns")
        if not isinstance(samples, list) or len(samples) < 1000 or any(not isinstance(x, int) or x <= 0 for x in samples):
            raise SystemExit(f"missing/invalid raw samples (need >=1000) in {path}:{line_no}: {key}")
        sorted_samples = sorted(samples)
        n = len(sorted_samples)
        median = (sorted_samples[n//2 - 1] + sorted_samples[n//2]) / 2 if n % 2 == 0 else sorted_samples[n//2]
        p95 = sorted_samples[math.ceil(n * 0.95) - 1]
        if int(measurement.get("warmups", -1)) < 100:
            raise SystemExit(f"need >=100 warmups in {path}:{line_no}: {key}")
        if measurement.get("measurement_scope") not in ("nexusq_core_public_api", "nexusq_core_hybrid_public_api", "aws_lc_evp_primitive_operation", "aws_lc_nexusq_hybrid_api_comparator"):
            raise SystemExit(f"unexpected measurement scope in {path}:{line_no}: {key}")
        records[key] = {"median": median, "p95": p95, "samples": len(samples), "scope": measurement["measurement_scope"],
                        "cpu": row["environment"].get("cpu"), "run_order": row["environment"].get("run_order")}
    missing = set(OPS) - records.keys()
    extra = records.keys() - set(OPS)
    if missing or extra:
        raise SystemExit(f"operation coverage mismatch in {path}: missing={sorted(missing)} extra={sorted(extra)}")
    return records


def ratio(a, b):
    return a / b if b else float("inf")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: evaluate_core_production_benchmark.py RUSTCRYPTO.jsonl NATIVE.jsonl AWS_LC.jsonl")
    rustcrypto = load(sys.argv[1], "nexusq-core-rustcrypto")
    native = load(sys.argv[2], "nexusq-core-native-backend")
    aws = load(sys.argv[3], "aws-lc")
    cpu_values = [v["cpu"] for data in (rustcrypto, native, aws) for v in data.values()]
    all_cpu = set(cpu_values)
    if len(all_cpu) != 1 or not all(isinstance(cpu, str) and cpu.strip() and cpu != "unknown" for cpu in cpu_values):
        raise SystemExit(f"CPU model mismatch or missing metadata: {all_cpu}")
    failed = []
    for key in OPS:
        expected_native_scope = "nexusq_core_hybrid_public_api" if key[0] == "ml-kem" and key[1] == "1024" else "nexusq_core_public_api"
        expected_aws_scope = "aws_lc_nexusq_hybrid_api_comparator" if key[0] == "ml-kem" and key[1] == "1024" else "aws_lc_evp_primitive_operation"
        if native[key]["scope"] != expected_native_scope or rustcrypto[key]["scope"] != expected_native_scope or aws[key]["scope"] != expected_aws_scope:
            raise SystemExit(f"scope mismatch for {key}: RustCrypto={rustcrypto[key]['scope']}, native={native[key]['scope']}, AWS-LC={aws[key]['scope']}; refuse incomparable gate")
    cpu = next(iter(all_cpu))
    print(f"CPU model: {cpu}; samples per operation: 1000; warmups: 100; implementation order is recorded in each JSONL artifact.")
    print("| Operation | RustCrypto median / p95 ns | Native median / p95 ns | AWS-LC median / p95 ns | Native/RustCrypto median | Native/AWS-LC median | Native/AWS-LC p95 | Samples (R/N/A) | Scope note |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    for key in OPS:
        r, n, a = rustcrypto[key], native[key], aws[key]
        med_delta = ratio(n["median"], r["median"])
        med_aws = ratio(n["median"], a["median"])
        p95_aws = ratio(n["p95"], a["p95"])
        scope_note = "matched NEXUS-Q hybrid wrapper" if key[0] == "ml-kem" and key[1] == "1024" else "public wrapper vs AWS-LC EVP"
        print(f"| {key[0]}-{key[1]} {key[2]} | {r['median']:.1f} / {r['p95']:.1f} | {n['median']:.1f} / {n['p95']:.1f} | {a['median']:.1f} / {a['p95']:.1f} | {med_delta:.3f}x | {med_aws:.3f}x | {p95_aws:.3f}x | {r['samples']}/{n['samples']}/{a['samples']} | {scope_note} |")
        if med_aws > LIMIT or p95_aws > LIMIT:
            failed.append((key, med_aws, p95_aws))
    print("\nThreshold: native/AWS-LC <= 1.5x on median and p95. No averaging of replicas; this report evaluates one replica's raw samples.")
    if failed:
        print("GATE FAILED:", failed)
        raise SystemExit(1)
    print("Nine-operation production-path gate passed for this replica.")

if __name__ == "__main__":
    main()
