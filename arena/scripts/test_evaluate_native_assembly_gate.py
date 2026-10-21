#!/usr/bin/env python3
"""Regression tests for intermediate and final Issue #23 performance gates."""
from __future__ import annotations
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("evaluate_native_assembly_gate.py")
OPS = {
    ("ml-kem", "768"): ("keygen", "encaps", "decaps"),
    ("ml-kem", "1024"): ("keygen", "encaps", "decaps"),
    ("ml-dsa", "65"): ("keygen", "sign", "verify"),
}


def write_round(path: Path, implementation: str, sample_ns: int, os_name: str | None = None) -> None:
    rows = []
    for (algorithm, parameter_set), operations in OPS.items():
        for operation in operations:
            rows.append({
                "implementation": {"id": implementation},
                **({"environment": {"target": "x86_64-linux-gnu", "os": os_name, "cpu": "CI CPU"}} if os_name else {}),
                "algorithm": {"id": algorithm, "parameter_set": parameter_set},
                "operation": operation,
                "measurement": {"samples_ns": [sample_ns] * 1000, "measurement_scope": "reference_implementation_operation"},
            })
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class EvaluatorTests(unittest.TestCase):
    def run_gate(self, root: Path, nexus_ns: int, aws_ns: int, limit: str | None = None, nexus_os: str | None = None, aws_os: str | None = None) -> subprocess.CompletedProcess[str]:
        nexus, aws = [], []
        for index in range(1, 4):
            n, a = root / f"nexus-{index}.jsonl", root / f"aws-{index}.jsonl"
            write_round(n, "nexusq", nexus_ns, nexus_os)
            write_round(a, "aws-lc", aws_ns, aws_os)
            nexus.append(str(n)); aws.append(str(a))
        report = root / "report.json"
        cmd = [sys.executable, str(SCRIPT), str(report)]
        if limit is not None:
            cmd += ["--limit", limit]
        cmd += nexus + ["--"] + aws
        result = subprocess.run(cmd, text=True, capture_output=True, check=False)
        self.assertTrue(report.exists(), result.stderr)
        self.assertEqual(json.loads(report.read_text())["gate"]["max_median_ratio"], float(limit or 1.5))
        return result

    def test_default_intermediate_gate_remains_1_5(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_gate(Path(temp), 120, 100)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"status": "PASS"', result.stdout)

    def test_equivalent_linux_distribution_labels_are_same_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_gate(Path(temp), 120, 100, nexus_os="linux", aws_os="Ubuntu")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"status": "PASS"', result.stdout)

    def test_final_1_0_gate_rejects_any_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_gate(Path(temp), 101, 100, "1.0")
            self.assertEqual(result.returncode, 1)
            self.assertIn('"status": "FAIL"', result.stdout)

    def test_final_1_0_gate_passes_exact_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_gate(Path(temp), 100, 100, "1.0")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"status": "PASS"', result.stdout)

    def test_invalid_limit_fails_closed(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT), "report.json", "--limit", "nan"],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn("finite positive", result.stderr)


    def test_best_of_selects_fastest_comparator_per_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nexus, aws, oqs = [], [], []
            for index in range(1, 4):
                n, a, o = root / f"nexus-{index}.jsonl", root / f"aws-{index}.jsonl", root / f"oqs-{index}.jsonl"
                write_round(n, "nexusq", 70)
                write_round(a, "aws-lc", 100)
                write_round(o, "liboqs", 80)
                nexus.append(str(n)); aws.append(str(a)); oqs.append(str(o))
            report = root / "best-report.json"
            cmd = [sys.executable, str(SCRIPT), str(report), "--limit", "1.0", "--best-of", *nexus,
                   "--comparator", "aws-lc", *aws, "--comparator", "liboqs", *oqs]
            result = subprocess.run(cmd, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(report.read_text())
            self.assertEqual(parsed["status"], "PASS")
            self.assertEqual(parsed["gate"]["comparator_implementations"], ["aws-lc", "liboqs"])
            self.assertTrue(all(row["best_median_comparator"] == "liboqs" for row in parsed["results"]))
            self.assertTrue(all(row["best_p95_comparator"] == "liboqs" for row in parsed["results"]))

    def test_best_of_allows_partial_comparator_when_union_covers_all_operations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nexus, aws, circl = [], [], []
            for index in range(1, 4):
                n, a, c = root / f"nexus-{index}.jsonl", root / f"aws-{index}.jsonl", root / f"circl-{index}.jsonl"
                write_round(n, "nexusq", 50); write_round(a, "aws-lc", 100); write_round(c, "circl", 60)
                rows = [json.loads(line) for line in c.read_text().splitlines()]
                c.write_text("".join(json.dumps(row) + "\n" for row in rows if not (row["algorithm"]["id"] == "ml-kem" and row["algorithm"]["parameter_set"] == "1024")))
                nexus.append(str(n)); aws.append(str(a)); circl.append(str(c))
            report = root / "best-report.json"
            cmd = [sys.executable, str(SCRIPT), str(report), "--limit", "1.0", "--best-of", *nexus,
                   "--comparator", "aws-lc", *aws, "--comparator", "circl", *circl]
            result = subprocess.run(cmd, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(report.read_text())
            self.assertEqual(parsed["status"], "PASS")
            self.assertTrue(all(x["best_median_comparator"] == "circl" for x in parsed["results"] if x["algorithm"] == "ml-kem" and x["parameter_set"] == "768"))
            self.assertTrue(all(x["best_median_comparator"] == "aws-lc" for x in parsed["results"] if x["algorithm"] == "ml-kem" and x["parameter_set"] == "1024"))


    def test_best_of_excludes_preimported_key_comparator_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nexus, aws, oqs = [], [], []
            for index in range(1, 4):
                n, a, o = root / f"nexus-{index}.jsonl", root / f"aws-{index}.jsonl", root / f"oqs-{index}.jsonl"
                write_round(n, "nexusq", 50); write_round(a, "aws-lc", 60); write_round(o, "liboqs", 80)
                rows = [json.loads(line) for line in a.read_text().splitlines()]
                for row in rows:
                    if row["operation"] != "keygen":
                        row["measurement"]["measurement_scope"] = "aws_lc_evp_preimported_key"
                a.write_text("".join(json.dumps(row) + "\n" for row in rows))
                nexus.append(str(n)); aws.append(str(a)); oqs.append(str(o))
            report = root / "scope-report.json"
            cmd = [sys.executable, str(SCRIPT), str(report), "--limit", "1.0", "--best-of", *nexus,
                   "--comparator", "aws-lc", *aws, "--comparator", "liboqs", *oqs]
            result = subprocess.run(cmd, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(report.read_text())
            by_key = {(x["algorithm"], x["parameter_set"], x["operation"]): x for x in parsed["results"]}
            self.assertEqual(by_key[("ml-kem", "768", "keygen")]["best_median_comparator"], "aws-lc")
            self.assertEqual(by_key[("ml-dsa", "65", "sign")]["best_median_comparator"], "liboqs")
            self.assertIn("pre-import keys", parsed["gate"]["eligible_comparator_scope"])


if __name__ == "__main__":
    unittest.main()
