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


def write_round(path: Path, implementation: str, sample_ns: int) -> None:
    rows = []
    for (algorithm, parameter_set), operations in OPS.items():
        for operation in operations:
            rows.append({
                "implementation": {"id": implementation},
                "algorithm": {"id": algorithm, "parameter_set": parameter_set},
                "operation": operation,
                "measurement": {"samples_ns": [sample_ns] * 1000},
            })
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class EvaluatorTests(unittest.TestCase):
    def run_gate(self, root: Path, nexus_ns: int, aws_ns: int, limit: str | None = None) -> subprocess.CompletedProcess[str]:
        nexus, aws = [], []
        for index in range(1, 4):
            n, a = root / f"nexus-{index}.jsonl", root / f"aws-{index}.jsonl"
            write_round(n, "nexusq", nexus_ns)
            write_round(a, "aws-lc", aws_ns)
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


if __name__ == "__main__":
    unittest.main()
