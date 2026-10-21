#!/usr/bin/env python3
"""Regression tests for the public-core production benchmark scope contract."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("evaluate_core_production_benchmark.py")
OPS = [(a, p, o) for a, p, operations in (
    ("ml-kem", "768", ("keygen", "encaps", "decaps")),
    ("ml-kem", "1024", ("keygen", "encaps", "decaps")),
    ("ml-dsa", "65", ("keygen", "sign", "verify")),
) for o in operations]


def scope(impl, key):
    algorithm, parameter, operation = key
    if impl == "aws-lc":
        if algorithm == "ml-kem" and parameter == "1024":
            return "aws_lc_nexusq_hybrid_api_comparator"
        if operation == "keygen":
            return "reference_implementation_operation"
        if operation in ("encaps", "verify"):
            return "aws_lc_evp_preimported_public_key"
        return "aws_lc_evp_preimported_secret_key"
    if algorithm == "ml-kem" and parameter == "1024":
        return "nexusq_core_hybrid_public_api"
    return "nexusq_core_public_api"


def write_fixture(path, impl, bad_scope=False):
    rows = []
    for key in OPS:
        algorithm, parameter, operation = key
        samples = [10000 + i for i in range(1000)]
        rows.append({
            "algorithm": {"id": algorithm, "parameter_set": parameter},
            "operation": operation,
            "implementation": {"id": impl},
            "environment": {"cpu": "Test CPU"},
            "measurement": {
                "samples_ns": samples, "warmups": 100,
                "measurement_scope": "wrong_scope" if bad_scope and key == OPS[1] else scope(impl, key),
            },
        })
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class ProductionEvaluatorTests(unittest.TestCase):
    def test_accepts_emitted_scope_contract_and_checks_performance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = [root / f"{name}.jsonl" for name in ("rustcrypto", "native", "aws")]
            for path, impl in zip(files, ("nexusq-core-rustcrypto", "nexusq-core-native-backend", "aws-lc")):
                write_fixture(path, impl)
            result = subprocess.run([sys.executable, str(SCRIPT), *(str(p) for p in files)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("production-path gate passed", result.stdout)

    def test_rejects_unexpected_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = [root / f"{name}.jsonl" for name in ("rustcrypto", "native", "aws")]
            write_fixture(files[0], "nexusq-core-rustcrypto")
            write_fixture(files[1], "nexusq-core-native-backend")
            write_fixture(files[2], "aws-lc", bad_scope=True)
            result = subprocess.run([sys.executable, str(SCRIPT), *(str(p) for p in files)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected measurement scope", result.stderr)


if __name__ == "__main__":
    unittest.main()
