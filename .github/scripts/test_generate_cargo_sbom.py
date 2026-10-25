#!/usr/bin/env python3
"""Offline structural tests for the Cargo.lock CycloneDX generator."""

import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from generate_cargo_sbom import generate

ROOT = Path(__file__).resolve().parents[2]


class CargoSbomTests(unittest.TestCase):
    def test_includes_locked_packages_and_relationships(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nexusq-sbom-test-") as directory:
            output = Path(directory) / "sbom.cdx.json"
            bom = generate(ROOT / "Cargo.lock", ROOT / "Cargo.toml", output, "test-commit", "test-ref")
            self.assertEqual(bom["bomFormat"], "CycloneDX")
            self.assertEqual(bom["specVersion"], "1.5")
            locked_package_count = len(tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))["package"])
            self.assertEqual(len(bom["components"]) + 1, locked_package_count)
            self.assertEqual(len(bom["dependencies"]), locked_package_count)
            self.assertGreater(len(bom["components"]), 100)
            self.assertTrue(any(c["name"] == "rsa" for c in bom["components"]))
            self.assertTrue(any(c["name"] == "nexusq-core" for c in bom["components"]))
            refs = {bom["metadata"]["component"]["bom-ref"]}
            refs.update(c["bom-ref"] for c in bom["components"])
            for node in bom["dependencies"]:
                self.assertIn(node["ref"], refs)
                self.assertTrue(set(node["dependsOn"]).issubset(refs))
            self.assertTrue(any(node["dependsOn"] for node in bom["dependencies"]))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), bom)


if __name__ == "__main__":
    unittest.main(verbosity=2)
