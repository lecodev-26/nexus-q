import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "bot" / "coordinator.py"
spec = importlib.util.spec_from_file_location("nexusq_audit_coordinator", MODULE)
coordinator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coordinator)

class CoordinatorTests(unittest.TestCase):
    def test_atomic_save_writes_valid_json_and_replaces_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "state.json"
            coordinator.save(target, {"phase": "hunt", "count": 1})
            coordinator.save(target, {"phase": "verify", "count": 2})
            self.assertEqual(json.loads(target.read_text()), {"phase": "verify", "count": 2})
            self.assertFalse(target.with_suffix(".json.tmp").exists())

    def test_checkpoint_persists_candidates_and_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            old_out = coordinator.OUT
            try:
                coordinator.OUT = Path(directory)
                meta, candidates, coverage = {}, [{"id": "candidate-1"}], []
                coordinator.checkpoint(meta, candidates, coverage, "hunting", completed_hunt_batches=1)
                self.assertEqual(json.loads((Path(directory) / "candidates.json").read_text()), candidates)
                saved = json.loads((Path(directory) / "run-metadata.json").read_text())
                self.assertEqual(saved["phase"], "hunting")
                self.assertEqual(saved["completed_hunt_batches"], 1)
            finally:
                coordinator.OUT = old_out

    def test_api_key_normalization_trims_outer_whitespace_and_rejects_embedded_newlines(self):
        self.assertEqual(coordinator.normalized_api_key("  test-key\n"), "test-key")
        with self.assertRaisesRegex(ValueError, "embedded newline"):
            coordinator.normalized_api_key("test\nkey")

    def test_child_environment_excludes_openrouter_key_and_preserves_other_variables(self):
        import os
        old_key = os.environ.get("OPENROUTER_API_KEY")
        old_marker = os.environ.get("NEXUSQ_CHILD_ENV_TEST")
        try:
            os.environ["OPENROUTER_API_KEY"] = "test-secret-do-not-propagate"
            os.environ["NEXUSQ_CHILD_ENV_TEST"] = "preserved"
            child_env = coordinator.child_environment()
            self.assertNotIn("OPENROUTER_API_KEY", child_env)
            self.assertEqual(child_env["NEXUSQ_CHILD_ENV_TEST"], "preserved")
            self.assertEqual(os.environ["OPENROUTER_API_KEY"], "test-secret-do-not-propagate")
        finally:
            if old_key is None:
                os.environ.pop("OPENROUTER_API_KEY", None)
            else:
                os.environ["OPENROUTER_API_KEY"] = old_key
            if old_marker is None:
                os.environ.pop("NEXUSQ_CHILD_ENV_TEST", None)
            else:
                os.environ["NEXUSQ_CHILD_ENV_TEST"] = old_marker

    def test_secret_redaction_covers_private_keys_tokens_and_api_key(self):
        raw = "OPENROUTER_API_KEY=or-secret sk-abcdefghijklmnopqrstuvwxyz123456 -----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----"
        cleaned = coordinator.redact(raw)
        self.assertNotIn("or-secret", cleaned)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", cleaned)
        self.assertNotIn("BEGIN PRIVATE KEY", cleaned)

    def test_partial_candidates_are_preserved_when_empty_findings_file_exists(self):
        sources = {"src/lib.rs": "pub fn entry() {}\npub fn sink() {}\n"}
        candidates = [{
            "id": "candidate-1",
            "title": "Unvalidated boundary candidate",
            "description": "Potential source-level issue",
            "source_refs": ["src/lib.rs:2"],
        }]
        with tempfile.TemporaryDirectory() as directory:
            findings_path = Path(directory) / "findings.json"
            findings_path.write_text("[]\n", encoding="utf-8")
            coordinator.recover_partial_findings(findings_path, candidates, sources, "partial")
            saved = json.loads(findings_path.read_text())
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0]["verdict"], "needs_validation")
            self.assertEqual(saved[0]["evidence"][0]["file"], "src/lib.rs")

            # A pre-existing finalized result must never be overwritten.
            finalized = [{"verdict": "rejected", "fingerprint": "existing"}]
            coordinator.save(findings_path, finalized)
            coordinator.recover_partial_findings(findings_path, candidates, sources, "partial")
            self.assertEqual(json.loads(findings_path.read_text()), finalized)

    def test_file_is_not_covered_until_every_planned_fragment_completed(self):
        planned = {
            ("src/large.rs", 1, 40, 1),
            ("src/large.rs", 41, 80, 1),
            ("src/other.rs", 1, 12, 1),
        }
        first_wave = {("src/large.rs", 1, 40, 1), ("src/other.rs", 1, 12, 1)}
        self.assertEqual(coordinator.fully_reviewed_paths(planned, first_wave), {"src/other.rs"})
        completed = first_wave | {("src/large.rs", 41, 80, 1)}
        self.assertEqual(coordinator.fully_reviewed_paths(planned, completed), {"src/large.rs", "src/other.rs"})

    def test_batch_fragments_preserve_file_and_line_ranges(self):
        batch = "FILE src/lib.rs:1-20\n1: first\n\nFILE src/lib.rs:21-35\n21: second\n"
        self.assertEqual(coordinator.batch_fragments(batch), {
            ("src/lib.rs", 1, 20, 1), ("src/lib.rs", 21, 35, 1)
        })


    def test_long_source_lines_are_split_without_loss_and_require_every_part(self):
        line = "x" * 5000
        fragments = coordinator.source_fragments("src/long.rs", line, 1200)
        self.assertGreater(len(fragments), 1)
        payloads = [fragment.split("\n", 1)[1] for fragment in fragments]
        self.assertEqual("".join(payloads), "1: " + line + "\n")

        planned = set().union(*(coordinator.batch_fragments(fragment) for fragment in fragments))
        self.assertEqual(len(planned), len(fragments))
        self.assertEqual(coordinator.fully_reviewed_paths(planned, planned - {next(iter(planned))}), set())
        self.assertEqual(coordinator.fully_reviewed_paths(planned, planned), {"src/long.rs"})

    def test_core_and_sdk_coverage_include_kernel_and_python_crates(self):
        sources = {
            "crates/nexusq-kernels/src/lib.rs": "pub fn kernel() {}\n",
            "crates/nexusq-ml-kem/src/lib.rs": "pub fn kem() {}\n",
            "crates/nexusq-py/src/lib.rs": "pub fn python_binding() {}\n",
            "crates/nexusq-c/src/lib.rs": "pub fn c_binding() {}\n",
        }
        units = coordinator.ledger()
        core = next(unit for unit in units if unit["subsystem"] == "Core crates")
        sdk = next(unit for unit in units if unit["subsystem"] == "SDKs and FFI")
        self.assertEqual(set(coordinator.coverage_paths_for_unit(core, sources)), {
            "crates/nexusq-kernels/src/lib.rs", "crates/nexusq-ml-kem/src/lib.rs"
        })
        self.assertEqual(set(coordinator.coverage_paths_for_unit(sdk, sources)), {
            "crates/nexusq-py/src/lib.rs", "crates/nexusq-c/src/lib.rs"
        })

    def test_coverage_does_not_silently_truncate_more_than_30_paths(self):
        sources = {f"crates/nexusq-core/src/module_{index}.rs": "pub fn safe() {}\n" for index in range(35)}
        unit = next(item for item in coordinator.ledger() if item["subsystem"] == "Core crates")
        paths = coordinator.coverage_paths_for_unit(unit, sources)
        self.assertEqual(len(paths), 35)
        unit["starting_paths"] = paths
        unit["status"] = "in_progress"
        unit["agent_id"] = "static-coordinator"
        coordinator.finalize_coverage([unit], set(paths[:30]), [], sources, {unit["coverage_id"]: paths})
        self.assertEqual(unit["status"], "blocked")
        self.assertEqual(len(unit["reviewed_paths"]), 30)
        self.assertEqual(unit["unresolved"], ["5 assigned source path(s) were not included in completed hunt batches."])

        unit["status"] = "in_progress"
        unit["reviewed_paths"] = []
        unit["local_checks"] = []
        unit["unresolved"] = []
        coordinator.finalize_coverage([unit], set(paths), [], sources, {unit["coverage_id"]: paths})
        self.assertEqual(unit["status"], "covered")
        self.assertEqual(set(unit["reviewed_paths"]), set(paths))

    def test_source_refs_must_exist_and_have_valid_line_numbers(self):
        sources = {"src/lib.rs": "first\nsecond\n"}
        item = {"source_refs": ["src/lib.rs:2", "src/lib.rs:0", "missing.rs:1", "src/lib.rs:nope"]}
        self.assertEqual(coordinator.refs_for(item, sources), [("src/lib.rs", 2)])

    def test_coverage_does_not_claim_fallback_paths_as_subsystem_review(self):
        units = coordinator.ledger()
        units.sort(key=lambda item: item["coverage_id"])
        sources = {"Cargo.toml": "[workspace]\n"}
        for unit in units:
            unit["starting_paths"] = ["Cargo.toml"]
            unit["status"] = "in_progress"
            unit["agent_id"] = "static-coordinator"
        # Cargo.toml is a schema-safe scope anchor, not proof that each subsystem was reviewed.
        coordinator.finalize_coverage(units, {"Cargo.toml"}, [], sources, {unit["coverage_id"]: [] for unit in units})
        self.assertTrue(all(unit["status"] == "deferred" for unit in units))
        self.assertTrue(all(not unit["reviewed_paths"] for unit in units))

    def test_coverage_records_only_paths_actually_reviewed_for_each_unit(self):
        units = coordinator.ledger()
        units.sort(key=lambda item: item["coverage_id"])
        for unit in units:
            unit["starting_paths"] = ["crates/nexusq-core/src/lib.rs"]
            unit["status"] = "in_progress"
            unit["agent_id"] = "static-coordinator"
        source = {"crates/nexusq-core/src/lib.rs": "pub fn safe() {}\n"}
        coordinator.finalize_coverage(units, set(source), [], source,
            {unit["coverage_id"]: (["crates/nexusq-core/src/lib.rs"] if unit["subsystem"] == "Core crates" else []) for unit in units})
        core = next(unit for unit in units if unit["subsystem"] == "Core crates")
        other = [unit for unit in units if unit is not core]
        self.assertEqual(core["status"], "covered")
        self.assertTrue(all(unit["status"] == "deferred" for unit in other))

    def test_partial_subsystem_review_is_blocked_not_covered(self):
        units = coordinator.ledger()
        units.sort(key=lambda item: item["coverage_id"])
        core = next(unit for unit in units if unit["subsystem"] == "Core crates")
        core["starting_paths"] = ["crates/nexusq-core/src/lib.rs", "crates/nexusq-core/src/keys.rs"]
        for unit in units:
            if unit is not core:
                unit["starting_paths"] = ["unreviewed/placeholder.txt"]
            unit["status"] = "in_progress"
            unit["agent_id"] = "static-coordinator"
        sources = {"crates/nexusq-core/src/lib.rs": "pub fn safe() {}\n"}
        paths = {unit["coverage_id"]: (unit["starting_paths"] if unit is core else []) for unit in units}
        coordinator.finalize_coverage(units, set(sources), [], sources, paths)
        self.assertEqual(core["status"], "blocked")
        self.assertEqual(core["unresolved"], ["1 assigned source path(s) were not included in completed hunt batches."])

if __name__ == "__main__":
    unittest.main()
