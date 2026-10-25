#!/usr/bin/env python3
"""Offline tests for the fail-closed release identity gate."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HELPER = Path(__file__).with_name("verify_release_identity.py").resolve()
OFFICIAL_REMOTE = "git@github.com:lecodev-26/nexus-q.git"


class ReleaseIdentityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="nexusq-release-gate-test-")
        self.repo = Path(self.tempdir.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Release Gate Test")
        self.git("config", "user.email", "release-gate-test@example.invalid")
        (self.repo / "tracked.txt").write_text("test\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "-qm", "test release identity gate")
        self.git("remote", "add", "origin", OFFICIAL_REMOTE)
        self.commit = self.git("rev-parse", "HEAD")
        self.git("tag", "0.0.1", self.commit)
        self.git("tag", "v0.0.1", self.commit)
        self.env = os.environ.copy()
        self.env.pop("NEXUSQ_RELEASE_IDENTITY_APPROVED", None)
        self.env.pop("NEXUSQ_APPROVED_RELEASE_COMMIT", None)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HELPER), "0.0.1"],
            cwd=self.repo,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def approve(self) -> None:
        self.env["NEXUSQ_RELEASE_IDENTITY_APPROVED"] = "true"
        self.env["NEXUSQ_APPROVED_RELEASE_COMMIT"] = self.commit

    def test_blocks_without_explicit_approval(self) -> None:
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release identity has been reviewed and approved", result.stderr)

    def test_blocks_if_approved_sha_does_not_match_head(self) -> None:
        self.approve()
        self.env["NEXUSQ_APPROVED_RELEASE_COMMIT"] = "0" * 40
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not equal approved commit", result.stderr)

    def test_blocks_dirty_worktree(self) -> None:
        self.approve()
        (self.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("working tree is not clean", result.stderr)

    def test_allows_exact_approved_clean_tag(self) -> None:
        self.approve()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"0.0.1 and v0.0.1 both resolve to approved commit {self.commit}", result.stdout)

    def test_blocks_if_bare_and_v_tags_diverge(self) -> None:
        self.approve()
        other = self.git("commit-tree", self.git("rev-parse", "HEAD^{tree}"), "-m", "different tag target")
        self.git("tag", "-f", "0.0.1", other)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0.0.1 resolves to", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
