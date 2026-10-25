#!/usr/bin/env python3
"""Offline tests for fail-closed Maven Central version lookup parsing."""

import unittest

from maven_version_state import state


class MavenVersionStateTests(unittest.TestCase):
    def test_zero_results_means_absent(self) -> None:
        self.assertEqual(state('{"response":{"numFound":0,"docs":[]}}'), "absent")

    def test_positive_results_means_present(self) -> None:
        self.assertEqual(state('{"response":{"numFound":1,"docs":[{"id":"g:a:1"}]}}'), "present")

    def test_invalid_json_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid Maven Central"):
            state("not json")

    def test_missing_fields_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid Maven Central"):
            state('{"response":{"numFound":0}}')

    def test_wrong_types_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "numFound"):
            state('{"response":{"numFound":"0","docs":[]}}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
