#!/usr/bin/env python3
"""Offline tests for read-only release preflight response handling."""
import unittest
from unittest.mock import patch

import release_preflight as preflight


class PreflightTests(unittest.TestCase):
    def test_http_404_is_absent(self):
        with patch.object(preflight, "get_json", return_value=(404, None, "not found")):
            result = preflight.version_result("test registry", "https://example.invalid", "4.1.1")
        self.assertEqual(result.state, "absent")

    def test_server_error_is_unknown_not_absent(self):
        with patch.object(preflight, "get_json", return_value=(503, None, "HTTP 503")):
            result = preflight.version_result("test registry", "https://example.invalid", "4.1.1")
        self.assertEqual(result.state, "unknown")

    def test_maven_schema_error_is_unknown(self):
        with patch.object(preflight, "get_json", return_value=(200, {"response": {"docs": "bad"}}, "")):
            result = preflight.version_result("Maven", "https://example.invalid", "4.1.1", check="maven")
        self.assertEqual(result.state, "unknown")

    def test_maven_all_expected_files_http_200_is_present(self):
        with patch.object(preflight, "get_status", return_value=(200, "")) as mocked:
            result = preflight.maven_artifact_result("Maven", "nexusq", "4.1.1")
        self.assertEqual(result.state, "present")
        self.assertIn("POM, binary JAR, and sources JAR", result.detail)
        self.assertEqual(mocked.call_count, 3)
        self.assertTrue(any("nexusq-4.1.1.pom" in call.args[0] for call in mocked.call_args_list))
        self.assertTrue(any("nexusq-4.1.1.jar" in call.args[0] for call in mocked.call_args_list))
        self.assertTrue(any("nexusq-4.1.1-sources.jar" in call.args[0] for call in mocked.call_args_list))

    def test_maven_all_expected_files_404_is_absent(self):
        with patch.object(preflight, "get_status", return_value=(404, "not found")):
            result = preflight.maven_artifact_result("Maven", "nexusq", "4.1.1")
        self.assertEqual(result.state, "absent")

    def test_maven_partial_publication_is_mismatch(self):
        with patch.object(preflight, "get_status", side_effect=[(200, ""), (404, "not found"), (200, "")]):
            result = preflight.maven_artifact_result("Maven", "nexusq", "4.1.1")
        self.assertEqual(result.state, "mismatch")
        self.assertIn("partial Maven publication", result.detail)

    def test_maven_server_error_is_unknown(self):
        with patch.object(preflight, "get_status", side_effect=[(200, ""), (503, "HTTP 503"), (200, "")]):
            result = preflight.maven_artifact_result("Maven", "nexusq", "4.1.1")
        self.assertEqual(result.state, "unknown")

    def test_nuget_version_index_checks_exact_version(self):
        with patch.object(preflight, "get_json", return_value=(200, {"versions": ["4.1.0", "4.1.1"]}, "")):
            result = preflight.version_result("NuGet", "https://example.invalid", "4.1.1", check="nuget")
        self.assertEqual(result.state, "present")

    def test_pypi_reports_version_mismatch(self):
        with patch.object(preflight, "get_json", return_value=(200, {"info": {"version": "4.1.0"}}, "")):
            result = preflight.version_result("PyPI", "https://example.invalid", "4.1.1", check="pypi")
        self.assertEqual(result.state, "mismatch")


    def test_annotated_tag_chain_resolves_to_commit(self):
        responses = [
            (200, {"object": {"sha": "a" * 40, "type": "tag"}}, ""),
            (200, {"object": {"sha": "b" * 40, "type": "tag"}}, ""),
            (200, {"object": {"sha": "c" * 40, "type": "commit"}}, ""),
        ]
        with patch.object(preflight, "get_json", side_effect=responses):
            result = preflight.github_ref("v4.1.1")
        self.assertEqual(result.state, "present")
        self.assertEqual(result.detail, f"resolves to {'c' * 40}")

    def test_tag_pointing_to_tree_is_not_accepted_as_commit(self):
        with patch.object(preflight, "get_json", return_value=(200, {"object": {"sha": "a" * 40, "type": "tree"}}, "")):
            result = preflight.github_ref("v4.1.1")
        self.assertEqual(result.state, "unknown")
        self.assertIn("unexpected Git object type", result.detail)

    def test_tag_chain_depth_is_bounded(self):
        response = (200, {"object": {"sha": "a" * 40, "type": "tag"}}, "")
        with patch.object(preflight, "get_json", return_value=response):
            result = preflight.github_ref("v4.1.1")
        self.assertEqual(result.state, "unknown")
        self.assertIn("maximum depth", result.detail)

    def test_packagist_schema_error_is_unknown(self):
        with patch.object(preflight, "get_json", return_value=(200, {"unexpected": {}}, "")):
            result = preflight.version_result("Packagist", "https://example.invalid", "4.1.1", check="packagist")
        self.assertEqual(result.state, "unknown")


if __name__ == "__main__":
    unittest.main()
