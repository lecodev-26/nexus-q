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

    def test_nuget_version_index_checks_exact_version(self):
        with patch.object(preflight, "get_json", return_value=(200, {"versions": ["4.1.0", "4.1.1"]}, "")):
            result = preflight.version_result("NuGet", "https://example.invalid", "4.1.1", check="nuget")
        self.assertEqual(result.state, "present")

    def test_pypi_reports_version_mismatch(self):
        with patch.object(preflight, "get_json", return_value=(200, {"info": {"version": "4.1.0"}}, "")):
            result = preflight.version_result("PyPI", "https://example.invalid", "4.1.1", check="pypi")
        self.assertEqual(result.state, "mismatch")

    def test_packagist_schema_error_is_unknown(self):
        with patch.object(preflight, "get_json", return_value=(200, {"unexpected": {}}, "")):
            result = preflight.version_result("Packagist", "https://example.invalid", "4.1.1", check="packagist")
        self.assertEqual(result.state, "unknown")


if __name__ == "__main__":
    unittest.main()
