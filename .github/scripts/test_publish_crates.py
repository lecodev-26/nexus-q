#!/usr/bin/env python3
"""Offline tests for crates.io publication safeguards and package coverage."""

import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from publish_crates import CRATES, published

EXPECTED_WORKSPACE_CRATES = {
    "nexusq", "nexusq-core", "nexusq-ml-dsa", "nexusq-ml-kem", "nexusq-kernels",
    "nexusq-cli", "nexusq-server", "nexusq-c", "nexusq-py", "nexusq-x509",
    "nexusq-ocsp", "nexusq-ha", "nexusq-enrollment", "nexusq-hsm", "nexusq-tsa",
    "nexusq-pki-cluster", "nexusq-admin",
}


class CratesPublisherTests(unittest.TestCase):
    def test_publisher_list_covers_every_workspace_crate(self) -> None:
        self.assertEqual(set(CRATES) - {"nexusq-native-backend"}, EXPECTED_WORKSPACE_CRATES)

    @patch("publish_crates.urllib.request.urlopen", return_value=io.BytesIO(b"{}"))
    def test_successful_registry_lookup_means_published(self, _urlopen) -> None:
        self.assertTrue(published("nexusq", "4.1.1"))

    @patch("publish_crates.urllib.request.urlopen", side_effect=HTTPError("https://crates.io", 404, "Not Found", {}, io.BytesIO()))
    def test_only_404_means_not_published(self, _urlopen) -> None:
        self.assertFalse(published("nexusq", "4.1.1"))

    @patch("publish_crates.urllib.request.urlopen", side_effect=HTTPError("https://crates.io", 503, "Unavailable", {}, io.BytesIO()))
    def test_server_error_fails_closed(self, _urlopen) -> None:
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            published("nexusq", "4.1.1")

    @patch("publish_crates.urllib.request.urlopen", side_effect=URLError("network unavailable"))
    def test_network_error_fails_closed(self, _urlopen) -> None:
        with self.assertRaisesRegex(RuntimeError, "network unavailable"):
            published("nexusq", "4.1.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
