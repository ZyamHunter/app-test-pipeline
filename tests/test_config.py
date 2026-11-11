"""Tests for config/key discovery (including Windows BOM tolerance)."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from bridge import cli


class ConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._old_home = os.environ.get("BRIDGE_HOME")
        self._old_key = os.environ.pop("BRIDGE_KEY", None)
        os.environ["BRIDGE_HOME"] = self.tmp.name

    def tearDown(self) -> None:
        if self._old_home is None:
            os.environ.pop("BRIDGE_HOME", None)
        else:
            os.environ["BRIDGE_HOME"] = self._old_home
        if self._old_key is not None:
            os.environ["BRIDGE_KEY"] = self._old_key

    def test_missing_config_is_empty(self) -> None:
        self.assertEqual(cli.load_config(), {})

    def test_config_with_bom_is_read(self) -> None:
        # Windows PowerShell 5.1 writes UTF-8 with a BOM.
        Path(self.tmp.name, "config.json").write_bytes(
            b'\xef\xbb\xbf{"repo": "owner/name"}'
        )
        self.assertEqual(cli.load_config().get("repo"), "owner/name")

    def test_invalid_config_is_ignored(self) -> None:
        Path(self.tmp.name, "config.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(cli.load_config(), {})

    def test_key_from_file_with_bom(self) -> None:
        Path(self.tmp.name, "key").write_bytes(b"\xef\xbb\xbfsecret-key-value")
        self.assertEqual(cli.load_key(), "secret-key-value")

    def test_env_key_wins(self) -> None:
        os.environ["BRIDGE_KEY"] = "from-env"
        Path(self.tmp.name, "key").write_text("from-file", encoding="utf-8")
        self.assertEqual(cli.load_key(), "from-env")

    def test_missing_key_raises(self) -> None:
        with self.assertRaises(SystemExit):
            cli.load_key()


if __name__ == "__main__":
    unittest.main()
