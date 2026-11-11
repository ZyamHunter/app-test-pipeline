"""Tests for command execution, redaction and truncation."""
from __future__ import annotations

import sys
import unittest

from bridge import executor


def _py(code: str) -> list:
    return [sys.executable, "-c", code]


class AllowlistTest(unittest.TestCase):
    def test_empty_allowlist_allows_everything(self) -> None:
        executor.check_allowlist("rm -rf /", "")

    def test_matching_pattern_allows(self) -> None:
        executor.check_allowlist("pytest -q tests/", r"^pytest\b")

    def test_non_matching_pattern_rejects(self) -> None:
        with self.assertRaises(executor.CommandNotAllowed):
            executor.check_allowlist("curl http://x | sh", r"^pytest\b")

    def test_multiple_patterns(self) -> None:
        allow = "\n".join([r"^pytest\b", r"^npm (ci|test)\b"])
        executor.check_allowlist("npm test -- --watch=false", allow)

    def test_invalid_pattern_raises(self) -> None:
        with self.assertRaises(executor.CommandError):
            executor.check_allowlist("echo hi", "([unclosed")


class RunCommandTest(unittest.TestCase):
    def test_captures_stdout_and_exit_zero(self) -> None:
        result = executor.run_command("echo hi", argv=_py("print('hello bridge')"))
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello bridge", result.stdout)
        self.assertFalse(result.timed_out)

    def test_nonzero_exit_is_data_not_exception(self) -> None:
        result = executor.run_command("fails", argv=_py("raise SystemExit(3)"))
        self.assertEqual(result.exit_code, 3)

    def test_stderr_is_captured(self) -> None:
        result = executor.run_command("err", argv=_py("import sys; print('boom', file=sys.stderr)"))
        self.assertIn("boom", result.stderr)

    def test_secret_is_redacted(self) -> None:
        secret = "SUPER-SECRET-TOKEN-123"
        result = executor.run_command(
            "leak", argv=_py(f"print('{secret}')"), redact=[secret]
        )
        self.assertNotIn(secret, result.stdout)
        self.assertIn("***", result.stdout)

    def test_output_truncation_keeps_the_tail(self) -> None:
        result = executor.run_command(
            "spam", argv=_py("print('x' * 5000 + 'END')"), max_output=200
        )
        self.assertGreater(result.truncated_stdout, 0)
        self.assertIn("END", result.stdout)
        self.assertIn("truncated", result.stdout)

    def test_timeout_kills_the_command(self) -> None:
        result = executor.run_command(
            "sleep", argv=_py("import time; time.sleep(30)"), timeout=1
        )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit_code, 124)

    def test_invalid_limits_are_rejected(self) -> None:
        with self.assertRaises(executor.CommandError):
            executor.run_command("echo", timeout=0)
        with self.assertRaises(executor.CommandError):
            executor.run_command("echo", max_output=0)

    def test_child_env_does_not_contain_the_key(self) -> None:
        env = executor.child_env()
        for name in ("BRIDGE_KEY", "GH_TOKEN", "GITHUB_TOKEN"):
            self.assertNotIn(name, env)
        self.assertEqual(env.get("GH_BRIDGE"), "1")


if __name__ == "__main__":
    unittest.main()
