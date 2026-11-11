"""Tests for the REST helpers that need no network."""
from __future__ import annotations

import unittest

from bridge import gh


class SplitRepoTest(unittest.TestCase):
    def test_owner_name(self) -> None:
        self.assertEqual(gh.split_repo("ZyamHunter/gh-bridge"), ("ZyamHunter", "gh-bridge"))

    def test_full_url(self) -> None:
        self.assertEqual(
            gh.split_repo("https://github.com/ZyamHunter/gh-bridge.git"),
            ("ZyamHunter", "gh-bridge"),
        )

    def test_trailing_slash_and_whitespace(self) -> None:
        self.assertEqual(gh.split_repo("  a/b/  "), ("a", "b"))

    def test_invalid(self) -> None:
        with self.assertRaises(gh.GitHubError):
            gh.split_repo("no-slash")


class ErrorMessageTest(unittest.TestCase):
    def test_404_mentions_default_branch(self) -> None:
        message = gh._friendly_http_error(404, "https://api/x", '{"message":"Not Found"}')
        self.assertIn("default branch", message)

    def test_detail_survives_invalid_json(self) -> None:
        message = gh._friendly_http_error(500, "https://api/x", "<html>oops</html>")
        self.assertIn("oops", message)

    def test_403_hint(self) -> None:
        self.assertIn("scope", gh._friendly_http_error(403, "https://api/x", ""))


class SummarizeRunTest(unittest.TestCase):
    def test_in_progress(self) -> None:
        self.assertEqual(gh.summarize_run({"status": "in_progress"}), "in_progress")

    def test_completed(self) -> None:
        self.assertEqual(
            gh.summarize_run({"status": "completed", "conclusion": "success"}),
            "completed/success",
        )


if __name__ == "__main__":
    unittest.main()
