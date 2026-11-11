"""Integration tests for the signed session server (localhost only)."""
from __future__ import annotations

import threading
import unittest

from bridge import session

KEY = "session-test-key-0123456789"


class SessionServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = session.SessionServer(0, KEY, ttl=120, max_commands=5, idle_timeout=120)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_signed_command_runs(self) -> None:
        result = session.call_session(self.url, KEY, "echo hello-session")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("hello-session", result["stdout"])
        self.assertEqual(result["commands_left"], 4)

    def test_wrong_key_is_rejected(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            session.call_session(self.url, "wrong-key", "echo nope")
        self.assertIn("401", str(ctx.exception))

    def test_command_budget_is_enforced(self) -> None:
        for _ in range(5):
            session.call_session(self.url, KEY, "echo ok")
        with self.assertRaises(RuntimeError) as ctx:
            session.call_session(self.url, KEY, "echo over")
        self.assertIn("budget", str(ctx.exception))

    def test_replay_is_rejected(self) -> None:
        body = session.sign_exec(KEY, "echo once")
        # normalize ts so the second call is byte-identical
        body["ts"] = int(body["ts"])
        import json
        import urllib.error
        import urllib.request

        def post(payload: dict) -> int:
            request = urllib.request.Request(
                self.url + "/exec",
                data=json.dumps(payload).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(post(body), 200)
        self.assertEqual(post(body), 400)

    def test_unsigned_command_is_rejected(self) -> None:
        import json
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            self.url + "/exec",
            data=json.dumps({"cmd_b64": "ZWNobyBoaQ==", "ts": 0, "nonce": "x", "sig": "nope"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(ctx.exception.code, 401)

    def test_health(self) -> None:
        info = session.fetch_session_url(self.url)
        self.assertTrue(info["ok"])
        self.assertEqual(info["commands"], 0)


if __name__ == "__main__":
    unittest.main()
