"""Integration tests for the signed callback receiver (localhost only)."""
from __future__ import annotations

import json
import time
import unittest
import urllib.error
import urllib.request

from bridge import crypto
from bridge.server import CallbackServer

KEY = "callback-test-key-0123456789"


class CallbackServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.received = []
        self.server = CallbackServer(0, KEY, self.received.append)
        self.thread = self.server.start_background()
        self.url = f"http://127.0.0.1:{self.server.port}/bridge/result"

    def tearDown(self) -> None:
        self.server.stop()
        self.thread.join(timeout=5)

    def _post(self, body: bytes, ts: int, sig: str) -> int:
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Bridge-Timestamp": str(ts),
                "X-Bridge-Signature": sig,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_signed_result_is_accepted(self) -> None:
        body = json.dumps({"nonce": "abc", "exit_code": 0, "stdout": "ok"}).encode()
        ts = int(time.time())
        status = self._post(body, ts, crypto.sign_body(KEY, body, ts))
        self.assertEqual(status, 200)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0].payload["nonce"], "abc")

    def test_unsigned_result_is_rejected(self) -> None:
        body = b'{"nonce":"abc","exit_code":0}'
        self.assertEqual(self._post(body, int(time.time()), "deadbeef"), 401)
        self.assertEqual(self.received, [])

    def test_stale_result_is_rejected(self) -> None:
        body = b'{"nonce":"abc","exit_code":0}'
        ts = int(time.time()) - 3600
        self.assertEqual(self._post(body, ts, crypto.sign_body(KEY, body, ts)), 401)

    def test_health_endpoint(self) -> None:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.server.port}/health", timeout=10
        ) as response:
            payload = json.loads(response.read())
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
