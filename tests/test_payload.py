"""Tests for the dispatch payload envelope."""
from __future__ import annotations

import time
import unittest

from bridge import payload

KEY = "unit-test-key-0123456789abcdef"


class PayloadTest(unittest.TestCase):
    def test_roundtrip_multiline_unicode(self) -> None:
        cmd = "pytest -q\n# comentário ção\necho 'fim'"
        request = payload.build_request(cmd, KEY)
        parsed = payload.parse_request(request, KEY)
        self.assertEqual(parsed.cmd, cmd)
        self.assertEqual(parsed.nonce, request["nonce"])

    def test_payload_contains_no_key(self) -> None:
        request = payload.build_request("echo hi", KEY)
        self.assertNotIn(KEY, str(request))

    def test_multiline_command_survives_base64(self) -> None:
        cmd = "a\nb\nc"
        self.assertEqual(payload.decode_cmd(payload.encode_cmd(cmd)), cmd)

    def test_wrong_key_is_rejected(self) -> None:
        request = payload.build_request("echo hi", KEY)
        with self.assertRaises(payload.PayloadError):
            payload.parse_request(request, "another-key")

    def test_tampered_payload_is_rejected(self) -> None:
        request = payload.build_request("echo hi", KEY)
        request["cmd_b64"] = payload.encode_cmd("rm -rf /")
        with self.assertRaises(payload.PayloadError):
            payload.parse_request(request, KEY)

    def test_empty_command_is_rejected(self) -> None:
        with self.assertRaises(payload.PayloadError):
            payload.build_request("   \n ", KEY)

    def test_invalid_base64_is_rejected(self) -> None:
        with self.assertRaises(payload.PayloadError):
            payload.decode_cmd("!!!not-base64!!!")

    def test_callback_is_signed(self) -> None:
        request = payload.build_request("echo hi", KEY, callback="https://example.test/x")
        parsed = payload.parse_request(request, KEY)
        self.assertEqual(parsed.callback, "https://example.test/x")
        request["callback"] = "https://attacker.test/x"
        with self.assertRaises(payload.PayloadError):
            payload.parse_request(request, KEY)

    def test_expired_payload_is_rejected(self) -> None:
        request = payload.build_request("echo hi", KEY)
        with self.assertRaises(payload.PayloadError):
            payload.parse_request(request, KEY, now=time.time() + 400)

    def test_nonce_is_short_and_unique(self) -> None:
        a = payload.new_nonce()
        b = payload.new_nonce()
        self.assertNotEqual(a, b)
        self.assertLessEqual(len(a), 16)


if __name__ == "__main__":
    unittest.main()
