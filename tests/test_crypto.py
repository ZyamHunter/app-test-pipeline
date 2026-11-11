"""Tests for the signing primitives."""
from __future__ import annotations

import unittest

from bridge import crypto

KEY = "unit-test-key-0123456789abcdef"
TS = 1_700_000_000


class CryptoTest(unittest.TestCase):
    def test_sign_verify_roundtrip(self) -> None:
        sig = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="cHl0aGVzdA==")
        crypto.verify(
            KEY, ts=TS, nonce="n1", cmd_b64="cHl0aGVzdA==", sig=sig, now=TS + 10
        )

    def test_signature_is_stable(self) -> None:
        a = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="aGk=")
        b = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="aGk=")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_tampered_command_is_rejected(self) -> None:
        sig = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="aGk=")
        with self.assertRaises(crypto.SignatureError):
            crypto.verify(KEY, ts=TS, nonce="n1", cmd_b64="ZGF0YQ==", sig=sig, now=TS)

    def test_callback_is_bound_to_the_signature(self) -> None:
        sig = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="aGk=", callback="https://a")
        with self.assertRaises(crypto.SignatureError):
            crypto.verify(
                KEY,
                ts=TS,
                nonce="n1",
                cmd_b64="aGk=",
                sig=sig,
                callback="https://evil",
                now=TS,
            )

    def test_expired_request_is_rejected(self) -> None:
        sig = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="aGk=")
        with self.assertRaises(crypto.SignatureError):
            crypto.verify(KEY, ts=TS, nonce="n1", cmd_b64="aGk=", sig=sig, now=TS + 301)

    def test_wrong_key_is_rejected(self) -> None:
        sig = crypto.sign(KEY, ts=TS, nonce="n1", cmd_b64="aGk=")
        with self.assertRaises(crypto.SignatureError):
            crypto.verify("other-key", ts=TS, nonce="n1", cmd_b64="aGk=", sig=sig, now=TS)

    def test_missing_key_is_rejected(self) -> None:
        with self.assertRaises(crypto.SignatureError):
            crypto.sign("", ts=TS, nonce="n1", cmd_b64="aGk=")

    def test_body_signature_roundtrip(self) -> None:
        body = b'{"exit_code": 0}'
        sig = crypto.sign_body(KEY, body, TS)
        crypto.verify_body(KEY, body, TS, sig, now=TS + 5)
        with self.assertRaises(crypto.SignatureError):
            crypto.verify_body(KEY, body + b" ", TS, sig, now=TS + 5)

    def test_generated_keys_are_unique(self) -> None:
        self.assertNotEqual(crypto.generate_key(), crypto.generate_key())


if __name__ == "__main__":
    unittest.main()
