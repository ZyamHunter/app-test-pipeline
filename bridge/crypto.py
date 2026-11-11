"""HMAC signing shared by the local CLI and the workflow.

Design goal: the long-lived shared key (``BRIDGE_KEY``) never travels inside a
dispatch payload.  The payload carries only a short-lived signature over the
exact command, the nonce, the timestamp and the callback URL.  A leaked
signature is useless after ``MAX_SKEW_SECONDS`` and cannot be re-pointed at a
different command or a different callback.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional

PROTOCOL_VERSION = "v1"

#: How far in the past/future a signed request may be.
MAX_SKEW_SECONDS = 300

#: How far in the past/future a signed session (ngrok) request may be.  The
#: session endpoint is short-lived, so the window can be tighter.
SESSION_MAX_SKEW_SECONDS = 120


class SignatureError(ValueError):
    """Raised when a signed payload is missing, malformed, stale or forged."""


def generate_key(nbytes: int = 32) -> str:
    """Return a fresh URL-safe random key (used for ``BRIDGE_KEY``)."""
    return secrets.token_urlsafe(nbytes)


def canonical(
    *,
    version: str,
    ts: int | str,
    nonce: str,
    cmd_b64: str,
    callback: str = "",
) -> bytes:
    """Build the exact byte string that gets signed.

    Newline separated so that no field can be smuggled into another one.
    """
    return "\n".join(
        [str(version), str(ts), str(nonce), str(cmd_b64), str(callback or "")]
    ).encode("utf-8")


def sign(
    key: str,
    *,
    ts: int | str,
    nonce: str,
    cmd_b64: str,
    callback: str = "",
    version: str = PROTOCOL_VERSION,
) -> str:
    """Return a lowercase hex HMAC-SHA256 signature."""
    if not key:
        raise SignatureError("BRIDGE_KEY is empty")
    digest = hmac.new(
        key.encode("utf-8"),
        canonical(
            version=version, ts=ts, nonce=nonce, cmd_b64=cmd_b64, callback=callback
        ),
        hashlib.sha256,
    )
    return digest.hexdigest()


def verify(
    key: str,
    *,
    ts: int | str,
    nonce: str,
    cmd_b64: str,
    sig: str,
    callback: str = "",
    version: str = PROTOCOL_VERSION,
    max_skew: int = MAX_SKEW_SECONDS,
    now: Optional[float] = None,
) -> None:
    """Validate a signature or raise :class:`SignatureError`.

    Constant-time comparison, explicit clock-window check.
    """
    if not key:
        raise SignatureError("server has no BRIDGE_KEY configured")
    if not sig:
        raise SignatureError("request has no signature")
    if not nonce:
        raise SignatureError("request has no nonce")

    current = time.time() if now is None else now
    try:
        ts_int = int(ts)
    except (TypeError, ValueError) as exc:
        raise SignatureError("invalid timestamp") from exc

    if abs(current - ts_int) > max_skew:
        raise SignatureError(
            f"timestamp is outside the +/-{max_skew}s window "
            "(check the clock of the machine that signed the request)"
        )

    expected = sign(
        key,
        ts=ts_int,
        nonce=nonce,
        cmd_b64=cmd_b64,
        callback=callback,
        version=version,
    )
    if not hmac.compare_digest(expected, str(sig).strip().lower()):
        raise SignatureError("signature mismatch")


def sign_body(key: str, body: bytes, ts: int | str) -> str:
    """Sign an arbitrary HTTP body together with its timestamp.

    Used for runner -> developer callbacks, where the body is JSON rather than
    the fixed request envelope.
    """
    if not key:
        raise SignatureError("BRIDGE_KEY is empty")
    mac = hmac.new(key.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(str(ts).encode("ascii") + b"." + body)
    return mac.hexdigest()


def verify_body(
    key: str,
    body: bytes,
    ts: int | str,
    sig: str,
    *,
    max_skew: int = MAX_SKEW_SECONDS,
    now: Optional[float] = None,
) -> None:
    """Verify a body signature produced by :func:`sign_body`."""
    if not key:
        raise SignatureError("server has no BRIDGE_KEY configured")
    if not sig:
        raise SignatureError("request has no signature")
    current = time.time() if now is None else now
    try:
        ts_int = int(ts)
    except (TypeError, ValueError) as exc:
        raise SignatureError("invalid timestamp") from exc
    if abs(current - ts_int) > max_skew:
        raise SignatureError(f"timestamp is outside the +/-{max_skew}s window")
    if not hmac.compare_digest(sign_body(key, body, ts_int), str(sig).strip().lower()):
        raise SignatureError("body signature mismatch")
