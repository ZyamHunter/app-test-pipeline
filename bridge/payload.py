"""The request envelope that travels through ``repository_dispatch``.

Everything that reaches the workflow is safe to appear in a log: the command is
base64 encoded (so multi-line commands survive JSON/env round-trips intact) and
the only secret-derived value is a short-lived HMAC signature.
"""

from __future__ import annotations

import base64
import binascii
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from . import crypto


class PayloadError(ValueError):
    """Raised when a client payload cannot be decoded."""


def encode_cmd(cmd: str) -> str:
    """Encode a command so newlines/quotes survive any transport."""
    if not isinstance(cmd, str):
        raise PayloadError("command must be a string")
    return base64.b64encode(cmd.encode("utf-8")).decode("ascii")


def decode_cmd(cmd_b64: str) -> str:
    """Inverse of :func:`encode_cmd`."""
    if not cmd_b64:
        raise PayloadError("command is empty")
    try:
        raw = base64.b64decode(str(cmd_b64).encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise PayloadError("command is not valid base64") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadError("command is not valid UTF-8") from exc


def new_nonce() -> str:
    """Short, log-friendly correlation id for one dispatched command."""
    return uuid.uuid4().hex[:16]


@dataclass
class BridgeRequest:
    """A decoded, already-verified bridge request."""

    cmd: str
    nonce: str
    ts: int
    cmd_b64: str
    callback: str = ""
    sig: str = ""
    version: str = crypto.PROTOCOL_VERSION
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "nonce": self.nonce,
            "cmd": self.cmd,
            "callback": self.callback,
            "ts": self.ts,
        }


def build_request(
    cmd: str,
    key: str,
    *,
    callback: str = "",
    nonce: Optional[str] = None,
    ts: Optional[int] = None,
    version: str = crypto.PROTOCOL_VERSION,
) -> Dict[str, Any]:
    """Build the ``client_payload`` dict for a dispatch."""
    cmd = cmd.strip("\n")
    if not cmd.strip():
        raise PayloadError("refusing to dispatch an empty command")
    cmd_b64 = encode_cmd(cmd)
    nonce = nonce or new_nonce()
    ts = int(ts if ts is not None else time.time())
    sig = crypto.sign(
        key, ts=ts, nonce=nonce, cmd_b64=cmd_b64, callback=callback, version=version
    )
    return {
        "v": version,
        "ts": ts,
        "nonce": nonce,
        "cmd_b64": cmd_b64,
        "callback": callback,
        "sig": sig,
    }


def parse_request(payload: Dict[str, Any], key: str, *, now: Optional[float] = None) -> BridgeRequest:
    """Validate the signature and return the decoded request.

    Raises :class:`PayloadError` on anything unexpected.
    """
    if not isinstance(payload, dict):
        raise PayloadError("client_payload is not an object")

    version = str(payload.get("v") or crypto.PROTOCOL_VERSION)
    nonce = str(payload.get("nonce") or "")
    cmd_b64 = str(payload.get("cmd_b64") or "")
    callback = str(payload.get("callback") or "")
    sig = str(payload.get("sig") or "")

    try:
        ts = int(payload.get("ts", 0))
    except (TypeError, ValueError) as exc:
        raise PayloadError("invalid ts") from exc

    try:
        crypto.verify(
            key,
            ts=ts,
            nonce=nonce,
            cmd_b64=cmd_b64,
            sig=sig,
            callback=callback,
            version=version,
            now=now,
        )
    except crypto.SignatureError as exc:
        raise PayloadError(str(exc)) from exc

    return BridgeRequest(
        cmd=decode_cmd(cmd_b64),
        nonce=nonce,
        ts=ts,
        cmd_b64=cmd_b64,
        callback=callback,
        sig=sig,
        version=version,
    )
