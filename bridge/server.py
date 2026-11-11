"""Optional HTTPS callback receiver (runner -> developer machine).

The runner POSTs the signed result as soon as the command finishes, so the
local CLI can show it without polling artifacts.  Requires a public tunnel
(ngrok/cloudflared) pointing at this server.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional

from . import crypto

MAX_BODY = 8 * 1024 * 1024


@dataclass
class ReceivedResult:
    payload: Dict[str, Any]
    verified: bool
    raw_size: int


class _Handler(BaseHTTPRequestHandler):
    server_version = "gh-bridge/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep the console clean: only bridge events are printed.
        return

    def _reply(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in {"/health", "/"}:
            self._reply(200, {"ok": True, "service": "gh-bridge-callback"})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        server: "CallbackServer" = self.server  # type: ignore[assignment]
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._reply(413, {"error": "body too large or empty"})
            return
        body = self.rfile.read(length)

        if self.path not in {"/bridge/result", "/result"}:
            self._reply(404, {"error": "not found"})
            return

        ts = self.headers.get("X-Bridge-Timestamp", "")
        sig = self.headers.get("X-Bridge-Signature", "")
        verified = True
        reason = ""
        try:
            crypto.verify_body(server.key, body, ts, sig)
        except crypto.SignatureError as exc:
            verified = False
            reason = str(exc)

        if not verified:
            self._reply(401, {"error": reason})
            return

        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._reply(400, {"error": "invalid json"})
            return

        if server.expect_nonce and payload.get("nonce") not in {None, server.expect_nonce}:
            self._reply(409, {"error": "unexpected nonce"})
            return

        server.on_result(ReceivedResult(payload=payload, verified=True, raw_size=len(body)))
        self._reply(200, {"ok": True})


class CallbackServer(ThreadingHTTPServer):
    """Small, signed, single-purpose HTTP receiver."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        port: int,
        key: str,
        on_result: Callable[[ReceivedResult], None],
        *,
        expect_nonce: Optional[str] = None,
        host: str = "127.0.0.1",
    ):
        super().__init__((host, port), _Handler)
        self.key = key
        self.on_result = on_result
        self.expect_nonce = expect_nonce

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        try:
            self.shutdown()
        except Exception:  # noqa: BLE001 - shutdown must never mask the real error
            pass
        try:
            self.server_close()
        except Exception:  # noqa: BLE001
            pass
