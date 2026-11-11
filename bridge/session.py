"""Optional "session" mode: a runner that accepts signed commands for a while.

This is the literal "ngrok link that receives commands" part of the bridge.
It is intentionally constrained:

* every request is HMAC-signed with ``BRIDGE_KEY`` and expires in 120 s;
* a nonce cannot be replayed;
* the server dies after a TTL, after N commands, or after an idle period;
* the executed command never sees ``BRIDGE_KEY`` nor the job token.

Prefer the normal ``run`` mode (one dispatch per command) unless you really
need an interactive shell on the runner.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from . import crypto, executor, payload

MAX_BODY = 2 * 1024 * 1024


def sign_exec(key: str, cmd: str, *, nonce: Optional[str] = None, ts: Optional[int] = None) -> Dict[str, Any]:
    """Build the signed JSON body for one session command."""
    cmd = cmd.strip("\n")
    if not cmd.strip():
        raise payload.PayloadError("refusing to send an empty command")
    cmd_b64 = payload.encode_cmd(cmd)
    nonce = nonce or uuid.uuid4().hex[:16]
    ts = int(ts if ts is not None else time.time())
    sig = crypto.sign(key, ts=ts, nonce=nonce, cmd_b64=cmd_b64)
    return {
        "v": crypto.PROTOCOL_VERSION,
        "ts": ts,
        "nonce": nonce,
        "cmd_b64": cmd_b64,
        "sig": sig,
    }


@dataclass
class SessionStats:
    commands: int = 0
    rejected: int = 0
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    stop_reason: str = ""


class SessionServer(ThreadingHTTPServer):
    """HTTPServer that executes signed commands until it decides to stop."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        port: int,
        key: str,
        *,
        ttl: int = 600,
        max_commands: int = 50,
        idle_timeout: int = 180,
        allowlist: Optional[str] = None,
        timeout: int = 300,
        max_output: int = executor.DEFAULT_MAX_OUTPUT,
        host: str = "127.0.0.1",
    ):
        super().__init__((host, port), _SessionHandler)
        self.key = key
        self.ttl = max(30, int(ttl))
        self.max_commands = max(1, int(max_commands))
        self.idle_timeout = max(30, int(idle_timeout))
        self.allowlist = allowlist
        self.timeout = timeout
        self.max_output = max_output
        self.stats = SessionStats()
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ------------------------------------------------------------------ life
    @property
    def port(self) -> int:
        return int(self.server_address[1])

    @property
    def expires_at(self) -> float:
        return self.stats.started_at + self.ttl

    def shutdown_async(self, reason: str) -> None:
        with self._lock:
            if self._stop.is_set():
                return
            self._stop.set()
            self.stats.stop_reason = reason
        threading.Thread(target=self.shutdown, daemon=True).start()

    def _watchdog(self) -> None:
        while not self._stop.is_set():
            now = time.time()
            if now >= self.expires_at:
                self.shutdown_async("ttl reached")
                return
            if now - self.stats.last_activity > self.idle_timeout:
                self.shutdown_async("idle timeout")
                return
            time.sleep(2)

    def serve_session(self) -> SessionStats:
        threading.Thread(target=self._watchdog, daemon=True).start()
        try:
            self.serve_forever(poll_interval=0.5)
        finally:
            self.server_close()
        if not self.stats.stop_reason:
            self.stats.stop_reason = "stopped"
        return self.stats

    # ---------------------------------------------------------------- execute
    def execute(self, body: Dict[str, Any]) -> Dict[str, Any]:
        nonce = str(body.get("nonce") or "")
        cmd_b64 = str(body.get("cmd_b64") or "")
        try:
            ts = int(body.get("ts", 0))
        except (TypeError, ValueError):
            raise payload.PayloadError("invalid ts")

        crypto.verify(
            self.key,
            ts=ts,
            nonce=nonce,
            cmd_b64=cmd_b64,
            sig=str(body.get("sig") or ""),
            max_skew=crypto.SESSION_MAX_SKEW_SECONDS,
        )
        with self._lock:
            if nonce in self._seen:
                raise payload.PayloadError("replayed nonce")
            self._seen.add(nonce)
            if len(self._seen) > 4096:
                self._seen = set(list(self._seen)[-2048:])

        cmd = payload.decode_cmd(cmd_b64)
        executor.check_allowlist(cmd, self.allowlist)

        with self._lock:
            if self.stats.commands >= self.max_commands:
                raise payload.PayloadError("command budget exhausted")
            self.stats.commands += 1
        self.stats.last_activity = time.time()

        result = executor.run_command(
            cmd,
            timeout=self.timeout,
            max_output=self.max_output,
            redact=[self.key],
        )
        data = result.to_json()
        data["nonce"] = nonce
        data["commands_left"] = max(0, self.max_commands - self.stats.commands)
        data["expires_in"] = max(0, int(self.expires_at - time.time()))
        return data

    # ----------------------------------------------------------------- control
    def verify_control(self, body: Dict[str, Any]) -> None:
        """Authenticate a ``:shutdown`` request (no command is executed)."""
        cmd_b64 = str(body.get("cmd_b64") or "")
        crypto.verify(
            self.key,
            ts=int(body.get("ts", 0)),
            nonce=str(body.get("nonce") or ""),
            cmd_b64=cmd_b64,
            sig=str(body.get("sig") or ""),
            max_skew=crypto.SESSION_MAX_SKEW_SECONDS,
        )
        if payload.decode_cmd(cmd_b64) != ":shutdown":
            raise payload.PayloadError("unexpected control command")


class _SessionHandler(BaseHTTPRequestHandler):
    server_version = "gh-bridge-session/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _reply(self, code: int, payload_data: Dict[str, Any]) -> None:
        raw = json.dumps(payload_data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    @property
    def session(self) -> SessionServer:
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:  # noqa: N802
        if self.path in {"/health", "/"}:
            self._reply(
                200,
                {
                    "ok": True,
                    "service": "gh-bridge-session",
                    "commands": self.session.stats.commands,
                    "commands_left": max(0, self.session.max_commands - self.session.stats.commands),
                    "expires_in": max(0, int(self.session.expires_at - time.time())),
                },
            )
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._reply(413, {"error": "body too large or empty"})
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._reply(400, {"error": "invalid json"})
            return

        if self.path == "/exec":
            try:
                self._reply(200, self.session.execute(body))
            except crypto.SignatureError as exc:
                self.session.stats.rejected += 1
                self._reply(401, {"error": str(exc)})
            except executor.CommandNotAllowed as exc:
                self.session.stats.rejected += 1
                self._reply(403, {"error": str(exc)})
            except payload.PayloadError as exc:
                self.session.stats.rejected += 1
                self._reply(400, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001 - never leak a traceback to the client
                self.session.stats.rejected += 1
                self._reply(500, {"error": f"internal error: {type(exc).__name__}"})
            return

        if self.path == "/shutdown":
            try:
                self.session.verify_control(body)
            except crypto.SignatureError as exc:
                self.session.stats.rejected += 1
                self._reply(401, {"error": str(exc)})
                return
            except payload.PayloadError as exc:
                self.session.stats.rejected += 1
                self._reply(400, {"error": str(exc)})
                return
            self._reply(200, {"ok": True})
            self.session.shutdown_async("shutdown requested")
            return

        self._reply(404, {"error": "not found"})


# --------------------------------------------------------------------- client
def call_session(
    url: str,
    key: str,
    cmd: str,
    *,
    timeout: float = 600,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Send one signed command to a running session and return its result."""
    body = json.dumps(sign_exec(key, cmd, nonce=nonce)).encode("utf-8")
    endpoint = url.rstrip("/")
    if not endpoint.endswith("/exec"):
        endpoint += "/exec"
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "gh-bridge/0.1",
            "ngrok-skip-browser-warning": "true",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"session rejected the request ({exc.code}): {detail[:300]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach the session: {exc.reason}") from exc


def request_shutdown(url: str, key: str, *, timeout: float = 10) -> Dict[str, Any]:
    """Sign and send a ``:shutdown`` control request (best effort)."""
    body = json.dumps(sign_exec(key, ":shutdown")).encode("utf-8")
    request = urllib.request.Request(
        url.rstrip("/") + "/shutdown",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "gh-bridge/0.1",
            "ngrok-skip-browser-warning": "true",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_session_url(
    url: str, *, timeout: float = 30, attempts: int = 3
) -> Dict[str, Any]:
    """GET /health, used to confirm the tunnel is really serving."""
    last: Optional[Exception] = None
    for _ in range(max(1, attempts)):
        try:
            request = urllib.request.Request(
                url.rstrip("/") + "/health",
                headers={"User-Agent": "gh-bridge/0.1", "ngrok-skip-browser-warning": "true"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError, OSError) as exc:
            last = exc
            time.sleep(2)
    raise RuntimeError(f"session health check failed: {last}")
