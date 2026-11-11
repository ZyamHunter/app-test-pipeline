"""Expose a local port through ngrok or a Cloudflare quick tunnel.

Only needed for the optional *session* mode (a runner that accepts commands for
a few minutes) and for the optional callback listener.  The normal bridge mode
needs no tunnel at all.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional


class TunnelError(RuntimeError):
    """The tunnel agent could not be started or never reported a URL."""


@dataclass
class Tunnel:
    kind: str
    url: str
    proc: subprocess.Popen
    port: int
    _log: List[str] = field(default_factory=list)

    def stop(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],
                    capture_output=True,
                    check=False,
                )
            else:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        except OSError:
            pass


def _which(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise TunnelError(f"{binary} not found on PATH")
    return path


def start_ngrok(port: int, *, timeout: float = 25, region: Optional[str] = None) -> Tunnel:
    """Start ``ngrok http <port>`` and wait for its public URL."""
    binary = _which("ngrok")
    cmd = [binary, "http", str(port), "--log=stdout", "--log-format=json"]
    if region:
        cmd += ["--region", region]
    env = dict(os.environ)
    # ngrok v3 reads this env var; passing --authtoken would expose it in ps.
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise TunnelError(
                "ngrok exited immediately. Is NGROK_AUTHTOKEN configured? "
                "Run 'ngrok config add-authtoken <token>' once."
            )
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:4040/api/tunnels", timeout=3
            ) as response:
                data = json.loads(response.read().decode("utf-8"))
            for tunnel in data.get("tunnels", []):
                url = tunnel.get("public_url") or ""
                if url.startswith("https://"):
                    return Tunnel(kind="ngrok", url=url, proc=proc, port=port)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            last_error = str(exc)
        time.sleep(1)
    proc.kill()
    raise TunnelError(f"ngrok did not report a public URL in {timeout:.0f}s ({last_error})")


def start_cloudflared(port: int, *, timeout: float = 40) -> Tunnel:
    """Start ``cloudflared tunnel --url http://127.0.0.1:<port>``."""
    binary = _which("cloudflared")
    proc = subprocess.Popen(
        [binary, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    found: dict[str, str] = {}
    stop = threading.Event()

    def _scan() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            if "trycloudflare.com" in line:
                for token in line.split():
                    if token.startswith("https://") and "trycloudflare.com" in token:
                        found["url"] = token.strip()
                        stop.set()
                        return

    threading.Thread(target=_scan, daemon=True).start()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if "url" in found:
            return Tunnel(kind="cloudflared", url=found["url"], proc=proc, port=port)
        if proc.poll() is not None:
            raise TunnelError("cloudflared exited before reporting a URL")
        time.sleep(0.5)
    proc.kill()
    raise TunnelError(f"cloudflared did not report a URL in {timeout:.0f}s")


def start_tunnel(kind: str, port: int, **kwargs) -> Tunnel:
    """Dispatch to the requested tunnel implementation."""
    kind = (kind or "none").lower()
    if kind == "ngrok":
        return start_ngrok(port, **kwargs)
    if kind in {"cloudflared", "cloudflare"}:
        return start_cloudflared(port, **kwargs)
    raise TunnelError(f"unknown tunnel kind {kind!r} (use ngrok, cloudflared or none)")
