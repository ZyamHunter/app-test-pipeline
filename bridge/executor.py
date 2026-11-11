"""Command execution, output capture and secret redaction.

Shared by the workflow step that runs a dispatched command and by the optional
ngrok session server.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence

DEFAULT_TIMEOUT = 600
DEFAULT_MAX_OUTPUT = 512 * 1024  # 512 KiB per stream
TRUNCATION_MARKER = "\n[... gh-bridge: output truncated, {} bytes dropped ...]\n"


class CommandError(RuntimeError):
    """Configuration problem, not a command failure."""


class CommandNotAllowed(CommandError):
    """The command did not match ``BRIDGE_ALLOWLIST``."""


@dataclass
class ExecResult:
    cmd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated_stdout: int = 0
    truncated_stderr: int = 0
    started_at: str = ""
    finished_at: str = ""
    extra: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> Dict[str, object]:
        data = asdict(self)
        data["ok"] = self.exit_code == 0
        return data


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def default_shell_argv(cmd: str) -> List[str]:
    """Pick a shell that behaves the same locally and on ubuntu runners."""
    if os.name == "nt":
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if not pwsh:
            raise CommandError("no PowerShell found on PATH")
        return [pwsh, "-NoProfile", "-NonInteractive", "-Command", cmd]
    bash = shutil.which("bash") or "/bin/bash"
    return [bash, "-lc", cmd]


def check_allowlist(cmd: str, allowlist: Optional[str]) -> None:
    """Enforce an optional regex allowlist (one expression per line)."""
    if not allowlist or not allowlist.strip():
        return
    patterns = [line.strip() for line in allowlist.splitlines() if line.strip()]
    for pattern in patterns:
        try:
            if re.search(pattern, cmd):
                return
        except re.error as exc:
            raise CommandError(f"invalid BRIDGE_ALLOWLIST pattern {pattern!r}: {exc}") from exc
    raise CommandNotAllowed(
        "command rejected by BRIDGE_ALLOWLIST (none of the configured patterns matched)"
    )


def _redact(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, "***")
    return text


def _truncate(text: str, limit: int) -> tuple[str, int]:
    """Keep the tail of the stream: test failures are reported at the end."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, 0
    dropped = len(encoded) - limit
    tail = encoded[-limit:].decode("utf-8", errors="replace")
    return tail + TRUNCATION_MARKER.format(dropped), dropped


def child_env(secrets: Sequence[str] = ()) -> Dict[str, str]:
    """Environment for the executed command.

    Deliberately strips every bridge/CI credential so the command cannot read
    the key that authorised it, nor the job token.
    """
    blocked = {
        "BRIDGE_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    }
    env = {k: v for k, v in os.environ.items() if k not in blocked}
    env["GH_BRIDGE"] = "1"
    return env


def run_command(
    cmd: str,
    *,
    cwd: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    redact: Sequence[str] = (),
    argv: Optional[Sequence[str]] = None,
) -> ExecResult:
    """Run ``cmd`` and capture its output.

    Never raises for a non-zero exit code: that is data, returned in the
    result.  Raises :class:`CommandError` only for local misconfiguration.
    """
    if timeout <= 0:
        raise CommandError("timeout must be positive")
    if max_output <= 0:
        raise CommandError("max_output must be positive")

    full_argv = list(argv) if argv else default_shell_argv(cmd)
    started = _now_iso()
    t0 = time.monotonic()
    timed_out = False

    proc = subprocess.Popen(
        full_argv,
        cwd=cwd or os.getcwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_env(),
        start_new_session=(os.name != "nt"),
        creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
    )
    try:
        raw_out, raw_err = proc.communicate(timeout=timeout)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            raw_out, raw_err = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            raw_out, raw_err = b"", b""
        exit_code = 124

    duration_ms = int((time.monotonic() - t0) * 1000)
    stdout = _redact(_decode(raw_out), redact)
    stderr = _redact(_decode(raw_err), redact)
    stdout, drop_out = _truncate(stdout, max_output)
    stderr, drop_err = _truncate(stderr, max_output)

    return ExecResult(
        cmd=cmd,
        exit_code=int(exit_code if exit_code is not None else 1),
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        timed_out=timed_out,
        truncated_stdout=drop_out,
        truncated_stderr=drop_err,
        started_at=started,
        finished_at=_now_iso(),
    )


def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw
    return raw.decode("utf-8", errors="replace")


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the whole process group so a timed-out test cannot linger."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def format_result(result: ExecResult) -> str:
    """Human readable block used by the CLI and the callback listener."""
    lines = []
    status = "OK" if result.exit_code == 0 else f"FAILED (exit {result.exit_code})"
    if result.timed_out:
        status += " [timed out]"
    lines.append(f"command : {result.cmd.splitlines()[0][:160]}")
    lines.append(f"status  : {status}")
    lines.append(f"duration: {result.duration_ms / 1000:.2f}s")
    if result.stdout:
        lines.append("--- stdout ---")
        lines.append(result.stdout.rstrip("\n"))
    if result.stderr:
        lines.append("--- stderr ---")
        lines.append(result.stderr.rstrip("\n"))
    return "\n".join(lines)
