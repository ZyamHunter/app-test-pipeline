"""Command line interface for gh-bridge.

Local side:  init / doctor / keygen / run / listen / session
Runner side: verify / execute / summary / notify / session-serve
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__, crypto, executor, payload, session
from .gh import DISPATCH_EVENT, GitHubClient, GitHubError, summarize_run
from .server import CallbackServer
from .tunnel import TunnelError, start_tunnel

CONFIG_FILE = "config.json"
KEY_FILE = "key"
SESSION_WORKFLOW = "bridge-session.yml"
DEFAULT_SESSION_TTL = 600


# --------------------------------------------------------------------- utils
def _home() -> Path:
    custom = os.environ.get("BRIDGE_HOME")
    return Path(custom) if custom else Path.home() / ".gh-bridge"


def config_path() -> Path:
    return _home() / CONFIG_FILE


def default_key_path() -> Path:
    return _home() / KEY_FILE


def load_config() -> Dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {}
    try:
        # utf-8-sig: tolerate the BOM that Windows PowerShell adds.
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        _print_err(f"warning: ignoring invalid config at {path}: {exc}")
        return {}


def save_config(data: Dict[str, Any]) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_key(explicit_file: Optional[str] = None) -> str:
    env_key = os.environ.get("BRIDGE_KEY")
    if env_key and env_key.strip():
        return env_key.strip()
    for candidate in (explicit_file, load_config().get("key_file"), str(default_key_path())):
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists():
            value = path.read_text(encoding="utf-8-sig").strip()
            if value:
                return value
    raise SystemExit(
        "no BRIDGE_KEY found.\n"
        "  Run 'gh-bridge init --repo <owner/name>' or set the BRIDGE_KEY env var."
    )


def save_key(key: str, path: Optional[Path] = None) -> Path:
    target = path or default_key_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(key + "\n", encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return target


def resolve_repo(args: argparse.Namespace) -> str:
    repo = getattr(args, "repo", None) or os.environ.get("BRIDGE_REPO") or load_config().get("repo")
    if not repo:
        raise SystemExit(
            "no repository configured.\n"
            "  Pass --repo <owner/name>, set BRIDGE_REPO, or run 'gh-bridge init'."
        )
    return str(repo)


def _print_err(message: str) -> None:
    print(message, file=sys.stderr)


def _require_gh() -> str:
    gh = shutil.which("gh")
    if not gh:
        raise SystemExit("the GitHub CLI ('gh') is required for this command")
    return gh


def _set_secret(repo: str, name: str, value: str) -> None:
    """Upload a repository secret without exposing it in the process list."""
    gh = _require_gh()
    proc = subprocess.run(
        [gh, "secret", "set", name, "--repo", repo],
        input=value,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"failed to set secret {name} on {repo}: "
            f"{(proc.stderr or proc.stdout).strip()}"
        )


def _emit_mask(value: str) -> None:
    """Ask the Actions runner to mask a value in all further log output."""
    if value:
        print(f"::add-mask::{value}", flush=True)


# ------------------------------------------------------------------ commands
def cmd_keygen(args: argparse.Namespace) -> int:
    key = crypto.generate_key()
    path = Path(args.out).expanduser() if args.out else None
    if path:
        save_key(key, path)
        print(f"key written to {path}")
    else:
        print(key)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    repo = args.repo or os.environ.get("BRIDGE_REPO")
    if not repo:
        raise SystemExit("usage: gh-bridge init --repo <owner/name> [--rotate]")
    client = GitHubClient(repo)
    if not client.token:
        raise SystemExit("no GitHub token: run 'gh auth login' first")

    try:
        info = client.repo_info()
    except GitHubError as exc:
        raise SystemExit(f"cannot access {repo}: {exc}") from exc

    key_path = default_key_path()
    key = None
    if key_path.exists() and not args.rotate:
        key = key_path.read_text(encoding="utf-8").strip()
        print(f"keeping existing local key at {key_path}")
    if not key:
        key = crypto.generate_key()
        save_key(key)
        print(f"generated new key at {key_path}")

    _set_secret(client.repo, "BRIDGE_KEY", key)
    print(f"secret BRIDGE_KEY uploaded to {client.repo}")

    config = load_config()
    config.update({"repo": client.repo, "key_file": str(key_path)})
    save_config(config)
    print(f"config written to {config_path()}")

    print()
    print(f"repo      : {info.get('full_name')} ({'public' if not info.get('private') else 'private'})")
    print(f"default   : {info.get('default_branch')}")
    print()
    print("next steps:")
    print("  1. push .github/workflows/ to the default branch")
    print('  2. gh-bridge doctor')
    print('  3. gh-bridge run -- "echo hello from GitHub"')
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    repo = args.repo or load_config().get("repo")
    ok = True
    print(f"gh-bridge {__version__}")

    key = None
    try:
        key = load_key(args.key_file)
    except SystemExit:
        key = None
    if key:
        fingerprint = crypto.sign(key, ts=0, nonce="fingerprint", cmd_b64="")[:12]
        print(f"  [ok] local key present (fingerprint {fingerprint})")
    else:
        ok = False
        print("  [!!] no local key (run: gh-bridge init --repo <owner/name>)")

    if not repo:
        print("  [!!] no repository configured (--repo or gh-bridge init)")
        return 1
    client = GitHubClient(repo)
    print(f"  [{'ok' if client.token else '!!'}] GitHub token")
    ok = ok and bool(client.token)
    if not client.token:
        return 1

    try:
        info = client.repo_info()
        visibility = "private" if info.get("private") else "public"
        print(f"  [ok] repo {info.get('full_name')} ({visibility}), default branch {info.get('default_branch')}")
    except GitHubError as exc:
        print(f"  [!!] repo: {exc}")
        return 1

    try:
        workflows = client.json("GET", f"/repos/{client.repo}/actions/workflows") or {}
        names = [f"{w.get('name')} [{Path(str(w.get('path'))).name}]" for w in workflows.get("workflows", [])]
        bridge_present = any("bridge.yml" in str(w.get("path")) for w in workflows.get("workflows", []))
        print(f"  [{'ok' if bridge_present else '!!'}] workflow bridge.yml on default branch")
        for name in names[:10]:
            print(f"        - {name}")
        ok = ok and bridge_present
    except GitHubError as exc:
        print(f"  [??] workflows: {exc}")

    try:
        secrets = client.list_secret_names()
        print(f"  [{'ok' if 'BRIDGE_KEY' in secrets else '!!'}] repository secret BRIDGE_KEY")
        ok = ok and "BRIDGE_KEY" in secrets
    except GitHubError as exc:
        print(f"  [??] secrets: {exc} (needs admin access)")

    if shutil.which("ngrok"):
        print("  [ok] ngrok available (session mode)")
    else:
        print("  [--] ngrok not found (session mode disabled)")

    print()
    print("ready" if ok else "not ready - fix the [!!] lines above")
    return 0 if ok else 1


def cmd_run(args: argparse.Namespace) -> int:
    command = _join_command(args.command)
    if not command.strip():
        raise SystemExit("usage: gh-bridge run -- <command>")
    client = GitHubClient(resolve_repo(args))
    key = load_key(args.key_file)

    request = payload.build_request(command, key, callback=args.callback or "")
    if args.dry_run:
        print(json.dumps(request, indent=2))
        return 0

    client.dispatch(DISPATCH_EVENT, request)
    nonce = request["nonce"]
    print(f"dispatched nonce {nonce} to {client.repo}")

    if args.no_wait:
        print(f"track it: https://github.com/{client.repo}/actions")
        return 0

    try:
        run = client.find_run(nonce, timeout=args.queue_timeout)
    except GitHubError as exc:
        raise SystemExit(str(exc)) from exc

    run_id = int(run["id"])
    print(f"run {run_id}: https://github.com/{client.repo}/actions/runs/{run_id}")
    run = client.wait_run(
        run_id,
        timeout=args.wait_timeout,
        on_update=lambda r: print(f"  status: {summarize_run(r)}", flush=True),
    )

    if run.get("status") != "completed":
        print("timed out waiting for the run; check the URL above")
        return 2

    result = client.read_result(run_id, nonce)
    if result is None:
        print("no result artifact found; falling back to the run log tail")
        tail = client.download_logs(run_id)
        if tail:
            print(tail)
        return 0 if run.get("conclusion") == "success" else 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_result(result, run_url=f"https://github.com/{client.repo}/actions/runs/{run_id}")

    return int(result.get("exit_code", 0))


def _join_command(parts: Sequence[str]) -> str:
    items = list(parts)
    if items and items[0] == "--":
        items = items[1:]
    if len(items) == 1:
        return items[0]
    return " ".join(items)


def _print_result(result: Dict[str, Any], *, run_url: str = "") -> None:
    status = "OK" if result.get("exit_code") == 0 else f"FAILED (exit {result.get('exit_code')})"
    if result.get("timed_out"):
        status += " [timed out]"
    print()
    print(f"status  : {status}")
    print(f"duration: {int(result.get('duration_ms', 0)) / 1000:.2f}s")
    if run_url:
        print(f"run     : {run_url}")
    if result.get("stdout"):
        print("--- stdout ---")
        print(str(result["stdout"]).rstrip("\n"))
    if result.get("stderr"):
        print("--- stderr ---")
        print(str(result["stderr"]).rstrip("\n"))
    if result.get("truncated_stdout") or result.get("truncated_stderr"):
        print("(output was truncated at the bridge limit)")


def cmd_listen(args: argparse.Namespace) -> int:
    key = load_key(args.key_file)
    received: List[Dict[str, Any]] = []
    done = threading.Event()

    def on_result(item: Any) -> None:
        received.append(item.payload)
        done.set()

    server = CallbackServer(args.port, key, on_result, expect_nonce=args.nonce)
    server.start_background()
    tunnel = None
    public = f"http://127.0.0.1:{server.port}"
    try:
        if args.tunnel != "none":
            tunnel = start_tunnel(args.tunnel, server.port)
            public = tunnel.url
        print(f"listening on {public}/bridge/result")
        print("pass this URL with: gh-bridge run --callback <url> -- <command>")
        deadline = time.monotonic() + args.timeout
        while not done.is_set() and time.monotonic() < deadline:
            time.sleep(0.2)
    except KeyboardInterrupt:
        return 130
    finally:
        server.stop()
        if tunnel:
            tunnel.stop()

    if not received:
        print("no result received before the timeout")
        return 2
    result = received[0]
    _print_result(result)
    return int(result.get("exit_code", 0))


def cmd_session(args: argparse.Namespace) -> int:
    client = GitHubClient(resolve_repo(args))
    key = load_key(args.key_file)
    nonce = payload.new_nonce()
    ref = args.ref or "main"

    inputs = {"nonce": nonce, "ttl": str(args.ttl), "tunnel": args.tunnel}
    client.dispatch_workflow(SESSION_WORKFLOW, ref, inputs)
    print(f"dispatched session {nonce} to {client.repo} (ref {ref})")

    try:
        run = client.find_run(nonce, event="workflow_dispatch", timeout=args.queue_timeout)
    except GitHubError as exc:
        raise SystemExit(str(exc)) from exc
    run_id = int(run["id"])
    print(f"run {run_id}: https://github.com/{client.repo}/actions/runs/{run_id}")

    artifact_name = f"session-url-{nonce}"
    deadline = time.monotonic() + args.wait_timeout
    url = ""
    while time.monotonic() < deadline and not url:
        raw = client.read_artifact_file(run_id, artifact_name, "session.json", timeout=5)
        if raw:
            data = json.loads(raw.decode("utf-8"))
            url = str(data.get("url") or "")
            break
        time.sleep(3)
    if not url:
        print("the session did not publish a URL in time; check the run above")
        return 2

    print(f"session url: {url}")
    try:
        health = session.fetch_session_url(url)
        print(f"session healthy: {json.dumps(health)}")
    except RuntimeError as exc:
        _print_err(str(exc))
        return 2

    try:
        if args.cmd:
            return _session_oneshot(url, key, args.cmd, args.json)
        if args.script:
            return _session_script(url, key, args.script, args.json)
        return _session_repl(url, key, args.json)
    finally:
        _session_shutdown(url, key)


def _session_oneshot(url: str, key: str, cmd: str, as_json: bool) -> int:
    try:
        result = session.call_session(url, key, cmd)
    except RuntimeError as exc:
        _print_err(str(exc))
        return 2
    if as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_result(result)
    return int(result.get("exit_code", 0))


def _session_script(url: str, key: str, script: str, as_json: bool) -> int:
    lines = Path(script).read_text(encoding="utf-8").splitlines()
    last = 0
    for line in lines:
        cmd = line.strip()
        if not cmd or cmd.startswith("#"):
            continue
        print(f"\n$ {cmd}")
        last = _session_oneshot(url, key, cmd, as_json)
        if last != 0 and not as_json:
            print("(continuing after failure)")
    return last


def _session_repl(url: str, key: str, as_json: bool) -> int:
    print("interactive session - type a command, ':quit' to leave")
    last = 0
    while True:
        try:
            line = input("bridge> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in {":quit", ":q", "exit", "quit"}:
            break
        if cmd == ":help":
            print("commands run on the GitHub runner; ':quit' closes the session")
            continue
        last = _session_oneshot(url, key, cmd, as_json)
    return last


def _session_shutdown(url: str, key: str) -> None:
    try:
        session.request_shutdown(url, key)
    except Exception:  # noqa: BLE001 - best effort
        pass


# --------------------------------------------------------------- runner side
def cmd_verify(args: argparse.Namespace) -> int:
    key = os.environ.get("BRIDGE_KEY", "")
    sig = os.environ.get("BRIDGE_SIG", "")
    _emit_mask(sig)

    if not key:
        _print_err("BRIDGE_KEY secret is not configured on this repository")
        return 2

    try:
        request = payload.parse_request(
            {
                "v": os.environ.get("BRIDGE_VERSION", crypto.PROTOCOL_VERSION),
                "ts": os.environ.get("BRIDGE_TS", "0"),
                "nonce": os.environ.get("BRIDGE_NONCE", ""),
                "cmd_b64": os.environ.get("BRIDGE_CMD_B64", ""),
                "callback": os.environ.get("BRIDGE_CALLBACK", ""),
                "sig": sig,
            },
            key,
        )
    except payload.PayloadError as exc:
        _print_err(f"rejected bridge request: {exc}")
        return 2

    _write_request(args.out, request)
    print(f"request accepted: nonce={request.nonce} cmd={len(request.cmd)} bytes")
    return 0


def cmd_manual(args: argparse.Namespace) -> int:
    """Prepare a request for a ``workflow_dispatch`` run (trusted UI path)."""
    cmd = os.environ.get("BRIDGE_CMD", "")
    if not cmd.strip():
        _print_err("empty command")
        return 2
    nonce = os.environ.get("BRIDGE_NONCE") or payload.new_nonce()
    request = payload.BridgeRequest(
        cmd=cmd, nonce=nonce, ts=int(time.time()), cmd_b64=payload.encode_cmd(cmd)
    )
    _write_request(args.out, request)
    print(f"manual request prepared: nonce={nonce}")
    return 0


def _write_request(path: str, request: payload.BridgeRequest) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(request.to_json(), indent=2), encoding="utf-8")


def _read_json(path: str, what: str) -> Dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"{what} not found at {path}; did the previous step fail?") from exc
    except ValueError as exc:
        raise SystemExit(f"{what} at {path} is not valid JSON: {exc}") from exc


def cmd_execute(args: argparse.Namespace) -> int:
    request = _read_json(args.request, "request file")
    cmd = str(request.get("cmd") or "")
    if not cmd.strip():
        _print_err("empty command in request")
        return 2

    allowlist = os.environ.get("BRIDGE_ALLOWLIST", "")
    timeout = int(os.environ.get("BRIDGE_TIMEOUT", executor.DEFAULT_TIMEOUT))
    max_output = int(os.environ.get("BRIDGE_MAX_OUTPUT", executor.DEFAULT_MAX_OUTPUT))
    echo = os.environ.get("BRIDGE_ECHO_OUTPUT", "false").lower() == "true"
    extra = [item for item in os.environ.get("BRIDGE_REDACT", "").split(",") if item]
    secrets = [os.environ.get("BRIDGE_KEY", "")] + extra

    print(f"executing in {os.getcwd()} (timeout {timeout}s)")
    try:
        executor.check_allowlist(cmd, allowlist)
        result = executor.run_command(
            cmd, timeout=timeout, max_output=max_output, redact=secrets
        )
    except executor.CommandNotAllowed as exc:
        _print_err(str(exc))
        result = executor.ExecResult(
            cmd=cmd, exit_code=126, stdout="", stderr=str(exc), duration_ms=0
        )
    except executor.CommandError as exc:
        _print_err(str(exc))
        result = executor.ExecResult(
            cmd=cmd, exit_code=2, stdout="", stderr=str(exc), duration_ms=0
        )

    data = result.to_json()
    data["nonce"] = request.get("nonce", "")
    data["run_url"] = _run_url()
    data["repo"] = os.environ.get("GITHUB_REPOSITORY", "")
    data["sha"] = os.environ.get("GITHUB_SHA", "")
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        f"exit={result.exit_code} duration={result.duration_ms}ms "
        f"stdout={len(result.stdout)}B stderr={len(result.stderr)}B"
    )
    if echo:
        print("--- stdout ---")
        print(result.stdout)
        print("--- stderr ---")
        print(result.stderr)
    else:
        print(f"output captured in artifact bridge-result-{data['nonce']} (not printed: public logs)")
    return result.exit_code


def cmd_summary(args: argparse.Namespace) -> int:
    request = _read_json(args.request, "request file")
    result = _read_json(args.result, "result file")
    status = "success" if result.get("exit_code") == 0 else "failure"
    icon = "✅" if status == "success" else "❌"
    print(f"## {icon} gh-bridge command {status}")
    print()
    print("| field | value |")
    print("| --- | --- |")
    print(f"| nonce | `{request.get('nonce', '')}` |")
    print(f"| exit code | `{result.get('exit_code')}` |")
    print(f"| duration | {int(result.get('duration_ms', 0)) / 1000:.2f}s |")
    print(f"| timed out | `{bool(result.get('timed_out'))}` |")
    if os.environ.get("BRIDGE_ECHO_OUTPUT", "false").lower() == "true":
        print()
        print("<details><summary>output</summary>")
        print()
        print("```")
        print((result.get("stdout") or "").rstrip())
        print((result.get("stderr") or "").rstrip())
        print("```")
        print()
        print("</details>")
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    request = _read_json(args.request, "request file")
    result = _read_json(args.result, "result file")
    callback = str(request.get("callback") or "")
    if not callback:
        print("no callback configured; nothing to do")
        return 0
    key = os.environ.get("BRIDGE_KEY", "")
    if not key:
        _print_err("BRIDGE_KEY missing; cannot sign the callback")
        return 2

    body = json.dumps(
        {
            "event": "result",
            "nonce": request.get("nonce", ""),
            "cmd": request.get("cmd", ""),
            "exit_code": result.get("exit_code"),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "duration_ms": result.get("duration_ms", 0),
            "timed_out": result.get("timed_out", False),
            "truncated_stdout": result.get("truncated_stdout", 0),
            "truncated_stderr": result.get("truncated_stderr", 0),
            "run_url": result.get("run_url", ""),
        },
        ensure_ascii=False,
    ).encode("utf-8")

    last_error = ""
    for attempt in range(1, 4):
        ts = int(time.time())
        sig = crypto.sign_body(key, body, ts)
        request_obj = urllib.request.Request(
            callback,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Bridge-Timestamp": str(ts),
                "X-Bridge-Signature": sig,
                "User-Agent": "gh-bridge/0.1",
                "ngrok-skip-browser-warning": "true",
            },
        )
        try:
            with urllib.request.urlopen(request_obj, timeout=20) as response:
                print(f"callback delivered ({response.status}) - attempt {attempt}")
                return 0
        except Exception as exc:  # noqa: BLE001 - network errors are all retryable here
            last_error = str(exc)
            time.sleep(2 * attempt)
    _print_err(f"callback failed after 3 attempts: {last_error}")
    return 0  # never fail the build because the developer machine is offline


def cmd_session_serve(args: argparse.Namespace) -> int:
    key = os.environ.get("BRIDGE_KEY", "")
    if not key:
        _print_err("BRIDGE_KEY is not configured")
        return 2

    nonce = args.nonce or os.environ.get("BRIDGE_NONCE") or payload.new_nonce()
    server = session.SessionServer(
        args.port,
        key,
        ttl=args.ttl,
        max_commands=args.max_commands,
        idle_timeout=args.idle_timeout,
        allowlist=os.environ.get("BRIDGE_ALLOWLIST"),
        timeout=int(os.environ.get("BRIDGE_TIMEOUT", 300)),
    )
    tunnel = None
    try:
        tunnel = start_tunnel(args.tunnel, server.port, timeout=60)
    except TunnelError as exc:
        server.shutdown()
        _print_err(f"cannot open the session tunnel: {exc}")
        return 2

    info = {
        "url": tunnel.url,
        "nonce": nonce,
        "expires_in": args.ttl,
        "kind": tunnel.kind,
        "max_commands": args.max_commands,
    }
    target = Path(args.url_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(f"BRIDGE_SESSION_URL={tunnel.url}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"\n### bridge session\n\n`{tunnel.url}`\n")

    try:
        stats = server.serve_session()
    finally:
        tunnel.stop()
        try:
            server.server_close()
        except Exception:  # noqa: BLE001
            pass
    print(f"session closed: {stats.stop_reason}; commands={stats.commands} rejected={stats.rejected}")
    return 0


def _run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not repo or not run_id:
        return ""
    return f"{server}/{repo}/actions/runs/{run_id}"


# ---------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gh-bridge",
        description="Run local commands on GitHub Actions and read the results back.",
    )
    parser.add_argument("--version", action="version", version=f"gh-bridge {__version__}")
    sub = parser.add_subparsers(dest="command_name", required=True)

    keygen = sub.add_parser("keygen", help="generate a BRIDGE_KEY")
    keygen.add_argument("--out", help="write the key to this file")
    keygen.set_defaults(func=cmd_keygen)

    init = sub.add_parser("init", help="create a local key, upload the secret, write config")
    init.add_argument("--repo", help="owner/name")
    init.add_argument("--rotate", action="store_true", help="replace the existing key")
    init.set_defaults(func=cmd_init)

    doctor = sub.add_parser("doctor", help="check repo, secret, workflow and token")
    doctor.add_argument("--repo")
    doctor.add_argument("--key-file")
    doctor.set_defaults(func=cmd_doctor)

    run = sub.add_parser("run", help="dispatch a command and wait for its output")
    run.add_argument("--repo")
    run.add_argument("--key-file")
    run.add_argument("--callback", help="public URL that should receive the result")
    run.add_argument("--json", action="store_true", help="print the raw result JSON")
    run.add_argument("--no-wait", action="store_true", help="dispatch and exit")
    run.add_argument("--dry-run", action="store_true", help="print the payload, send nothing")
    run.add_argument("--queue-timeout", type=float, default=120)
    run.add_argument("--wait-timeout", type=float, default=1800)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    listen = sub.add_parser("listen", help="receive a signed result callback")
    listen.add_argument("--port", type=int, default=8787)
    listen.add_argument("--tunnel", choices=["ngrok", "cloudflared", "none"], default="ngrok")
    listen.add_argument("--timeout", type=float, default=1800)
    listen.add_argument("--nonce", help="only accept this nonce")
    listen.add_argument("--key-file")
    listen.set_defaults(func=cmd_listen)

    sess = sub.add_parser("session", help="open an interactive session on a runner")
    sess.add_argument("--repo")
    sess.add_argument("--key-file")
    sess.add_argument("--ttl", type=int, default=DEFAULT_SESSION_TTL)
    sess.add_argument("--tunnel", choices=["ngrok", "cloudflared"], default="ngrok")
    sess.add_argument("--ref", default="main")
    sess.add_argument("--cmd", help="run one command and exit")
    sess.add_argument("--script", help="run commands from a file, one per line")
    sess.add_argument("--json", action="store_true")
    sess.add_argument("--queue-timeout", type=float, default=180)
    sess.add_argument("--wait-timeout", type=float, default=240)
    sess.set_defaults(func=cmd_session)

    verify = sub.add_parser("verify", help="[runner] verify the dispatched payload")
    verify.add_argument("--out", default=".bridge/request.json")
    verify.set_defaults(func=cmd_verify)

    manual = sub.add_parser("manual", help="[runner] build a request for workflow_dispatch")
    manual.add_argument("--out", default=".bridge/request.json")
    manual.set_defaults(func=cmd_manual)

    execute = sub.add_parser("execute", help="[runner] run the verified command")
    execute.add_argument("--request", default=".bridge/request.json")
    execute.add_argument("--out", default=".bridge/result.json")
    execute.set_defaults(func=cmd_execute)

    summary = sub.add_parser("summary", help="[runner] print the job summary markdown")
    summary.add_argument("--request", default=".bridge/request.json")
    summary.add_argument("--result", default=".bridge/result.json")
    summary.set_defaults(func=cmd_summary)

    notify = sub.add_parser("notify", help="[runner] POST the signed result to the callback")
    notify.add_argument("--request", default=".bridge/request.json")
    notify.add_argument("--result", default=".bridge/result.json")
    notify.set_defaults(func=cmd_notify)

    serve = sub.add_parser("session-serve", help="[runner] tunnel + execute signed commands")
    serve.add_argument("--port", type=int, default=8788)
    serve.add_argument("--ttl", type=int, default=DEFAULT_SESSION_TTL)
    serve.add_argument("--max-commands", type=int, default=50)
    serve.add_argument("--idle-timeout", type=int, default=180)
    serve.add_argument("--tunnel", choices=["ngrok", "cloudflared"], default="ngrok")
    serve.add_argument("--url-file", default=".bridge/session.json")
    serve.add_argument("--nonce")
    serve.set_defaults(func=cmd_session_serve)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except GitHubError as exc:
        _print_err(f"github: {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
