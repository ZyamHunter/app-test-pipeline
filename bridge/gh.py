"""Minimal GitHub REST client (stdlib only) for Actions dispatch + results.

Only the endpoints the bridge needs are implemented, with explicit error
messages so a misconfigured repo fails loudly instead of silently.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Callable, Dict, Iterable, List, Optional

API_ROOT = "https://api.github.com"
USER_AGENT = "gh-bridge/0.1 (+https://github.com)"
ACCEPT = "application/vnd.github+json"
API_VERSION = "2022-11-28"

#: ``event_type`` sent in the dispatch call.
DISPATCH_EVENT = "bridge-cmd"

#: Value of the ``event`` field in the Actions API (not the same thing!).
REPOSITORY_EVENT = "repository_dispatch"


class GitHubError(RuntimeError):
    """Any non-success answer from the GitHub API."""

    def __init__(self, message: str, status: Optional[int] = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Artifact/download URLs redirect to pre-signed blob storage.

    Forwarding the Authorization header to that host makes Azure reject the
    request, so drop it on cross-host redirects.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(
            req.full_url
        ).netloc:
            new.remove_header("Authorization")
        return new


def resolve_token(explicit: Optional[str] = None) -> Optional[str]:
    """Token from flag, then env, then the ``gh`` CLI keyring."""
    if explicit:
        return explicit.strip()
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "BRIDGE_GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value.strip()
    gh = shutil.which("gh")
    if gh:
        try:
            proc = subprocess.run(
                [gh, "auth", "token"], capture_output=True, text=True, timeout=20
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def split_repo(repo: str) -> tuple[str, str]:
    """Accept ``owner/name`` or a full github URL."""
    value = repo.strip().rstrip("/")
    if value.startswith("http"):
        parts = urllib.parse.urlsplit(value).path.strip("/").split("/")
    else:
        parts = value.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise GitHubError(f"invalid repository {repo!r}; expected 'owner/name'")
    name = parts[1]
    if name.endswith(".git"):
        name = name[: -len(".git")]
    return parts[0], name


class GitHubClient:
    """Thin wrapper over the REST endpoints used by the bridge."""

    def __init__(
        self,
        repo: str,
        token: Optional[str] = None,
        *,
        api_root: str = API_ROOT,
        timeout: int = 30,
    ):
        self.owner, self.name = split_repo(repo)
        self.repo = f"{self.owner}/{self.name}"
        self.token = resolve_token(token)
        self.api_root = api_root.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_StripAuthOnRedirect)

    # ------------------------------------------------------------------ http
    def _headers(self, raw: bool = False) -> Dict[str, str]:
        headers = {
            # The artifact/log endpoints reject 'application/octet-stream'.
            "Accept": "*/*" if raw else ACCEPT,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _open(
        self,
        method: str,
        url: str,
        *,
        body: Optional[bytes] = None,
        raw: bool = False,
    ):
        request = urllib.request.Request(
            url, data=body, headers=self._headers(raw=raw), method=method
        )
        return self._opener.open(request, timeout=self.timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        raw: bool = False,
    ) -> bytes:
        if not self.token:
            raise GitHubError(
                "no GitHub token: run 'gh auth login', or set GH_TOKEN"
            )
        url = path if path.startswith("http") else f"{self.api_root}{path}"
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
        try:
            with self._open(method, url, body=body, raw=raw) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GitHubError(
                _friendly_http_error(exc.code, url, detail), exc.code, detail
            ) from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"cannot reach {url}: {exc.reason}") from exc

    def json(self, method: str, path: str, **kwargs: Any) -> Any:
        raw = self.request(method, path, **kwargs)
        if not raw:
            return None
        return json.loads(raw.decode("utf-8"))

    # -------------------------------------------------------------- dispatch
    def dispatch(self, event_type: str, client_payload: Dict[str, Any]) -> None:
        """Fire a ``repository_dispatch`` event (returns 204, no body)."""
        self.request(
            "POST",
            f"/repos/{self.repo}/dispatches",
            json_body={"event_type": event_type, "client_payload": client_payload},
        )

    def dispatch_workflow(
        self, workflow_id: str, ref: str, inputs: Dict[str, str]
    ) -> None:
        """Trigger a ``workflow_dispatch`` workflow by file name or id."""
        self.request(
            "POST",
            f"/repos/{self.repo}/actions/workflows/{urllib.parse.quote(workflow_id)}/dispatches",
            json_body={"ref": ref, "inputs": inputs},
        )

    # ------------------------------------------------------------------ runs
    def repo_info(self) -> Dict[str, Any]:
        return self.json("GET", f"/repos/{self.repo}")

    def list_runs(
        self, *, event: Optional[str] = None, per_page: int = 50
    ) -> List[Dict[str, Any]]:
        query = {"per_page": str(per_page)}
        if event:
            query["event"] = event
        path = f"/repos/{self.repo}/actions/runs?" + urllib.parse.urlencode(query)
        data = self.json("GET", path) or {}
        return list(data.get("workflow_runs") or [])

    def get_run(self, run_id: int) -> Dict[str, Any]:
        return self.json("GET", f"/repos/{self.repo}/actions/runs/{run_id}")

    def find_run(
        self,
        nonce: str,
        *,
        event: Optional[str] = REPOSITORY_EVENT,
        since: Optional[float] = None,
        timeout: float = 120,
        interval: float = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Dict[str, Any]:
        """Poll until the run carrying ``nonce`` in its title shows up."""
        deadline = time.monotonic() + timeout
        started = time.monotonic()
        while True:
            events: List[Optional[str]] = [event]
            # If the event filter finds nothing, retry unfiltered: some runs
            # are reported under a different event name than expected.
            if event and time.monotonic() - started > 15:
                events.append(None)
            for current_event in events:
                for run in self.list_runs(event=current_event, per_page=50):
                    haystack = " ".join(
                        str(run.get(key) or "")
                        for key in ("display_title", "name", "head_branch")
                    )
                    if nonce in haystack:
                        return run
            if time.monotonic() >= deadline:
                raise GitHubError(
                    f"no run found for nonce {nonce} after {timeout:.0f}s "
                    "(is the workflow on the default branch? does it use run-name with the nonce?)"
                )
            sleep(interval)

    def wait_run(
        self,
        run_id: int,
        *,
        timeout: float = 1800,
        interval: float = 3,
        on_update: Optional[Callable[[Dict[str, Any]], None]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Dict[str, Any]:
        """Block until the run completes (or ``timeout`` elapses)."""
        deadline = time.monotonic() + timeout
        last_status = None
        while True:
            run = self.get_run(run_id)
            status = run.get("status")
            if status != last_status and on_update:
                on_update(run)
            last_status = status
            if status == "completed":
                return run
            if time.monotonic() >= deadline:
                return run
            sleep(interval)

    # ------------------------------------------------------------- artifacts
    def list_artifacts(self, run_id: int) -> List[Dict[str, Any]]:
        data = self.json("GET", f"/repos/{self.repo}/actions/runs/{run_id}/artifacts") or {}
        return list(data.get("artifacts") or [])

    def find_artifact(
        self,
        run_id: int,
        name: str,
        *,
        timeout: float = 60,
        interval: float = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Optional[Dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while True:
            for artifact in self.list_artifacts(run_id):
                if artifact.get("name") == name and not artifact.get("expired"):
                    return artifact
            if time.monotonic() >= deadline:
                return None
            sleep(interval)

    def download_artifact(self, artifact_id: int) -> bytes:
        return self.request(
            "GET",
            f"/repos/{self.repo}/actions/artifacts/{artifact_id}/zip",
            raw=True,
        )

    def read_artifact_file(
        self,
        run_id: int,
        artifact_name: str,
        filename: str,
        *,
        timeout: float = 60,
    ) -> Optional[bytes]:
        artifact = self.find_artifact(run_id, artifact_name, timeout=timeout)
        if not artifact:
            return None
        blob = self.download_artifact(int(artifact["id"]))
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for member in archive.namelist():
                if os.path.basename(member) == filename:
                    return archive.read(member)
        return None

    def read_result(self, run_id: int, nonce: str) -> Optional[Dict[str, Any]]:
        raw = self.read_artifact_file(run_id, f"bridge-result-{nonce}", "result.json")
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    # ------------------------------------------------------------------ logs
    def download_logs(self, run_id: int, *, max_chars: int = 20000) -> str:
        """Best-effort plain-text tail of a run's logs (public repos: readable)."""
        try:
            blob = self.request(
                "GET", f"/repos/{self.repo}/actions/runs/{run_id}/logs", raw=True
            )
        except GitHubError:
            return ""
        chunks: List[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                for member in archive.namelist():
                    if member.endswith(".txt"):
                        chunks.append(archive.read(member).decode("utf-8", errors="replace"))
        except zipfile.BadZipFile:
            return ""
        text = "\n".join(chunks)
        return text[-max_chars:]

    # --------------------------------------------------------------- secrets
    def list_secret_names(self) -> List[str]:
        data = self.json("GET", f"/repos/{self.repo}/actions/secrets") or {}
        return [item.get("name", "") for item in data.get("secrets", [])]

    def list_variable_names(self) -> List[str]:
        data = self.json("GET", f"/repos/{self.repo}/actions/variables") or {}
        return [item.get("name", "") for item in data.get("variables", [])]


def _friendly_http_error(code: int, url: str, detail: str) -> str:
    hint = ""
    if code == 401:
        hint = " (bad or expired token)"
    elif code == 403:
        hint = " (token lacks repo/workflow scope, or rate limited)"
    elif code == 404:
        hint = (
            " (repo/workflow not found, or the token cannot see it; "
            "repository_dispatch only works from the default branch)"
        )
    elif code == 422:
        hint = " (payload rejected - check the workflow inputs)"
    try:
        message = json.loads(detail).get("message", "")
    except (ValueError, AttributeError):
        message = ""
    return f"GitHub API {code}{hint}: {message or detail[:300]} [{url}]"


def summarize_run(run: Dict[str, Any]) -> str:
    """One-line status used by the CLI progress output."""
    status = run.get("status") or "?"
    conclusion = run.get("conclusion") or ""
    return f"{status}{'/' + conclusion if conclusion else ''}"
