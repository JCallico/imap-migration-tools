"""GitHub CLI wrapper used for every GitHub interaction made by the agent loop."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .engines import is_blocked_variable


class GhError(RuntimeError):
    """Raised when a ``gh`` command fails."""

    def __init__(self, args: Sequence[str], returncode: int, stderr: str):
        self.args_list = list(args)
        self.returncode = returncode
        self.stderr = stderr.strip()
        super().__init__(f"gh {' '.join(_redact(args)[:4])} failed ({returncode}): {self.stderr[:300]}")


def _redact(args: Sequence[str]) -> list[str]:
    redacted = []
    for arg in args:
        redacted.append("Authorization: <redacted>" if arg.lower().startswith("authorization:") else arg)
    return redacted


Runner = Callable[..., subprocess.CompletedProcess]
TokenProvider = Callable[[], str]


class Gh:
    """Run ``gh`` with JSON output, optionally authenticated as the GitHub App installation."""

    def __init__(
        self,
        repo: str | None,
        token_provider: TokenProvider | None = None,
        runner: Runner = subprocess.run,
        base_env: Mapping[str, str] | None = None,
    ):
        self.repo = repo
        self.token_provider = token_provider
        self.runner = runner
        self.base_env = dict(os.environ if base_env is None else base_env)

    @property
    def as_app(self) -> bool:
        return self.token_provider is not None

    def environment(self, *, authenticated: bool = True) -> dict[str, str]:
        env = {key: value for key, value in self.base_env.items() if not is_blocked_variable(key)}
        env["GH_PROMPT_DISABLED"] = "1"
        env["NO_COLOR"] = "1"
        if authenticated and self.token_provider is not None:
            env["GH_TOKEN"] = self.token_provider()
        return env

    def run(self, args: Sequence[str], *, input_text: str | None = None, authenticated: bool = True) -> str:
        command = ["gh", *args]
        completed = self.runner(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            env=self.environment(authenticated=authenticated),
            check=False,
            timeout=120,
        )
        if completed.returncode != 0:
            raise GhError(args, completed.returncode, completed.stderr or completed.stdout or "")
        return completed.stdout or ""

    def json(self, args: Sequence[str], **kwargs) -> Any:
        output = self.run(args, **kwargs)
        return json.loads(output) if output.strip() else None

    def api(
        self,
        path: str,
        *,
        method: str = "GET",
        fields: Mapping[str, Any] | None = None,
        body: Any = None,
        paginate: bool = False,
        headers: Sequence[str] = (),
        authenticated: bool = True,
    ) -> Any:
        """Call ``gh api``; ``fields`` become typed ``-F`` parameters, ``body`` is sent as JSON on stdin."""
        args = ["api", "--method", method, path]
        for header in headers:
            args += ["-H", header]
        for key, value in (fields or {}).items():
            args += ["-F" if isinstance(value, (bool, int)) else "-f", f"{key}={_field(value)}"]
        input_text = None
        if body is not None:
            args += ["--input", "-"]
            input_text = json.dumps(body)
        if paginate:
            args += ["--paginate", "--slurp"]
        result = self.json(args, input_text=input_text, authenticated=authenticated)
        if paginate and isinstance(result, list) and all(isinstance(page, list) for page in result):
            return [item for page in result for item in page]
        return result

    def graphql(self, query: str, variables: Mapping[str, Any] | None = None) -> dict:
        args = ["api", "graphql", "-f", f"query={query}"]
        for key, value in (variables or {}).items():
            if value is None:
                continue
            args += ["-F" if isinstance(value, (bool, int)) else "-f", f"{key}={_field(value)}"]
        result = self.json(args)
        if not isinstance(result, dict):
            raise GhError(args, 0, "unexpected GraphQL response")
        if result.get("errors"):
            raise GhError(args, 0, json.dumps(result["errors"])[:500])
        return result.get("data") or {}

    def repo_parts(self) -> tuple[str, str]:
        if not self.repo or "/" not in self.repo:
            raise GhError(["repo"], 1, "repository is not configured; set [github] repo or AGENT_LOOP_REPO")
        owner, name = self.repo.split("/", 1)
        return owner, name


def _field(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def detect_repo(runner: Runner = subprocess.run) -> str | None:
    """Return ``owner/name`` of the current checkout's GitHub repository, if ``gh`` can resolve it."""
    try:
        completed = runner(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    value = (completed.stdout or "").strip()
    return value if completed.returncode == 0 and "/" in value else None
