"""Headless Codex and Claude invocation: commands, scrubbed environments, and output parsing."""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .config import ModelRef
from .quota import Classification, RateLimitSnapshot, classify_failure, claude_snapshot, codex_snapshot

READ_ONLY = "read-only"
WORKSPACE_WRITE = "workspace-write"

# Variables a stage process may inherit. Everything else, including repository .env values, is dropped.
BASE_PASSTHROUGH = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TZ",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)

# Variables that would switch a CLI from subscription billing to paid API or cloud billing, or that carry
# credentials a stage must not receive implicitly. They are removed even when listed in env_passthrough.
BLOCKED_VARIABLES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "CODEX_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
    }
)
BLOCKED_PREFIXES = ("AWS_", "GOOGLE_APPLICATION_CREDENTIALS", "VERTEX_")


def is_blocked_variable(name: str) -> bool:
    return name in BLOCKED_VARIABLES or name.startswith(BLOCKED_PREFIXES)


def stage_environment(
    base: Mapping[str, str],
    passthrough: Iterable[str] = (),
    grants: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build an allowlisted environment for a stage process.

    ``grants`` are explicit values the dispatcher hands to a stage (for example a scoped GitHub token in later
    phases); API-key variables are never granted.
    """
    allowed = set(BASE_PASSTHROUGH) | set(passthrough)
    env = {name: value for name, value in base.items() if name in allowed and not is_blocked_variable(name)}
    for name, value in (grants or {}).items():
        if name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY") or name.startswith("AWS_"):
            raise ValueError(f"refusing to grant {name} to a stage process")
        env[name] = value
    return env


def build_command(
    ref: ModelRef,
    *,
    cwd: Path,
    sandbox: str = READ_ONLY,
    resume_session: str | None = None,
    max_turns: int | None = None,
    allowed_tools: Sequence[str] = (),
    output_schema: Path | None = None,
) -> list[str]:
    """Return the argv for a headless run; the prompt is always supplied on stdin."""
    if sandbox not in (READ_ONLY, WORKSPACE_WRITE):
        raise ValueError(f"unsupported sandbox {sandbox!r}")
    if ref.engine == "codex":
        command = ["codex", "exec"]
        if resume_session:
            command.append("resume")
        command += [
            "--json",
            "--ignore-user-config",
            "--skip-git-repo-check",
            "-m",
            ref.model,
            "-c",
            f'model_reasoning_effort="{ref.effort}"',
        ]
        if not resume_session:
            command += ["-s", sandbox, "-C", str(cwd)]
            if output_schema is not None:
                command += ["--output-schema", str(output_schema)]
        else:
            command.append(resume_session)
        command.append("-")
        return command
    if ref.engine == "claude":
        command = [
            "claude",
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--model",
            ref.model,
            "--effort",
            ref.effort,
            "--strict-mcp-config",
            "--permission-mode",
            "acceptEdits" if sandbox == WORKSPACE_WRITE else "default",
        ]
        if max_turns:
            command += ["--max-turns", str(max_turns)]
        if allowed_tools:
            command += ["--allowedTools", ",".join(allowed_tools)]
        if sandbox == READ_ONLY:
            command += ["--disallowedTools", "Edit,Write,NotebookEdit"]
        if resume_session:
            command += ["--resume", resume_session]
        return command
    raise ValueError(f"unknown engine {ref.engine!r}")


@dataclass
class EngineRun:
    """Parsed outcome of one headless engine invocation."""

    engine: str
    requested_model: str
    exit_code: int | None
    session_id: str | None = None
    actual_models: set[str] = field(default_factory=set)
    final_message: str = ""
    error_messages: list[str] = field(default_factory=list)
    task_error: bool = False
    snapshot: RateLimitSnapshot | None = None
    timed_out: bool = False
    duration_seconds: float = 0.0
    classification: Classification | None = None

    @property
    def model_mismatch(self) -> bool:
        """True when the engine reported using a model other than the one requested."""
        return bool(self.actual_models) and self.actual_models != {self.requested_model}


def _json_lines(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def parse_codex_output(run: EngineRun, stdout: str, rollout_text: str | None) -> None:
    """Parse ``codex exec --json`` events and the session rollout file (model and rate-limit telemetry)."""
    for event in _json_lines(stdout):
        kind = event.get("type")
        if kind == "thread.started":
            run.session_id = event.get("thread_id") or run.session_id
        elif kind == "item.completed":
            item = event.get("item") or {}
            if item.get("type") == "agent_message":
                run.final_message = item.get("text") or run.final_message
        elif kind == "error":
            run.error_messages.append(str(event.get("message", "")))
        elif kind == "turn.failed":
            error = event.get("error") or {}
            run.error_messages.append(str(error.get("message", "")) if isinstance(error, dict) else str(error))
            run.task_error = True
    if rollout_text:
        for record in _json_lines(rollout_text):
            payload = record.get("payload") or {}
            if record.get("type") == "turn_context" and payload.get("model"):
                run.actual_models.add(str(payload["model"]))
            elif isinstance(payload, dict) and payload.get("type") == "token_count":
                snapshot = codex_snapshot(payload.get("rate_limits"))
                if snapshot is not None:
                    run.snapshot = snapshot


def parse_claude_output(run: EngineRun, stdout: str) -> None:
    """Parse ``claude -p --output-format stream-json`` events."""
    for event in _json_lines(stdout):
        kind = event.get("type")
        run.session_id = event.get("session_id") or run.session_id
        if kind == "system" and event.get("subtype") == "init" and event.get("model"):
            run.actual_models.add(str(event["model"]))
        elif kind == "rate_limit_event":
            snapshot = claude_snapshot(event.get("rate_limit_info"))
            if snapshot is not None:
                run.snapshot = snapshot
        elif kind == "assistant" and event.get("parent_tool_use_id") is None:
            # Only main-thread turns count; Claude Code may use other models for subagents and housekeeping.
            model = (event.get("message") or {}).get("model")
            if model and not str(model).startswith("<"):
                run.actual_models.add(str(model))
        elif kind == "result":
            run.final_message = str(event.get("result") or "")
            if event.get("is_error"):
                run.task_error = True
                run.error_messages.append(
                    " ".join(
                        str(part)
                        for part in (event.get("subtype"), event.get("api_error_status"), event.get("result"))
                        if part
                    )
                )


def codex_home(environ: Mapping[str, str]) -> Path:
    return Path(environ.get("CODEX_HOME") or Path(environ.get("HOME", str(Path.home()))) / ".codex")


def find_codex_rollout(session_id: str, home: Path) -> Path | None:
    matches = sorted((home / "sessions").glob(f"*/*/*/rollout-*-{session_id}.jsonl"))
    return matches[-1] if matches else None


Runner = Callable[..., subprocess.CompletedProcess]


def run_engine(
    ref: ModelRef,
    command: Sequence[str],
    prompt: str,
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    runner: Runner = subprocess.run,
    clock: Callable[[], float] = time.time,
) -> EngineRun:
    """Run a stage command with a time limit, then parse and classify the result."""
    run = EngineRun(engine=ref.engine, requested_model=ref.model, exit_code=None)
    started = clock()
    stdout = ""
    stderr = ""
    try:
        completed = runner(
            list(command),
            input=prompt,
            capture_output=True,
            text=True,
            cwd=str(cwd),
            env=dict(env),
            timeout=timeout_seconds,
            check=False,
        )
        run.exit_code = completed.returncode
        stdout, stderr = completed.stdout or "", completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        run.timed_out = True
        stdout = _decode(exc.stdout)
        stderr = _decode(exc.stderr)
    run.duration_seconds = clock() - started
    if ref.engine == "codex":
        parse_codex_output(run, stdout, None)
        if run.session_id:
            rollout = find_codex_rollout(run.session_id, codex_home(env))
            if rollout is not None:
                parse_codex_output(run, "", rollout.read_text(encoding="utf-8", errors="replace"))
    else:
        parse_claude_output(run, stdout)
    if stderr.strip():
        run.error_messages.append(stderr.strip()[-2000:])
    run.classification = classify_failure(
        run.exit_code,
        run.error_messages,
        run.snapshot,
        task_error=run.task_error,
        timed_out=run.timed_out,
        now=clock(),
    )
    return run


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def subscription_status(engine: str, runner: Runner = subprocess.run, env: Mapping[str, str] | None = None) -> tuple:
    """Return ``(ok, detail)`` describing whether ``engine`` is signed in with a subscription, not an API key."""
    env = dict(env if env is not None else stage_environment(os.environ))
    try:
        if engine == "codex":
            completed = runner(
                ["codex", "login", "status"], capture_output=True, text=True, env=env, timeout=30, check=False
            )
            text = f"{completed.stdout}\n{completed.stderr}".strip()
            if completed.returncode == 0 and "chatgpt" in text.lower():
                return True, text.splitlines()[0]
            if "api key" in text.lower():
                return False, "Codex is signed in with an API key; run `codex login` with your ChatGPT subscription"
            return False, text.splitlines()[0] if text else "Codex is not signed in; run `codex login`"
        if engine == "claude":
            completed = runner(
                ["claude", "auth", "status", "--json"], capture_output=True, text=True, env=env, timeout=30, check=False
            )
            try:
                data = json.loads(completed.stdout or "{}")
            except json.JSONDecodeError:
                return False, "could not read `claude auth status --json` output"
            if not data.get("loggedIn"):
                return False, "Claude Code is not signed in; run `claude auth login`"
            method = str(data.get("authMethod", ""))
            if method != "claude.ai" or data.get("apiProvider") not in (None, "firstParty"):
                return False, f"Claude Code uses {method or 'an unknown method'}, not a claude.ai subscription"
            return True, f"claude.ai subscription ({data.get('subscriptionType', 'unknown plan')})"
    except FileNotFoundError:
        return False, f"`{engine}` CLI not found on PATH"
    except subprocess.TimeoutExpired:
        return False, f"`{engine}` status check timed out"
    raise ValueError(f"unknown engine {engine!r}")


def codex_models(runner: Runner = subprocess.run, env: Mapping[str, str] | None = None) -> set[str] | None:
    """Return the model slugs in the local Codex catalog, or ``None`` when unavailable."""
    env = dict(env if env is not None else stage_environment(os.environ))
    try:
        completed = runner(
            ["codex", "debug", "models"], capture_output=True, text=True, env=env, timeout=60, check=False
        )
        data = json.loads(completed.stdout or "{}")
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    models = data.get("models") if isinstance(data, dict) else data
    if not isinstance(models, list):
        return None
    return {str(model.get("slug")) for model in models if isinstance(model, dict) and model.get("slug")}
