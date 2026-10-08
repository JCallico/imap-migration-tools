"""Tests for headless engine commands, environment scrubbing, and recorded CLI output parsing."""

import json
import subprocess
from pathlib import Path

import pytest
from agent_loop_fakes import FIXTURES

from agent_loop.config import ModelRef
from agent_loop.engines import (
    READ_ONLY,
    WORKSPACE_WRITE,
    build_command,
    run_engine,
    stage_environment,
    subscription_status,
)
from agent_loop.quota import QUOTA_EXHAUSTED, SUCCESS

CODEX = ModelRef("codex", "gpt-6-luna", "low")
CLAUDE = ModelRef("claude", "claude-haiku-4-5-20251001", "low")


def test_stage_environment_is_allowlisted_and_never_carries_api_keys():
    base = {
        "PATH": "/usr/bin",
        "HOME": "/home/u",
        "IMAP_PASSWORD": "secret",
        "ANTHROPIC_API_KEY": "sk-ant",
        "OPENAI_API_KEY": "sk-openai",
        "GH_TOKEN": "ghp",
        "AWS_ACCESS_KEY_ID": "aws",
        "CUSTOM": "1",
    }

    env = stage_environment(base, passthrough=("CUSTOM", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID"))

    assert env == {"PATH": "/usr/bin", "HOME": "/home/u", "CUSTOM": "1"}


def test_stage_environment_refuses_api_key_grants():
    with pytest.raises(ValueError):
        stage_environment({}, grants={"OPENAI_API_KEY": "x"})
    assert stage_environment({}, grants={"GH_TOKEN": "scoped"}) == {"GH_TOKEN": "scoped"}


def test_codex_command(tmp_path):
    command = build_command(CODEX, cwd=tmp_path, sandbox=READ_ONLY)

    assert command[:2] == ["codex", "exec"]
    assert ["-m", "gpt-6-luna"] == command[command.index("-m") : command.index("-m") + 2]
    assert 'model_reasoning_effort="low"' in command
    assert ["-s", "read-only"] == command[command.index("-s") : command.index("-s") + 2]
    assert "--ignore-user-config" in command and command[-1] == "-"


def test_codex_resume_command(tmp_path):
    command = build_command(CODEX, cwd=tmp_path, resume_session="abc")

    assert command[:3] == ["codex", "exec", "resume"]
    assert command[-2:] == ["abc", "-"]


def test_claude_commands(tmp_path):
    read_only = build_command(CLAUDE, cwd=tmp_path, sandbox=READ_ONLY, max_turns=5, allowed_tools=("Read", "Grep"))
    writable = build_command(CLAUDE, cwd=tmp_path, sandbox=WORKSPACE_WRITE, resume_session="s1")

    assert read_only[:2] == ["claude", "-p"]
    assert "--strict-mcp-config" in read_only
    assert read_only[read_only.index("--disallowedTools") + 1] == "Edit,Write,NotebookEdit"
    assert read_only[read_only.index("--allowedTools") + 1] == "Read,Grep"
    assert read_only[read_only.index("--max-turns") + 1] == "5"
    assert writable[writable.index("--permission-mode") + 1] == "acceptEdits"
    assert writable[-2:] == ["--resume", "s1"]


def completed(stdout, code=0, stderr=""):
    return lambda *args, **kwargs: subprocess.CompletedProcess(args, code, stdout, stderr)


def install_rollout(codex_home: Path, session_id: str) -> None:
    folder = codex_home / "sessions" / "2026" / "10" / "06"
    folder.mkdir(parents=True)
    (folder / f"rollout-2026-10-06T06-28-17-{session_id}.jsonl").write_text(
        (FIXTURES / "codex_rollout_ok.jsonl").read_text()
    )


def test_codex_run_reads_model_and_quota_from_rollout(tmp_path):
    stdout = (FIXTURES / "codex_exec_ok.jsonl").read_text()
    session_id = json.loads(stdout.splitlines()[0])["thread_id"]
    install_rollout(tmp_path / "codex", session_id)

    run = run_engine(
        CODEX,
        ["codex"],
        "prompt",
        cwd=tmp_path,
        env={"CODEX_HOME": str(tmp_path / "codex")},
        timeout_seconds=10,
        runner=completed(stdout),
    )

    assert run.session_id == session_id
    assert run.final_message == "OK"
    assert run.actual_models == {"gpt-6-luna"}
    assert not run.model_mismatch
    assert run.snapshot is not None and run.snapshot.used_percent == 10.0
    assert run.classification.kind == SUCCESS


def test_claude_run_reads_session_model_and_quota(tmp_path):
    stdout = (FIXTURES / "claude_stream_ok.jsonl").read_text()

    run = run_engine(CLAUDE, ["claude"], "prompt", cwd=tmp_path, env={}, timeout_seconds=10, runner=completed(stdout))

    assert run.session_id == "32c179a9-11c9-428d-bf02-d5a41cd3821b"
    assert run.final_message == "OK"
    assert run.actual_models == {"claude-haiku-4-5-20251001"}
    assert run.snapshot.used_percent == 24.0
    assert run.classification.kind == SUCCESS


def test_claude_limit_and_model_mismatch(tmp_path):
    events = [
        {"type": "system", "subtype": "init", "session_id": "s", "model": "claude-opus-5-5"},
        {
            "type": "rate_limit_event",
            "rate_limit_info": {"status": "rejected", "rateLimitType": "five_hour", "resetsAt": 2_000_000_000},
        },
        {"type": "result", "is_error": True, "subtype": "error", "result": "Usage limit reached"},
    ]
    stdout = "\n".join(json.dumps(event) for event in events)

    run = run_engine(CLAUDE, ["claude"], "p", cwd=tmp_path, env={}, timeout_seconds=10, runner=completed(stdout, 1))

    assert run.model_mismatch
    assert run.classification.kind == QUOTA_EXHAUSTED
    assert run.classification.reset_at == 2_000_000_000


def test_timeout_is_reported(tmp_path):
    def runner(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output=b"", stderr=b"")

    run = run_engine(CLAUDE, ["claude"], "p", cwd=tmp_path, env={}, timeout_seconds=1, runner=runner)

    assert run.timed_out
    assert run.classification.kind == "task_failure"


@pytest.mark.parametrize(
    "engine, stdout, expected",
    [
        ("codex", "Logged in using ChatGPT", True),
        ("codex", "Logged in using an API key", False),
        ("claude", json.dumps({"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty"}), True),
        ("claude", json.dumps({"loggedIn": True, "authMethod": "apiKey"}), False),
        ("claude", json.dumps({"loggedIn": False}), False),
    ],
)
def test_subscription_status(engine, stdout, expected):
    ok, _detail = subscription_status(engine, runner=completed(stdout), env={})

    assert ok is expected
