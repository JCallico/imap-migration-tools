"""Verification runner: executes the repository's required checks outside any sandbox and summarizes the outcome."""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .config import VerifyConfig
from .engines import stage_environment

OUTPUT_TAIL_CHARS = 6000
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_PYTEST_SUMMARY = re.compile(r"(\d+) passed(?:, (\d+) skipped)?")

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass
class StepResult:
    command: str
    returncode: int | None
    output_tail: str
    seconds: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass
class VerifyResult:
    steps: list[StepResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(step.ok for step in self.steps)

    def test_summary(self) -> str:
        """The pytest "N passed" line, when a step produced one."""
        for step in self.steps:
            match = _PYTEST_SUMMARY.search(step.output_tail)
            if match:
                skipped = f", {match.group(2)} skipped" if match.group(2) else ""
                return f"{match.group(1)} passed{skipped}"
        return ""

    def summary(self) -> str:
        lines = []
        for step in self.steps:
            status = "passed" if step.ok else ("timed out" if step.timed_out else f"failed (exit {step.returncode})")
            lines.append(f"- `{step.command}`: {status} in {step.seconds:.0f}s")
        return "\n".join(lines)

    def failure_report(self, limit: int = OUTPUT_TAIL_CHARS) -> str:
        """Failing steps with the tail of their output, for the model to act on."""
        parts = []
        for step in self.steps:
            if step.ok:
                continue
            status = "timed out" if step.timed_out else f"exited with {step.returncode}"
            parts.append(f"$ {step.command}\n({status})\n{step.output_tail[-limit:]}")
        return "\n\n".join(parts)


def _tail(text: str) -> str:
    return _ANSI.sub("", text).strip()[-OUTPUT_TAIL_CHARS:]


def run_verification(
    worktree: Path,
    config: VerifyConfig,
    base_environ: Mapping[str, str],
    *,
    python: str | None = None,
    runner: Runner = subprocess.run,
    clock: Callable[[], float] = time.monotonic,
) -> VerifyResult:
    """Run every configured command in order in ``worktree`` and collect the results."""
    python = python or sys.executable
    env = stage_environment(base_environ)
    env["PYTHONPATH"] = config.pythonpath
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = VerifyResult()
    for template in config.commands:
        command = template.format(python=shlex.quote(python))
        started = clock()
        try:
            completed = runner(
                shlex.split(command),
                capture_output=True,
                text=True,
                cwd=str(worktree),
                env=env,
                timeout=config.timeout_minutes * 60,
                check=False,
            )
            step = StepResult(
                command, completed.returncode, _tail(f"{completed.stdout}\n{completed.stderr}"), clock() - started
            )
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            step = StepResult(command, None, _tail(partial), clock() - started, timed_out=True)
        except FileNotFoundError as exc:
            step = StepResult(command, 127, str(exc), clock() - started)
        result.steps.append(step)
    return result
