"""Cross-platform asynchronous subprocess execution."""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
import subprocess
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

LineCallback = Callable[[str], Awaitable[None]]


def _display_environment(environment: dict[str, str]) -> list[str]:
    """Format explicit environment assignments without exposing secrets."""
    sensitive_fragments = ("PASSWORD", "SECRET", "TOKEN")
    assignments = []
    for name, value in sorted(environment.items()):
        if not value and name not in {"BACKUP_LOCAL_PATH", "SRC_LOCAL_PATH", "DEST_LOCAL_PATH"}:
            continue
        display_value = "[REDACTED]" if any(fragment in name.upper() for fragment in sensitive_fragments) else value
        display_value = display_value.replace("\r", "\\r").replace("\n", "\\n")
        assignments.append(f"{name}={shlex.quote(display_value)}")
    return assignments


@dataclass(frozen=True)
class RunRequest:
    command: list[str]
    cwd: Path
    environment: dict[str, str]
    display_environment: dict[str, str] | None = None
    desktop_worker: bool = False


class OperationRunner:
    """Run one command and stream merged output without blocking the UI."""

    def __init__(self) -> None:
        self.process: asyncio.subprocess.Process | None = None
        self.desktop_worker = False

    @property
    def active(self) -> bool:
        return self.process is not None and self.process.returncode is None

    async def run(self, request: RunRequest, on_line: LineCallback) -> int:
        command = subprocess.list2cmdline(request.command) if os.name == "nt" else shlex.join(request.command)
        await on_line("Command:")
        for assignment in _display_environment(request.display_environment or {}):
            await on_line(assignment)
        await on_line(command)
        await on_line("")
        env = os.environ.copy()
        env.update(request.environment)
        env["PYTHONUNBUFFERED"] = "1"
        kwargs: dict[str, object] = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            if request.desktop_worker:
                kwargs["creationflags"] |= subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        self.desktop_worker = request.desktop_worker
        command_args = request.command
        if request.desktop_worker:
            command_args = (
                [
                    str(
                        Path(sys.executable).parent
                        / "worker"
                        / ("imap-tools-worker.exe" if os.name == "nt" else "imap-tools-worker")
                    ),
                    "--imap-worker",
                    *request.command[3:],
                ]
                if getattr(sys, "frozen", False)
                else [sys.executable, "-u", "-m", "ui_core.worker", *request.command[3:]]
            )
            kwargs["stdin"] = asyncio.subprocess.PIPE
        self.process = await asyncio.create_subprocess_exec(
            *command_args,
            cwd=request.cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **kwargs,
        )
        assert self.process.stdout is not None
        buffer = ""
        while chunk := await self.process.stdout.read(4096):
            buffer += chunk.decode(errors="replace").replace("\r", "\n")
            lines = buffer.split("\n")
            buffer = lines.pop()
            for line in lines:
                if line:
                    await on_line(line)
        if buffer:
            await on_line(buffer)
        return await self.process.wait()

    async def interrupt(self) -> bool:
        """Request graceful cancellation and report whether it exited promptly."""
        if not self.active or self.process is None:
            return True
        if os.name == "nt" and self.desktop_worker:
            if self.process.stdin:
                self.process.stdin.write(b"cancel\n")
                await self.process.stdin.drain()
        elif os.name == "nt":
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            try:
                os.killpg(self.process.pid, signal.SIGINT)
            except ProcessLookupError:
                return True
        try:
            await asyncio.wait_for(self.process.wait(), timeout=5)
            return True
        except asyncio.TimeoutError:
            return False

    def terminate(self) -> None:
        if self.active and self.process is not None:
            if os.name == "nt":
                self.process.terminate()
            else:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
