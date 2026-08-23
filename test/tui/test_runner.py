"""Tests for subprocess streaming and interruption."""

from __future__ import annotations

import asyncio
import sys
from unittest.mock import AsyncMock, Mock

from tui.runner import OperationRunner, RunRequest, _display_environment


def test_runner_streams_stdout_and_stderr(tmp_path):
    async def exercise():
        lines = []
        runner = OperationRunner()
        request = RunRequest(
            [sys.executable, "-u", "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
            tmp_path,
            {"IMAP_HOST": "imap.example.com", "IMAP_PASSWORD": "secret", "BACKUP_LOCAL_PATH": ""},
            {"IMAP_HOST": "imap.example.com", "IMAP_PASSWORD": "secret", "BACKUP_LOCAL_PATH": ""},
        )

        async def receive(line):
            lines.append(line)

        assert await runner.run(request, receive) == 0
        assert lines[0] == "Command:"
        assert lines[1:4] == ["BACKUP_LOCAL_PATH=''", "IMAP_HOST=imap.example.com", "IMAP_PASSWORD='[REDACTED]'"]
        assert "-c" in lines[4]
        assert lines[5:] == ["", "out", "err"]

    asyncio.run(exercise())


def test_runner_interrupts_process_group(tmp_path):
    async def exercise():
        runner = OperationRunner()
        request = RunRequest([sys.executable, "-u", "-c", "import time; print('ready'); time.sleep(30)"], tmp_path, {})
        ready = asyncio.Event()

        async def receive(line):
            if line == "ready":
                ready.set()

        task = asyncio.create_task(runner.run(request, receive))
        await asyncio.wait_for(ready.wait(), 5)
        assert await runner.interrupt()
        assert await task != 0

    asyncio.run(exercise())


def test_interrupt_without_active_process_is_already_complete():
    assert asyncio.run(OperationRunner().interrupt())


def test_interrupt_timeout_enables_force_stop(monkeypatch):
    async def exercise():
        runner = OperationRunner()
        process = Mock(pid=123, returncode=None)
        process.wait = AsyncMock()
        runner.process = process
        monkeypatch.setattr("tui.runner.os.killpg", Mock())

        async def timeout(_awaitable, timeout):
            assert timeout == 5
            _awaitable.close()
            raise asyncio.TimeoutError

        monkeypatch.setattr("tui.runner.asyncio.wait_for", timeout)
        assert not await runner.interrupt()

    asyncio.run(exercise())


def test_interrupt_and_terminate_ignore_disappeared_process(monkeypatch):
    async def exercise():
        runner = OperationRunner()
        runner.process = Mock(pid=123, returncode=None)
        killpg = Mock(side_effect=ProcessLookupError)
        monkeypatch.setattr("tui.runner.os.killpg", killpg)
        assert await runner.interrupt()
        runner.terminate()
        assert killpg.call_count == 2

    asyncio.run(exercise())


def test_runner_streams_final_line_without_newline(tmp_path):
    async def exercise():
        lines = []
        runner = OperationRunner()
        request = RunRequest([sys.executable, "-u", "-c", "print('tail', end='')"], tmp_path, {})

        async def receive(line):
            lines.append(line)

        assert await runner.run(request, receive) == 0
        assert lines[-1] == "tail"

    asyncio.run(exercise())


def test_display_environment_skips_empty_non_path_values():
    assert _display_environment({"IMAP_HOST": "", "BACKUP_LOCAL_PATH": ""}) == ["BACKUP_LOCAL_PATH=''"]


def test_windows_interrupt_and_terminate_use_process_methods(monkeypatch):
    async def exercise():
        runner = OperationRunner()
        process = Mock(pid=123, returncode=None)
        process.wait = AsyncMock(return_value=0)
        runner.process = process
        monkeypatch.setattr("tui.runner.os.name", "nt")
        monkeypatch.setattr("tui.runner.signal.CTRL_BREAK_EVENT", 99, raising=False)

        assert await runner.interrupt()
        process.send_signal.assert_called_once_with(99)
        runner.terminate()
        process.terminate.assert_called_once()

    asyncio.run(exercise())
