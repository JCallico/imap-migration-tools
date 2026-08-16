"""Tests for subprocess streaming and interruption."""

from __future__ import annotations

import asyncio
import sys

from tui.runner import OperationRunner, RunRequest


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
