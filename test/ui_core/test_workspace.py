"""Shared behavior and compatibility contracts for both frontends."""

import asyncio
import importlib
import os
from pathlib import Path

import pytest

from ui_core import history
from ui_core.config import save_form
from ui_core.operations import OPERATION_BY_NAME, build_command
from ui_core.runner import OperationRunner, RunRequest
from ui_core.session import RunSession
from ui_core.workspace import make_options, run_confirmation, validated_form


@pytest.mark.parametrize("module", ["config", "history", "operations", "runner", "layout"])
def test_legacy_import_is_same_module(module):
    assert importlib.import_module(f"tui.{module}") is importlib.import_module(f"ui_core.{module}")


def test_comparison_options_override_local_paths():
    options = make_options(
        "compare",
        {"SRC_LOCAL_PATH": "source", "DEST_LOCAL_PATH": "destination"},
        source_mode="imap",
        destination_mode="local",
    )
    assert options.environment == {"SRC_LOCAL_PATH": ""}
    assert options.destination_path == "destination"
    assert options.source_path == ""


def test_deletion_confirmation_identifies_targets():
    values = {
        "DELETE_FROM_SOURCE": "true",
        "DEST_DELETE": "true",
        "SRC_IMAP_HOST": "source",
        "SRC_IMAP_USERNAME": "alice",
        "DEST_IMAP_HOST": "destination",
        "DEST_IMAP_USERNAME": "bob",
    }
    message, required = run_confirmation("migrate", make_options("migrate", values), values)
    assert required
    assert "alice@source" in message and "bob@destination" in message
    assert "DELETE" in message


def test_external_file_validation(tmp_path):
    path = tmp_path / ".env"
    save_form(path, {"MAX_WORKERS": "6"})
    assert validated_form(path)["MAX_WORKERS"] == "6"
    path.write_text('MAX_WORKERS="zero"\n')
    with pytest.raises(ValueError, match="MAX_WORKERS"):
        validated_form(path)


def test_session_redacts_and_persists_cancelled_status(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    session = RunSession("backup", {"SRC_IMAP_PASSWORD": "private-password"})
    assert session.receive("SAVED private-password") == "SAVED [REDACTED]"
    record = session.finish(0, cancelled=True)
    assert record.status == "cancelled"
    assert record.copied == 1
    assert history.load_records()[0] == record
    assert "private-password" not in history.read_log(record.run_id)


def test_real_desktop_worker_runs_count(tmp_path):
    backup = tmp_path / "backup" / "INBOX"
    backup.mkdir(parents=True)
    (backup / "one.eml").write_text("Subject: Example\n\nBody")
    save_form(tmp_path / ".env", {"BACKUP_LOCAL_PATH": str(backup.parent)})
    options = make_options("count", {}, count_mode="local")
    source = str(Path(__file__).resolve().parents[2] / "src")
    request = RunRequest(
        build_command(OPERATION_BY_NAME["count"], options),
        tmp_path,
        {"PYTHONPATH": source, "BACKUP_LOCAL_PATH": str(backup.parent)},
        desktop_worker=True,
    )
    lines = []

    async def execute():
        async def receive(line):
            lines.append(line)

        return await OperationRunner().run(request, receive)

    assert asyncio.run(execute()) == 0
    assert any("INBOX" in line for line in lines)


def test_worker_rejects_arbitrary_modules():
    from ui_core.worker import main

    with pytest.raises(SystemExit, match="Unknown IMAP"):
        main(["os"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX process group integration")
def test_real_runner_cancellation(tmp_path):
    import sys

    request = RunRequest([sys.executable, "-u", "-c", "import time; print('ready'); time.sleep(60)"], tmp_path, {})

    async def execute():
        runner = OperationRunner()
        started = asyncio.Event()

        async def receive(line):
            if line == "ready":
                started.set()

        task = asyncio.create_task(runner.run(request, receive))
        await asyncio.wait_for(started.wait(), 10)
        assert await runner.interrupt()
        assert await task != 0

    asyncio.run(execute())


def test_worker_stdin_cancellation_without_console(tmp_path):
    """Exercise the channel used by a Windows GUI with no console attached."""
    import sys

    (tmp_path / "imap_count.py").write_text(
        "import time\ndef main():\n print('ready', flush=True)\n while True: time.sleep(0.02)\nif __name__ == '__main__': main()\n"
    )
    source = str(Path(__file__).resolve().parents[2] / "src")
    request = RunRequest(
        [sys.executable, "-u", "-m", "imap_count"],
        tmp_path,
        {"PYTHONPATH": os.pathsep.join((str(tmp_path), source))},
        desktop_worker=True,
    )

    async def execute():
        runner = OperationRunner()
        ready = asyncio.Event()

        async def receive(line):
            if line == "ready":
                ready.set()

        task = asyncio.create_task(runner.run(request, receive))
        try:
            await asyncio.wait_for(ready.wait(), 10)
            runner.process.stdin.write(b"cancel\n")
            await runner.process.stdin.drain()
            assert await asyncio.wait_for(task, 10) != 0
        finally:
            runner.terminate()

    asyncio.run(execute())


def test_explicit_local_comparison_requires_path_even_with_account():
    from ui_core.operations import readiness

    values = {
        f"{prefix}_IMAP_{name}": value
        for prefix in ("SRC", "DEST")
        for name, value in (("HOST", "server"), ("USERNAME", "user"), ("PASSWORD", "secret"))
    }
    assert not readiness("compare", values, compare_source_mode="local").ready
    assert not readiness("compare", values, compare_destination_mode="local").ready
