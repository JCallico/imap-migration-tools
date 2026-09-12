"""Desktop controller lifecycle and failure handling."""

import asyncio
import queue
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

import gui.controller as controller_module
from gui.controller import RunController


def bare_controller(runner):
    controller = RunController.__new__(RunController)
    controller.events = queue.Queue()
    controller.runner = runner
    controller.active = False
    controller.cancelled = False
    return controller


def drain(controller):
    events = []
    while not controller.events.empty():
        events.append(controller.events.get_nowait())
    return events


def test_controller_run_streams_events_and_session_warning(monkeypatch):
    @dataclass
    class Progress:
        copied: int = 0

    class Session:
        def __init__(self, operation, values):
            self.record = SimpleNamespace(run_id="run")
            self.warning = "history warning"
            self.progress = Progress()
            self.redactor = lambda message: message

        def receive(self, line):
            self.progress.copied += 1
            return line.upper()

        def finish(self, code, cancelled):
            assert (code, cancelled) == (0, False)
            return SimpleNamespace(status="completed")

    class Runner:
        async def run(self, request, receive):
            await receive("line")
            return 0

    monkeypatch.setattr(controller_module, "RunSession", Session)
    controller = bare_controller(Runner())
    asyncio.run(controller._run("count", {}, object()))
    events = drain(controller)
    assert [kind for kind, _ in events] == ["started", "warning", "line", "progress", "warning", "finished"]
    assert events[2] == ("line", "LINE")


def test_controller_reports_initialization_and_runner_failures(monkeypatch):
    class BrokenSession:
        def __init__(self, *args):
            raise OSError("secret setup failure")

    monkeypatch.setattr(controller_module, "RunSession", BrokenSession)
    controller = bare_controller(None)
    asyncio.run(controller._run("count", {}, object()))
    assert drain(controller) == [("warning", "Unable to initialize operation"), ("finished", None)]

    class Session:
        warning = ""
        record = SimpleNamespace(run_id="run")
        redactor = staticmethod(lambda message: message.replace("secret", "[REDACTED]"))

        def __init__(self, *args):
            pass

        def finish(self, code, cancelled):
            return SimpleNamespace(status="failed")

    class BrokenRunner:
        async def run(self, request, receive):
            raise OSError("secret runner failure")

    monkeypatch.setattr(controller_module, "RunSession", Session)
    controller = bare_controller(BrokenRunner())
    asyncio.run(controller._run("count", {}, object()))
    assert drain(controller)[1] == ("warning", "[REDACTED] runner failure")


def test_controller_start_cancel_and_close_branches(monkeypatch):
    controller = bare_controller(SimpleNamespace())
    controller.active = True
    with pytest.raises(RuntimeError, match="already running"):
        controller.start("count", {}, object())

    submitted = []

    def submit(coroutine, loop):
        submitted.append(loop)
        coroutine.close()

    controller.active = False
    controller.loop = object()
    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", submit)
    controller.start("count", {}, object())
    assert controller.active and submitted == [controller.loop]
    controller.cancel(force=True)
    assert controller.cancelled and submitted == [controller.loop, controller.loop]

    class Runner:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

        async def interrupt(self):
            return False

    runner = Runner()
    controller = bare_controller(runner)
    asyncio.run(controller._cancel(True))
    assert runner.terminated
    asyncio.run(controller._cancel(False))
    assert drain(controller) == [("force_available", None)]

    async def broken_interrupt():
        raise OSError("gone")

    runner.interrupt = broken_interrupt
    asyncio.run(controller._cancel(False))
    assert drain(controller) == [("force_available", None)]

    controller.active = True
    with pytest.raises(RuntimeError, match="finish"):
        controller.close()
    controller.active = False
    calls = []
    controller.loop = SimpleNamespace(
        stop=lambda: None,
        call_soon_threadsafe=lambda callback: calls.append(callback),
        close=lambda: calls.append("closed"),
    )
    controller.thread = SimpleNamespace(join=lambda timeout: calls.append(timeout))
    controller.close()
    assert calls == [controller.loop.stop, 5, "closed"]
