"""Desktop event-loop adapter for shared asynchronous operations."""

from __future__ import annotations

import asyncio
import queue
import threading
from dataclasses import replace

from ui_core.runner import OperationRunner
from ui_core.session import RunSession


class RunController:
    """Keep subprocess IO off the native GUI thread; deliver ordered events."""

    def __init__(self):
        self.events = queue.Queue()
        self.runner = OperationRunner()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="imap-ui-io", daemon=True)
        self.thread.start()
        self.active = False
        self.cancelled = False

    def start(self, operation, values, request):
        if self.active:
            raise RuntimeError("An operation is already running")
        self.active = True
        self.cancelled = False
        asyncio.run_coroutine_threadsafe(self._run(operation, values, request), self.loop)

    async def _run(self, operation, values, request):
        session = None
        code = -1
        try:
            session = RunSession(operation, values)
            self.events.put(("started", session.record))
            if session.warning:
                self.events.put(("warning", session.warning))

            async def receive(line):
                self.events.put(("line", session.receive(line)))
                self.events.put(("progress", replace(session.progress)))

            code = await self.runner.run(request, receive)
        except Exception as exc:
            message = session.redactor(str(exc)) if session else "Unable to initialize operation"
            self.events.put(("warning", message))
        finally:
            record = session.finish(code, self.cancelled) if session else None
            if session and session.warning:
                self.events.put(("warning", session.warning))
            self.events.put(("finished", record))

    def cancel(self, force=False):
        self.cancelled = True
        asyncio.run_coroutine_threadsafe(self._cancel(force), self.loop)

    async def _cancel(self, force):
        try:
            if force:
                self.runner.terminate()
            elif not await self.runner.interrupt():
                self.events.put(("force_available", None))
        except (OSError, ValueError):
            self.events.put(("force_available", None))

    def close(self):
        if self.active:
            raise RuntimeError("Wait for the operation to finish before closing")
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)
        self.loop.close()
