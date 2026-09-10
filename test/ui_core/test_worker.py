"""Desktop bundle worker dispatch and cancellation."""

import sys

import pytest

import ui_core.worker as worker


class ImmediateThread:
    def __init__(self, target, **kwargs):
        self.target = target

    def start(self):
        self.target()


def test_worker_dispatches_supported_module_and_reads_cancel(monkeypatch):
    chunks = iter((b"ignored\ncancel\n", b""))
    interrupted = []
    dispatched = []
    monkeypatch.setattr(worker.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(worker.os, "read", lambda *args: next(chunks))
    monkeypatch.setattr(worker._thread, "interrupt_main", lambda: interrupted.append(True))
    monkeypatch.setattr(worker.runpy, "run_module", lambda *args, **kwargs: dispatched.append((args, kwargs)))
    worker.main(["imap_count", "--help"])
    assert interrupted == [True]
    assert sys.argv == ["imap_count", "--help"]
    assert dispatched == [(("imap_count",), {"run_name": "__main__", "alter_sys": True})]


def test_worker_uses_process_arguments_and_ignores_closed_stdin(monkeypatch):
    dispatched = []
    monkeypatch.setattr(worker.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(worker.os, "read", lambda *args: (_ for _ in ()).throw(OSError("closed")))
    monkeypatch.setattr(worker.runpy, "run_module", lambda name, **kwargs: dispatched.append(name))
    monkeypatch.setattr(sys, "argv", ["worker", "imap_backup"])
    worker.main()
    assert dispatched == ["imap_backup"]


@pytest.mark.parametrize("arguments", [[], ["unknown"]])
def test_worker_rejects_missing_or_unknown_operation(arguments):
    with pytest.raises(SystemExit, match="Unknown IMAP worker operation"):
        worker.main(arguments)
