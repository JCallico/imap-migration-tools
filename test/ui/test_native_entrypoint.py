"""Optional desktop dependency diagnostics."""

import builtins
import runpy
import sys
from types import SimpleNamespace

import pytest

from ui import main


def test_missing_wx_has_installation_guidance(monkeypatch):
    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "ui.app":
            raise ModuleNotFoundError("No module named wx", name="wx")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(SystemExit, match=r"imap-migration-tools\[ui\]"):
        main()


def test_unrelated_import_error_is_preserved(monkeypatch):
    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "ui.app":
            raise ModuleNotFoundError("No unrelated module", name="unrelated")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(ModuleNotFoundError, match="unrelated"):
        main()


def test_entrypoint_launches_application(monkeypatch):
    launched = []
    monkeypatch.setitem(sys.modules, "ui.app", SimpleNamespace(main=lambda: launched.append(True)))
    main()
    assert launched == [True]


def test_python_module_entrypoint(monkeypatch):
    launched = []
    monkeypatch.setattr("ui.main", lambda: launched.append(True))
    runpy.run_module("ui.__main__", run_name="__main__")
    assert launched == [True]
