"""Optional desktop dependency diagnostics."""

import builtins
import runpy
import sys
from types import SimpleNamespace

import pytest

from gui import main


def test_missing_wx_has_installation_guidance(monkeypatch):
    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "gui.app":
            raise ModuleNotFoundError("No module named wx", name="wx")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(SystemExit, match=r"imap-migration-tools\[gui\]"):
        main()


def test_unrelated_import_error_is_preserved(monkeypatch):
    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "gui.app":
            raise ModuleNotFoundError("No unrelated module", name="unrelated")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(ModuleNotFoundError, match="unrelated"):
        main()


def test_entrypoint_launches_application(monkeypatch):
    launched = []
    monkeypatch.setitem(sys.modules, "gui.app", SimpleNamespace(main=lambda: launched.append(True)))
    main()
    assert launched == [True]


def test_python_module_entrypoint(monkeypatch):
    launched = []
    monkeypatch.setattr("gui.main", lambda: launched.append(True))
    runpy.run_module("gui.__main__", run_name="__main__")
    assert launched == [True]
