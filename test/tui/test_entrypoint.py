"""Tests for the optional TUI console entry point."""

import builtins

import pytest

import tui
import tui.app


def test_main_launches_textual_application(monkeypatch):
    launched = []
    monkeypatch.setattr(tui.app, "main", lambda: launched.append(True))
    tui.main()
    assert launched == [True]


def test_main_explains_missing_optional_dependency(monkeypatch):
    original_import = builtins.__import__

    def missing_textual(name, *args, **kwargs):
        if name == "tui.app":
            error = ModuleNotFoundError("No module named 'textual'")
            error.name = "textual"
            raise error
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_textual)
    with pytest.raises(SystemExit, match=r"imap-migration-tools\[tui\]"):
        tui.main()


def test_main_reraises_unrelated_import_failure(monkeypatch):
    original_import = builtins.__import__

    def missing_unrelated(name, *args, **kwargs):
        if name == "tui.app":
            error = ModuleNotFoundError("No module named 'unrelated'")
            error.name = "unrelated"
            raise error
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_unrelated)
    with pytest.raises(ModuleNotFoundError, match="unrelated"):
        tui.main()
