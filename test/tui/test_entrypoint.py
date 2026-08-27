"""Tests for the optional TUI console entry point."""

import builtins

import pytest

import tui
import tui.app
from tui.display import resolve_display_profile


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


def test_app_main_resolves_cli_display_mode(monkeypatch):
    launched = []

    class FakeApp:
        def __init__(self, *, display_profile):
            launched.append(display_profile)

        def run(self):
            launched.append("run")

    monkeypatch.setattr(tui.app, "ImapToolsApp", FakeApp)
    tui.app.main(["--display-mode", "ascii"])

    assert launched == [resolve_display_profile("ascii"), "run"]


def test_app_main_uses_environment_display_mode(monkeypatch):
    launched = []

    class FakeApp:
        def __init__(self, *, display_profile):
            launched.append(display_profile)

        def run(self):
            launched.append("run")

    monkeypatch.setenv("IMAP_TOOLS_DISPLAY_MODE", "standard")
    monkeypatch.setattr(tui.app, "ImapToolsApp", FakeApp)
    tui.app.main([])

    assert launched == [resolve_display_profile("standard"), "run"]
