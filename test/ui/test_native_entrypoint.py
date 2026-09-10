"""Optional desktop dependency diagnostics."""

import builtins

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
