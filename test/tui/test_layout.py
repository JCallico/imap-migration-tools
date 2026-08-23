"""Tests for persistent TUI panel layout settings."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from tui.layout import load_layout, save_layout


def test_layout_round_trip(tmp_path):
    path = tmp_path / "layout.json"
    save_layout(path, {"left": 42, "rows": 9})

    assert load_layout(path) == {"left": 42, "rows": 9}


def test_layout_ignores_invalid_or_incompatible_data(tmp_path):
    path = tmp_path / "layout.json"
    path.write_text("not JSON", encoding="utf-8")
    assert load_layout(path) == {}

    path.write_text(json.dumps({"version": 999, "splitters": {"left": 42}}), encoding="utf-8")
    assert load_layout(path) == {}

    path.write_text(
        json.dumps({"version": 1, "splitters": {"good": 42, "zero": 0, "boolean": True, "text": "10"}}),
        encoding="utf-8",
    )
    assert load_layout(path) == {"good": 42}

    path.write_text(json.dumps({"version": 1, "splitters": []}), encoding="utf-8")
    assert load_layout(path) == {}


def test_save_layout_ignores_chmod_failure(tmp_path, monkeypatch):
    path = tmp_path / "layout.json"
    monkeypatch.setattr("tui.layout.os.chmod", Mock(side_effect=OSError("unsupported")))
    save_layout(path, {"left": 42})
    assert load_layout(path) == {"left": 42}


def test_save_layout_removes_temporary_file_when_replace_fails(tmp_path, monkeypatch):
    path = tmp_path / "layout.json"
    monkeypatch.setattr("tui.layout.os.replace", Mock(side_effect=OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        save_layout(path, {"left": 42})
    assert list(tmp_path.iterdir()) == []
