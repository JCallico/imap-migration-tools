"""Tests for shared persistent panel and window layout settings."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from ui_core import layout
from ui_core.layout import load_layout, load_window_size, save_layout


def test_default_layout_path_uses_platform_config_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(layout, "user_config_path", lambda *args: tmp_path)

    assert layout.default_layout_path() == tmp_path / "tui-layout.json"


def test_layout_round_trip(tmp_path):
    path = tmp_path / "layout.json"
    save_layout(path, {"left": 42, "rows": 9})

    assert load_layout(path) == {"left": 42, "rows": 9}
    assert load_window_size(path) is None


def test_window_size_round_trip(tmp_path):
    path = tmp_path / "layout.json"
    save_layout(path, {"left": 42}, (1100, 740))

    assert load_layout(path) == {"left": 42}
    assert load_window_size(path) == (1100, 740)


def test_layout_ignores_invalid_or_incompatible_data(tmp_path):
    path = tmp_path / "layout.json"
    path.write_text("not JSON", encoding="utf-8")
    assert load_layout(path) == {}

    path.write_text(json.dumps({"version": 999, "splitters": {"left": 42}}), encoding="utf-8")
    assert load_layout(path) == {}
    assert load_window_size(path) is None

    path.write_text(
        json.dumps({"version": 1, "splitters": {"good": 42, "zero": 0, "boolean": True, "text": "10"}}),
        encoding="utf-8",
    )
    assert load_layout(path) == {"good": 42}

    path.write_text(json.dumps({"version": 1, "splitters": []}), encoding="utf-8")
    assert load_layout(path) == {}


@pytest.mark.parametrize(
    "size",
    [None, [], {"width": True, "height": 700}, {"width": 900, "height": "700"}, {"width": 0, "height": 700}],
)
def test_window_size_ignores_invalid_data(tmp_path, size):
    path = tmp_path / "layout.json"
    path.write_text(json.dumps({"version": 1, "splitters": {}, "window_size": size}), encoding="utf-8")

    assert load_window_size(path) is None


def test_save_layout_ignores_chmod_failure(tmp_path, monkeypatch):
    path = tmp_path / "layout.json"
    monkeypatch.setattr("ui_core.layout.os.chmod", Mock(side_effect=OSError("unsupported")))
    save_layout(path, {"left": 42})
    assert load_layout(path) == {"left": 42}


def test_save_layout_removes_temporary_file_when_replace_fails(tmp_path, monkeypatch):
    path = tmp_path / "layout.json"
    monkeypatch.setattr("ui_core.layout.os.replace", Mock(side_effect=OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        save_layout(path, {"left": 42})
    assert list(tmp_path.iterdir()) == []
