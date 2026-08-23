"""Tests for persistent TUI panel layout settings."""

from __future__ import annotations

import json

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
