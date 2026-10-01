"""Desktop appearance settings tests."""

import json
import os

import pytest

from ui.appearance import load_appearance, save_appearance


def test_appearance_round_trip(tmp_path):
    path = tmp_path / "appearance.json"
    save_appearance(path, 88, 120, "dark")
    assert load_appearance(path) == {"opacity": 88, "zoom": 120, "theme": "dark"}
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "opacity, zoom, theme",
    [
        (True, 100, "system"),
        (69, 100, "system"),
        (101, 100, "system"),
        (88, True, "system"),
        (88, 79, "system"),
        (88, 151, "system"),
    ],
)
def test_appearance_rejects_invalid_settings(tmp_path, opacity, zoom, theme):
    path = tmp_path / "appearance.json"
    with pytest.raises(ValueError, match="must be between"):
        save_appearance(path, opacity, zoom, theme)


def test_appearance_rejects_unknown_theme(tmp_path):
    with pytest.raises(ValueError, match="theme must be one of"):
        save_appearance(tmp_path / "appearance.json", 88, 100, "sepia")


def test_appearance_ignores_invalid_or_incompatible_files(tmp_path):
    path = tmp_path / "appearance.json"
    path.write_text("not json")
    assert load_appearance(path) == {}
    path.write_text(json.dumps({"version": 2, "opacity": 88, "zoom": 100}))
    assert load_appearance(path) == {}
    path.write_text(json.dumps({"version": 1, "opacity": "88", "zoom": 100}))
    assert load_appearance(path) == {}
    path.write_text(json.dumps({"version": 1, "opacity": 88, "zoom": "large"}))
    assert load_appearance(path) == {}
    path.write_text(json.dumps({"version": 1, "opacity": 88, "zoom": 100, "theme": "sepia"}))
    assert load_appearance(path) == {}


def test_appearance_legacy_zoom_default_and_permission_failure(tmp_path, monkeypatch):
    path = tmp_path / "appearance.json"
    path.write_text(json.dumps({"version": 1, "opacity": 88}))
    assert load_appearance(path) == {"opacity": 88, "zoom": 100, "theme": "system"}
    monkeypatch.setattr(os, "chmod", lambda *args: (_ for _ in ()).throw(OSError("unsupported")))
    save_appearance(path, 90)
    assert load_appearance(path) == {"opacity": 90, "zoom": 100, "theme": "system"}


def test_appearance_cleans_temporary_file_after_replace_failure(tmp_path, monkeypatch):
    path = tmp_path / "appearance.json"
    monkeypatch.setattr(os, "replace", lambda *args: (_ for _ in ()).throw(OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        save_appearance(path, 90)
    assert list(tmp_path.iterdir()) == []
