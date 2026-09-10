"""Desktop appearance settings tests."""

import json
import os

import pytest

from ui_core.appearance import load_appearance, save_appearance


def test_appearance_round_trip(tmp_path):
    path = tmp_path / "appearance.json"
    save_appearance(path, 88, 120)
    assert load_appearance(path) == {"opacity": 88, "zoom": 120}
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("opacity, zoom", [(True, 100), (69, 100), (101, 100), (88, True), (88, 79), (88, 151)])
def test_appearance_rejects_invalid_settings(tmp_path, opacity, zoom):
    path = tmp_path / "appearance.json"
    with pytest.raises(ValueError, match="must be between"):
        save_appearance(path, opacity, zoom)


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


def test_appearance_legacy_zoom_default_and_permission_failure(tmp_path, monkeypatch):
    path = tmp_path / "appearance.json"
    path.write_text(json.dumps({"version": 1, "opacity": 88}))
    assert load_appearance(path) == {"opacity": 88, "zoom": 100}
    monkeypatch.setattr(os, "chmod", lambda *args: (_ for _ in ()).throw(OSError("unsupported")))
    save_appearance(path, 90)
    assert load_appearance(path) == {"opacity": 90, "zoom": 100}


def test_appearance_cleans_temporary_file_after_replace_failure(tmp_path, monkeypatch):
    path = tmp_path / "appearance.json"
    monkeypatch.setattr(os, "replace", lambda *args: (_ for _ in ()).throw(OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        save_appearance(path, 90)
    assert list(tmp_path.iterdir()) == []
