"""Tests for centralized polling filesystem observation."""

from pathlib import Path
from unittest.mock import Mock

from utils.filesystem_watch import FilesystemWatcher, directory_fingerprint, file_content_fingerprint


def test_file_target_reports_each_content_version_once(tmp_path):
    path = tmp_path / ".env"
    path.write_text("first", encoding="utf-8")
    watcher = FilesystemWatcher()
    watcher.watch_file("configuration", path)

    assert watcher.poll() == []
    path.write_text("second", encoding="utf-8")
    changes = watcher.poll()
    assert [change.target for change in changes] == ["configuration"]
    assert changes[0].current == file_content_fingerprint(path)
    assert watcher.poll() == []

    path.unlink()
    assert watcher.poll("configuration")[0].current == "missing"


def test_directory_target_detects_matching_add_update_and_delete(tmp_path):
    watcher = FilesystemWatcher()
    watcher.watch_directory("history", tmp_path, "*.json")
    ignored = tmp_path / "run.log"
    ignored.write_text("log", encoding="utf-8")
    assert watcher.poll() == []

    summary = tmp_path / "run.json"
    summary.write_text('{"status": "running"}', encoding="utf-8")
    assert watcher.poll("history")
    summary.write_text('{"status": "completed"}', encoding="utf-8")
    assert watcher.poll("history")
    summary.unlink()
    assert watcher.poll("history")


def test_refresh_advances_baseline_and_snapshot_errors_are_safe(tmp_path, monkeypatch):
    path = tmp_path / "file"
    watcher = FilesystemWatcher()
    watcher.watch_file("file", path)
    path.write_text("content", encoding="utf-8")
    watcher.refresh("file")
    assert watcher.poll("file") == []

    monkeypatch.setattr(Path, "glob", Mock(side_effect=OSError("unavailable")))
    assert directory_fingerprint(tmp_path, "*.json") == ()
