"""Tests for sanitized run history."""

import os
from unittest.mock import Mock

from tui import history


def test_history_redacts_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    record = history.new_record("count")
    writer = history.HistoryWriter(record, history.Redactor(["very-secret"]))
    assert writer.write("password=very-secret") == "password=[REDACTED]"
    writer.write("Bearer abc.def.ghi")
    record.status = "completed"
    record.exit_code = 0
    writer.close()

    loaded = history.load_records()
    assert loaded[0].status == "completed"
    log = history.read_log(record.run_id)
    assert "very-secret" not in log
    assert "Bearer [REDACTED]" in log


def test_clear_history(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")
    (tmp_path / "run.log").write_text("log", encoding="utf-8")
    history.clear_history()
    assert list(tmp_path.iterdir()) == []


def test_history_ignores_corrupt_records_and_missing_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    (tmp_path / "invalid.json").write_text("not json", encoding="utf-8")
    (tmp_path / "wrong-shape.json").write_text('{"unexpected": true}', encoding="utf-8")
    assert history.load_records() == []
    assert history.read_log("missing") == ""


def test_delete_record_removes_summary_and_log(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    for suffix in (".json", ".log"):
        (tmp_path / f"run-1{suffix}").write_text("content", encoding="utf-8")
    history.delete_record("run-1")
    assert list(tmp_path.iterdir()) == []


def test_history_prunes_old_runs_by_count(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    monkeypatch.setattr(history, "MAX_RUNS", 1)
    older = tmp_path / "older.json"
    newer = tmp_path / "newer.json"
    older.write_text("{}", encoding="utf-8")
    (tmp_path / "older.log").write_text("old", encoding="utf-8")
    newer.write_text("{}", encoding="utf-8")
    older.touch()
    newer.touch()
    older_mtime = newer.stat().st_mtime - 10
    os.utime(older, (older_mtime, older_mtime))
    history.prune_history()
    assert newer.exists()
    assert not older.exists()
    assert not (tmp_path / "older.log").exists()


def test_history_writer_ignores_permission_hardening_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    chmod = Mock(side_effect=OSError("unsupported"))
    monkeypatch.setattr(history.os, "chmod", chmod)

    writer = history.HistoryWriter(history.new_record("count"), history.Redactor([]))
    writer.save()
    writer.close()

    assert chmod.call_count >= 2
    assert writer.summary_path.exists()


def test_history_directory_ignores_permission_hardening_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "user_data_path", lambda *_args: tmp_path)
    monkeypatch.setattr("pathlib.Path.chmod", Mock(side_effect=OSError("unsupported")))
    assert history.history_dir() == tmp_path / "history"
