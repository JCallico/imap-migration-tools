"""Tests for sanitized run history."""

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
