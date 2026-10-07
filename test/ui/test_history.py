"""Tests for sanitized run history, which is isolated per project scope."""

import os
from unittest.mock import Mock

import pytest

from ui import history

SCOPE = "project-acme"


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "history_dir", lambda: tmp_path)
    return tmp_path


def run(scope, operation="count", status="completed", secret="very-secret"):
    record = history.new_record(operation)
    writer = history.HistoryWriter(record, history.Redactor([secret]), scope)
    writer.write(f"{scope} password={secret}")
    record.status = status
    record.exit_code = 0
    writer.close()
    return record


def test_history_redacts_and_round_trips(root):
    record = history.new_record("count")
    writer = history.HistoryWriter(record, history.Redactor(["very-secret"]), SCOPE)
    assert writer.write("password=very-secret") == "password=[REDACTED]"
    writer.write("Bearer abc.def.ghi")
    record.status = "completed"
    record.exit_code = 0
    writer.close()

    loaded = history.load_records(SCOPE)
    assert loaded[0].status == "completed"
    log = history.read_log(record.run_id, SCOPE)
    assert "very-secret" not in log
    assert "Bearer [REDACTED]" in log


def test_each_scope_sees_only_its_own_runs(root):
    acme = run("project-acme")
    other = run("project-other")

    assert [record.run_id for record in history.load_records("project-acme")] == [acme.run_id]
    assert [record.run_id for record in history.load_records("project-other")] == [other.run_id]
    assert history.load_records(history.DEFAULT_SCOPE) == []
    assert "project-acme" in history.read_log(acme.run_id, "project-acme")
    assert history.read_log(acme.run_id, "project-other") == ""
    assert (root / "projects" / "project-acme" / f"{acme.run_id}.json").is_file()
    assert [path.name for path in root.iterdir()] == ["projects"]


def test_deleting_clearing_and_pruning_never_cross_scopes(root, monkeypatch):
    acme = run("project-acme")
    other = run("project-other")

    history.delete_record(acme.run_id, "project-other")
    assert history.load_records("project-acme")

    history.clear_history("project-other")
    assert history.load_records("project-other") == []
    assert history.load_records("project-acme")[0].run_id == acme.run_id

    kept = run("project-other")
    monkeypatch.setattr(history, "MAX_RUNS", 1)
    run("project-acme")
    assert len(history.load_records("project-acme")) == 1
    assert [record.run_id for record in history.load_records("project-other")] == [kept.run_id]
    assert other.run_id not in {record.run_id for record in history.load_records("project-other")}


@pytest.mark.parametrize("scope", ["", ".", "..", "../outside", "a/b", "a\\b", "bad\x00name"])
def test_unsafe_scopes_are_rejected(root, scope):
    with pytest.raises(ValueError, match="Invalid history scope"):
        history.scope_dir(scope)
    with pytest.raises(ValueError, match="Invalid history scope"):
        history.delete_scope(scope)


def test_history_before_projects_is_adopted_by_the_default_project_only(root):
    for suffix in (".json", ".log"):
        (root / f"legacy-run{suffix}").write_text("{}" if suffix == ".json" else "log", encoding="utf-8")

    assert history.load_records("project-acme") == []
    assert (root / "legacy-run.json").exists()

    history.scope_dir(history.DEFAULT_SCOPE)

    assert not (root / "legacy-run.json").exists()
    assert (root / "projects" / "default" / "legacy-run.log").read_text(encoding="utf-8") == "log"
    assert history.load_records("project-acme") == []


def test_move_scope_carries_history_to_the_new_name_and_refuses_to_merge(root):
    record = run("project-acme")

    history.move_scope("project-acme", "project-acme-corp")
    assert history.load_records("project-acme-corp")[0].run_id == record.run_id
    assert history.load_records("project-acme") == []
    history.move_scope("project-missing", "project-anything")
    history.move_scope("project-acme-corp", "project-acme-corp")

    run("project-leftover")
    with pytest.raises(FileExistsError, match="already exists"):
        history.move_scope("project-acme-corp", "project-leftover")
    assert history.load_records("project-acme-corp")


def test_delete_scope_removes_only_that_projects_history(root):
    run("project-acme")
    kept = run("project-other")

    history.delete_scope("project-acme")
    history.delete_scope("project-acme")

    assert not (root / "projects" / "project-acme").exists()
    assert [record.run_id for record in history.load_records("project-other")] == [kept.run_id]


def test_clear_history(root):
    directory = history.scope_dir(SCOPE)
    (directory / "run.json").write_text("{}", encoding="utf-8")
    (directory / "run.log").write_text("log", encoding="utf-8")
    history.clear_history(SCOPE)
    assert list(directory.iterdir()) == []


def test_history_ignores_corrupt_records_and_missing_logs(root):
    directory = history.scope_dir(SCOPE)
    (directory / "invalid.json").write_text("not json", encoding="utf-8")
    (directory / "wrong-shape.json").write_text('{"unexpected": true}', encoding="utf-8")
    assert history.load_records(SCOPE) == []
    assert history.read_log("missing", SCOPE) == ""


def test_delete_record_removes_summary_and_log(root):
    directory = history.scope_dir(SCOPE)
    for suffix in (".json", ".log"):
        (directory / f"run-1{suffix}").write_text("content", encoding="utf-8")
    history.delete_record("run-1", SCOPE)
    assert list(directory.iterdir()) == []


def test_history_prunes_old_runs_by_count(root, monkeypatch):
    directory = history.scope_dir(SCOPE)
    monkeypatch.setattr(history, "MAX_RUNS", 1)
    older = directory / "older.json"
    newer = directory / "newer.json"
    older.write_text("{}", encoding="utf-8")
    (directory / "older.log").write_text("old", encoding="utf-8")
    newer.write_text("{}", encoding="utf-8")
    older.touch()
    newer.touch()
    older_mtime = newer.stat().st_mtime - 10
    os.utime(older, (older_mtime, older_mtime))
    history.prune_history(SCOPE)
    assert newer.exists()
    assert not older.exists()
    assert not (directory / "older.log").exists()


def test_history_writer_ignores_permission_hardening_failures(root, monkeypatch):
    chmod = Mock(side_effect=OSError("unsupported"))
    monkeypatch.setattr(history.os, "chmod", chmod)

    writer = history.HistoryWriter(history.new_record("count"), history.Redactor([]), SCOPE)
    writer.save()
    writer.close()

    assert chmod.call_count >= 2
    assert writer.summary_path.exists()


def test_history_directory_ignores_permission_hardening_failure(tmp_path, monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(history, "user_data_path", lambda *_args: tmp_path)
    monkeypatch.setattr("pathlib.Path.chmod", Mock(side_effect=OSError("unsupported")))
    assert history.history_dir() == tmp_path / "history"
    assert history.scope_dir(SCOPE) == tmp_path / "history" / "projects" / SCOPE


def test_history_summary_save_is_atomic_and_cleans_failed_temporary_file(root, monkeypatch):
    writer = history.HistoryWriter(history.new_record("count"), history.Redactor([]), SCOPE)
    original = writer.summary_path.read_text(encoding="utf-8")
    monkeypatch.setattr(history.os, "replace", Mock(side_effect=OSError("replace failed")))

    writer.record.status = "completed"
    try:
        writer.save()
    except OSError as exc:
        assert str(exc) == "replace failed"
    else:
        raise AssertionError("save should propagate replacement failure")

    assert writer.summary_path.read_text(encoding="utf-8") == original
    assert list(history.scope_dir(SCOPE).glob(f".{writer.summary_path.name}.*")) == []
