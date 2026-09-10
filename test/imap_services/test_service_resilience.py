"""Focused tests for service error handling and resource cleanup contracts."""

import imaplib
from contextlib import nullcontext

import pytest

from imap_services import (
    AccountConfig,
    BackupOptions,
    BackupService,
    ComparisonService,
    CountService,
    ImapTarget,
    LocalTarget,
    MigrationOptions,
    MigrationService,
    RestoreService,
)
from imap_services import backup as backup_module
from imap_services import compare as compare_module
from imap_services import count as count_module
from imap_services import migrate as migrate_module
from imap_services import restore as restore_module
from utils import imap_common


class StubConnection:
    """Minimal connection whose logout behavior can be controlled."""

    def __init__(self, logout_error=None):
        self.logout_error = logout_error
        self.logout_calls = 0

    def logout(self):
        self.logout_calls += 1
        if self.logout_error:
            raise self.logout_error


def account(username="user@example.com"):
    return AccountConfig("imap.example.com", username, password="secret")


def test_backup_ignores_logout_failure(monkeypatch, tmp_path):
    connection = StubConnection(RuntimeError("connection already closed"))
    monkeypatch.setattr(backup_module, "connect", lambda *_args: (connection, {}))
    monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _connection: [])

    result = BackupService(account(), tmp_path, BackupOptions()).run()

    assert result.folders == ()
    assert connection.logout_calls == 1


def test_restore_ignores_logout_failure(monkeypatch, tmp_path):
    connection = StubConnection(RuntimeError("connection already closed"))
    (tmp_path / "INBOX").mkdir()
    monkeypatch.setattr(restore_module, "connect", lambda *_args: (connection, {}))
    monkeypatch.setattr(imap_common, "get_backup_folders", lambda _path: [("INBOX", str(tmp_path / "INBOX"))])
    monkeypatch.setattr(imap_common, "load_progress_cache", lambda *_args, **_kwargs: (None, {}, None))
    monkeypatch.setattr(restore_module, "progress_reporter", lambda *_args: nullcontext())
    monkeypatch.setattr("imap_services._operations.restore.restore_folder", lambda *_args, **_kwargs: None)

    result = RestoreService(tmp_path, account()).run()

    assert [folder.name for folder in result.folders] == ["INBOX"]
    assert connection.logout_calls == 1


def test_migration_reports_cache_failure_and_ignores_logout_failures(monkeypatch, tmp_path):
    source = StubConnection(RuntimeError("source already closed"))
    destination = StubConnection(RuntimeError("destination already closed"))
    destination.configure_folder_mapping = lambda *_args: None
    connections = iter(((source, {}), (destination, {})))
    events = []
    monkeypatch.setattr(migrate_module, "connect", lambda *_args: next(connections))
    monkeypatch.setattr(imap_common, "detect_dest_namespace", lambda _connection: ("", "/"))
    monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _connection: [])
    monkeypatch.setattr(
        imap_common, "load_progress_cache", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable"))
    )

    result = MigrationService(
        account("source@example.com"),
        account("destination@example.com"),
        MigrationOptions(cache_path=tmp_path),
        events.append,
    ).run()

    assert result.folders == ()
    assert source.logout_calls == 1
    assert destination.logout_calls == 1
    assert any(event.phase == "cache" and event.severity == "warning" for event in events)


def test_local_count_preserves_unknown_folder_counts(monkeypatch, tmp_path):
    events = []
    monkeypatch.setattr(imap_common, "list_local_folders", lambda _path: ["INBOX", "Unreadable"])
    monkeypatch.setattr(imap_common, "get_local_email_count", lambda _path, folder: 2 if folder == "INBOX" else None)

    result = CountService(LocalTarget(tmp_path), events.append).run()

    assert result.folder_counts == {"INBOX": 2, "Unreadable": None}
    assert result.total == 2
    assert [event.current for event in events if event.phase == "folder"] == [2, None]


class CountConnection(StubConnection):
    def __init__(self):
        super().__init__(RuntimeError("connection already closed"))

    def select(self, folder, readonly=False):
        if "SelectFailure" in folder:
            return "NO", []
        if "ProtocolError" in folder:
            raise imaplib.IMAP4.error("cannot select")
        return "OK", [b"0"]

    def search(self, _charset, _criteria):
        return "NO", []


def test_imap_count_returns_unknown_for_protocol_failures(monkeypatch):
    connection = CountConnection()
    monkeypatch.setattr(count_module, "connect", lambda *_args, **_kwargs: (connection, {}))
    monkeypatch.setattr(
        imap_common, "list_selectable_folders", lambda _connection: ["SelectFailure", "SearchFailure", "ProtocolError"]
    )

    result = CountService(ImapTarget(account())).run()

    assert result.folder_counts == {"SelectFailure": None, "SearchFailure": None, "ProtocolError": None}
    assert result.total == 0
    assert connection.logout_calls == 1


@pytest.mark.parametrize(
    ("select_result", "expected"),
    [
        (("NO", []), None),
        (("OK", []), 0),
        (("OK", [b""]), 0),
        (("OK", [b"7"]), 7),
    ],
)
def test_comparison_imap_count_handles_server_responses(select_result, expected):
    class Connection:
        def select(self, _folder, readonly=False):
            return select_result

    assert compare_module._imap_count(Connection(), "INBOX") == expected


def test_comparison_imap_count_handles_unexpected_error():
    class Connection:
        def select(self, _folder, readonly=False):
            raise RuntimeError("disconnected")

    assert compare_module._imap_count(Connection(), "INBOX") is None


def test_comparison_ignores_cleanup_base_exception(monkeypatch):
    source = StubConnection(KeyboardInterrupt())
    destination = StubConnection(SystemExit())
    destination.configure_folder_mapping = lambda *_args: None
    connections = iter(((source, {}), (destination, {})))
    monkeypatch.setattr(compare_module, "connect", lambda *_args: next(connections))
    monkeypatch.setattr(imap_common, "detect_dest_namespace", lambda _connection: ("", "/"))
    monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _connection: [])

    with pytest.raises(Exception, match="failed to list source folders"):
        ComparisonService(ImapTarget(account("source")), ImapTarget(account("destination"))).run()

    assert source.logout_calls == 1
    assert destination.logout_calls == 1
