"""Unit tests for public service contracts and compatibility operation edges."""

import imaplib

import pytest

from imap_services import AccountConfig, LocalTarget, MigrationService, OAuth2Config, _common
from imap_services import count as count_service
from imap_services import migrate as migrate_service
from imap_services._operations import backup, compare, count, migrate, restore
from imap_services.config import MigrationOptions, validate_parallelism
from imap_services.events import EventSink
from imap_services.exceptions import (
    AuthenticationError,
    CallbackError,
    ConfigurationError,
    ConnectionError,
    FilesystemError,
)
from imap_services.results import ComparisonResult, ComparisonRow
from providers import provider_exchange
from utils import imap_common


def password_account(username="user@example.com"):
    return AccountConfig("imap.example.com", username, password="secret")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: OAuth2Config(""),
        lambda: OAuth2Config("client", account_type="invalid"),
        lambda: AccountConfig("", "user", password="secret"),
        lambda: AccountConfig("host", "user"),
        lambda: AccountConfig("host", "user", password="secret", oauth2=OAuth2Config("client")),
        lambda: validate_parallelism(0, 1),
    ],
)
def test_invalid_service_configuration_is_rejected(factory):
    with pytest.raises(ConfigurationError):
        factory()


def test_connection_builder_translates_authentication_exit(monkeypatch):
    monkeypatch.setattr(_common.imap_session, "build_imap_conf", lambda *_args: (_ for _ in ()).throw(SystemExit()))

    with pytest.raises(AuthenticationError, match="source"):
        _common.build_connection_config(password_account(), "source")


def test_connect_translates_missing_connection(monkeypatch):
    monkeypatch.setattr(_common.imap_common, "get_imap_connection_from_conf", lambda _conf: None)

    with pytest.raises(ConnectionError, match="destination"):
        _common.connect(password_account(), "destination")


def test_event_sink_is_silent_without_callback_and_wraps_callback_errors():
    EventSink("count", None).message("ignored")
    sink = EventSink("count", lambda _event: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(CallbackError) as exc_info:
        sink.emit("folder", "INBOX")

    assert isinstance(exc_info.value.__cause__, RuntimeError)


def test_comparison_matches_requires_every_row_to_match():
    assert ComparisonResult((ComparisonRow("INBOX", 1, 1),), 1, 1).matches
    assert not ComparisonResult((ComparisonRow("INBOX", 1, None),), 1, 0).matches


def test_count_service_rejects_missing_local_directory(tmp_path):
    with pytest.raises(FilesystemError):
        count_service.CountService(LocalTarget(tmp_path / "missing")).run()


def test_migration_service_skips_exchange_special_folders(monkeypatch):
    class Connection:
        def configure_folder_mapping(self, *_args):
            pass

        def logout(self):
            pass

    source = Connection()
    destination = Connection()
    connections = iter(((source, {}), (destination, {})))
    monkeypatch.setattr(migrate_service, "connect", lambda *_args: next(connections))
    monkeypatch.setattr(imap_common, "detect_dest_namespace", lambda _connection: ("", "/"))
    monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _connection: ["Calendar"])
    monkeypatch.setattr(provider_exchange, "is_special_folder", lambda folder: folder == "Calendar")

    result = MigrationService(password_account("source"), password_account("destination"), MigrationOptions()).run()

    assert result.folders == ()


class CountConnection:
    def __init__(self, select_result=("OK", [b"0"]), search_result=("OK", [b"1 2"])):
        self.select_result = select_result
        self.search_result = search_result

    def select(self, *_args, **_kwargs):
        if isinstance(self.select_result, BaseException):
            raise self.select_result
        return self.select_result

    def search(self, *_args):
        if isinstance(self.search_result, BaseException):
            raise self.search_result
        return self.search_result

    def logout(self):
        pass


@pytest.mark.parametrize(
    ("connection", "expected"),
    [
        (None, "Connecting"),
        (CountConnection(("NO", [])), "Skipped"),
        (CountConnection(search_result=("NO", [])), "Error"),
        (CountConnection(select_result=imaplib.IMAP4.error("select")), "Error"),
    ],
)
def test_compatibility_imap_count_handles_unavailable_folders(monkeypatch, capsys, connection, expected):
    monkeypatch.setattr(imap_common, "get_imap_connection", lambda *_args: connection)
    monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _connection: ["INBOX"])

    count.count_emails("host", "user", "secret")

    assert expected in capsys.readouterr().out


def test_compatibility_imap_count_handles_empty_list_and_outer_errors(monkeypatch, capsys):
    connection = CountConnection()
    monkeypatch.setattr(imap_common, "get_imap_connection", lambda *_args: connection)
    monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _connection: [])
    count.count_emails("host", "user")
    assert "Failed to list" in capsys.readouterr().out

    monkeypatch.setattr(
        imap_common, "get_imap_connection", lambda *_args: (_ for _ in ()).throw(imaplib.IMAP4.error("auth"))
    )
    count.count_emails("host", "user")
    assert "IMAP Error" in capsys.readouterr().out

    monkeypatch.setattr(imap_common, "get_imap_connection", lambda *_args: (_ for _ in ()).throw(OSError("down")))
    count.count_emails("host", "user")
    assert "An error occurred" in capsys.readouterr().out


def test_compatibility_local_count_handles_empty_and_unknown_counts(monkeypatch, capsys):
    monkeypatch.setattr(imap_common, "list_local_folders", lambda _path: [])
    count.count_local_emails("backup")
    assert "No folders found" in capsys.readouterr().out

    monkeypatch.setattr(imap_common, "list_local_folders", lambda _path: ["Unreadable"])
    monkeypatch.setattr(imap_common, "get_local_email_count", lambda *_args: None)
    count.count_local_emails("backup")
    assert "N/A" in capsys.readouterr().out


def test_compatibility_compare_handles_exception():
    connection = CountConnection(select_result=RuntimeError("down"))
    assert compare.get_email_count(connection, "INBOX") is None


class BackupConnection:
    def __init__(self, response):
        self.response = response

    def uid(self, *_args):
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


@pytest.mark.parametrize(
    ("response", "auth_error", "success"),
    [
        (("NO", []), False, True),
        (("OK", [(b"meta", b"")]), False, True),
        (RuntimeError("broken"), False, True),
        (RuntimeError("expired"), True, False),
    ],
)
def test_backup_single_uid_handles_fetch_edges(monkeypatch, tmp_path, response, auth_error, success):
    monkeypatch.setattr(backup.imap_oauth2, "is_auth_error", lambda _exc: auth_error)

    actual, _ = backup.process_single_uid(BackupConnection(response), b"1", "INBOX", str(tmp_path))

    assert actual is success


def test_backup_single_uid_handles_subjectless_existing_and_write_failure(monkeypatch, tmp_path):
    raw = b"Message-ID: <one@example.com>\r\n\r\nbody"
    connection = BackupConnection(("OK", [(b"meta", raw)]))
    expected = tmp_path / "1_No Subject.eml"
    expected.write_bytes(raw)
    assert backup.process_single_uid(connection, b"1", "INBOX", str(tmp_path))[0]

    expected.unlink()
    monkeypatch.setattr(
        backup, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("readonly")), raising=False
    )
    assert backup.process_single_uid(connection, b"1", "INBOX", str(tmp_path))[0]


def test_backup_batch_handles_connection_select_and_session_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(backup.imap_session, "get_thread_connection", lambda *_args: None)
    assert backup.process_batch([b"1"], "INBOX", {}, str(tmp_path)) is None

    class SelectFailure:
        def select(self, *_args, **_kwargs):
            raise RuntimeError("select")

    monkeypatch.setattr(backup.imap_session, "get_thread_connection", lambda *_args: SelectFailure())
    assert backup.process_batch([b"1"], "INBOX", {}, str(tmp_path)) is None

    class SelectSuccess:
        def select(self, *_args, **_kwargs):
            pass

    monkeypatch.setattr(backup.imap_session, "get_thread_connection", lambda *_args: SelectSuccess())
    monkeypatch.setattr(backup.imap_session, "ensure_folder_session", lambda *_args, **_kwargs: (None, False))
    assert backup.process_batch([b"1"], "INBOX", {}, str(tmp_path)) is None


def test_restore_helpers_handle_invalid_date_listing_and_upload_errors(monkeypatch, tmp_path):
    eml = tmp_path / "bad-date.eml"
    eml.write_bytes(b"Message-ID: <one@example.com>\r\nDate: not-a-date\r\n\r\nbody")
    assert restore.parse_eml_file(eml)[1] is None

    monkeypatch.setattr(restore.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("unreadable")))
    assert restore.get_eml_files(tmp_path) == []

    monkeypatch.setattr(imap_common, "append_email", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("down")))
    assert restore.upload_email(object(), "INBOX", b"body", None) is restore.UploadResult.FAILURE
    assert restore.get_labels_from_manifest({"id": "invalid"}, "id") == []


def test_restore_prefilter_and_empty_gmail_restore(monkeypatch, tmp_path):
    monkeypatch.setattr(imap_common, "extract_message_id_from_eml", lambda path: "duplicate" if "one" in path else None)
    files = [("one.eml", "one.eml"), ("two.eml", "two.eml")]
    assert restore.pre_filter_eml_files(files, {"duplicate"}) == [("two.eml", "two.eml")]

    monkeypatch.setattr(restore, "get_eml_files", lambda _path: [])
    assert restore.restore_gmail_with_labels(str(tmp_path), {"host": "h", "user": "u"}, {}, False) is None


class MigrationSource:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def uid(self, *args):
        self.calls.append(args)
        if isinstance(self.response, BaseException):
            raise self.response
        if args[0] == "fetch":
            return self.response
        if args[0] == "copy":
            raise OSError("copy failed")
        return "OK", []


@pytest.mark.parametrize("response", [("NO", []), ("OK", [])])
def test_migration_single_uid_handles_failed_or_empty_fetch(response):
    result = migrate.process_single_uid(
        MigrationSource(response), object(), b"1", "INBOX", False, None, False, False, None, False
    )
    assert result[0] is True
    assert result[3] == 0


def test_migration_single_uid_handles_append_and_source_copy_failures(monkeypatch):
    raw = b"Message-ID: <one@example.com>\r\nSubject: Test\r\n\r\nbody"
    source = MigrationSource(("OK", [(b'1 (FLAGS (\\Seen) INTERNALDATE "01-Jan-2020 00:00:00 +0000")', raw)]))
    monkeypatch.setattr(imap_common, "append_email", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(migrate.restore_cache, "record_progress", lambda **_kwargs: None)

    result = migrate.process_single_uid(source, object(), b"1", "INBOX", True, "Trash", True, False, None, False)

    assert result[0] is True
    assert result[3] == 1


@pytest.mark.parametrize("auth_error", [False, True])
def test_migration_single_uid_classifies_execution_errors(monkeypatch, auth_error):
    monkeypatch.setattr(migrate.imap_oauth2, "is_auth_error", lambda _exc: auth_error)
    result = migrate.process_single_uid(
        MigrationSource(RuntimeError("failure")), object(), b"1", "INBOX", False, None, False, False, None, False
    )
    assert result[0] is not auth_error
