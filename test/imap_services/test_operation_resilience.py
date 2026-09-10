"""Coverage for defensive branches in the extracted operation engines."""

import pytest

from imap_services._operations import backup, migrate, restore
from utils import imap_common


class ManifestConnection:
    def __init__(self, list_result=("OK", []), list_error=None, noop_error=None):
        self.list_result = list_result
        self.list_error = list_error
        self.noop_error = noop_error

    def list(self):
        if self.list_error:
            raise self.list_error
        return self.list_result

    def noop(self):
        if self.noop_error:
            raise self.noop_error


@pytest.mark.parametrize("connection", [ManifestConnection(("NO", [])), ManifestConnection(list_error=OSError("down"))])
def test_flags_manifest_handles_folder_listing_failures(connection, tmp_path):
    assert backup.build_flags_manifest(connection, str(tmp_path)) == {}


def test_flags_manifest_handles_noop_and_save_failures(monkeypatch, tmp_path):
    connection = ManifestConnection(noop_error=OSError("closed"))
    monkeypatch.setattr(
        backup,
        "get_message_info_in_folder_with_conf",
        lambda conn, *_args: ({"id": {"flags": [imap_common.FLAG_SEEN]}}, conn),
    )
    monkeypatch.setattr(
        backup, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("readonly")), raising=False
    )
    assert backup.build_flags_manifest(connection, str(tmp_path), ["INBOX"]) == {
        "id": {"flags": [imap_common.FLAG_SEEN]}
    }


def test_delete_orphan_files_handles_invalid_names_and_io_failures(monkeypatch, tmp_path):
    (tmp_path / "invalid_name.eml").write_text("message")
    (tmp_path / "1_orphan.eml").write_text("message")
    monkeypatch.setattr(backup.os, "remove", lambda _path: (_ for _ in ()).throw(OSError("readonly")))
    assert backup.delete_orphan_local_files(str(tmp_path), set()) == 0
    monkeypatch.setattr(backup.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("unreadable")))
    assert backup.delete_orphan_local_files(str(tmp_path), set()) == 0


class BackupFolderConnection:
    def __init__(self, search=("OK", [b""])):
        self.search = search

    def select(self, *_args, **_kwargs):
        pass

    def uid(self, *_args):
        return self.search


def test_backup_folder_handles_directory_select_and_search_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(backup.os, "makedirs", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("readonly")))
    assert backup.backup_folder(BackupFolderConnection(), "INBOX", str(tmp_path), {}) is None
    monkeypatch.undo()

    connection = BackupFolderConnection()
    monkeypatch.setattr(connection, "select", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing")))
    assert backup.backup_folder(connection, "INBOX", str(tmp_path), {}) is None
    assert backup.backup_folder(BackupFolderConnection(("NO", [])), "INBOX", str(tmp_path), {}) is None


def test_backup_folder_detects_up_to_date_and_orphaned_files(tmp_path):
    folder = tmp_path / "INBOX"
    folder.mkdir()
    (folder / "1_existing.eml").write_text("message")
    (folder / "2_orphan.eml").write_text("message")
    assert backup.backup_folder(BackupFolderConnection(("OK", [b"1"])), "INBOX", str(tmp_path), {}, True) is None
    assert (folder / "1_existing.eml").exists()
    assert not (folder / "2_orphan.eml").exists()


def test_restore_batch_handles_missing_connections_and_unparseable_message(monkeypatch):
    monkeypatch.setattr(restore.imap_session, "get_thread_connection", lambda *_args: None)
    assert restore.process_restore_batch([], "INBOX", {}, {}, False, False) is None
    connections = iter((object(), None))
    monkeypatch.setattr(restore.imap_session, "get_thread_connection", lambda *_args: next(connections))
    assert restore.process_restore_batch([("bad.eml", "bad.eml")], "INBOX", {}, {}, False, False) is None
    monkeypatch.setattr(restore.imap_session, "get_thread_connection", lambda *_args: object())
    monkeypatch.setattr(restore, "parse_eml_file", lambda _path: (None, None, None, None))
    assert restore.process_restore_batch([("bad.eml", "bad.eml")], "INBOX", {}, {}, False, False) is None


def test_restore_batch_covers_existing_failed_and_label_skip_paths(monkeypatch):
    monkeypatch.setattr(restore.imap_session, "get_thread_connection", lambda *_args: object())
    monkeypatch.setattr(restore, "parse_eml_file", lambda _path: ("id", None, b"body", "subject"))
    monkeypatch.setattr(imap_common, "load_folder_msg_ids", lambda *_args: {"id"})
    monkeypatch.setattr(imap_common, "sync_flags_on_existing", lambda *_args: None)
    monkeypatch.setattr(restore.restore_cache, "record_progress", lambda **_kwargs: None)
    manifest = {"id": {"flags": ["\\Seen"], "labels": ["INBOX", "Spam"]}}
    restore.process_restore_batch([("one.eml", "one.eml")], "__GMAIL_MODE__", {}, manifest, True, True, True, {}, None)
    monkeypatch.setattr(imap_common, "load_folder_msg_ids", lambda *_args: set())
    monkeypatch.setattr(restore, "upload_email", lambda *_args: restore.UploadResult.FAILURE)
    restore.process_restore_batch([("one.eml", "one.eml")], "INBOX", {}, {}, False, False)


class BatchConnection:
    def __init__(self, select_error=None, expunge_error=None):
        self.select_error = select_error
        self.expunge_error = expunge_error

    def select(self, *_args, **_kwargs):
        if self.select_error:
            raise self.select_error

    def expunge(self):
        if self.expunge_error:
            raise self.expunge_error


def test_migration_batch_handles_connection_and_selection_failures(monkeypatch):
    monkeypatch.setattr(migrate.imap_session, "get_thread_connection", lambda *_args: None)
    assert migrate.process_batch([], "INBOX", {}, {}, False) == (False, 0)
    connection = BatchConnection(select_error=OSError("missing"))
    monkeypatch.setattr(migrate.imap_session, "get_thread_connection", lambda *_args: connection)
    assert migrate.process_batch([], "INBOX", {}, {}, False) == (False, 0)


def test_migration_batch_handles_lost_sessions_and_expunge_error(monkeypatch):
    source = BatchConnection(expunge_error=OSError("closed"))
    destination = BatchConnection()
    connections = iter((source, destination))
    monkeypatch.setattr(migrate.imap_session, "get_thread_connection", lambda *_args: next(connections))
    monkeypatch.setattr(migrate.imap_session, "ensure_folder_session", lambda *_args, **_kwargs: (source, False))
    assert migrate.process_batch([b"invalid"], "INBOX", {}, {}, False) == (False, 0)

    connections = iter((source, destination))
    monkeypatch.setattr(migrate.imap_session, "get_thread_connection", lambda *_args: next(connections))
    monkeypatch.setattr(migrate.imap_session, "ensure_folder_session", lambda *_args, **_kwargs: (source, True))
    monkeypatch.setattr(migrate.imap_session, "ensure_connection", lambda *_args: destination)
    monkeypatch.setattr(migrate, "process_single_uid", lambda *_args, **_kwargs: (True, source, destination, 1))
    assert migrate.process_batch([b"invalid"], "INBOX", {}, {}, True) == (True, 0)


class MigrateFolderConnection:
    def __init__(self, *, select_error=None, search=("OK", [b""])):
        self.select_error = select_error
        self.search = search

    def create(self, *_args):
        raise OSError("already exists")

    def select(self, *_args, **_kwargs):
        if self.select_error:
            raise self.select_error

    def response(self, *_args):
        raise OSError("unsupported")

    def uid(self, *_args):
        return self.search


def test_migrate_folder_handles_select_search_and_empty_paths(monkeypatch):
    source = MigrateFolderConnection(select_error=OSError("missing"))
    assert migrate.migrate_folder(source, MigrateFolderConnection(), "Archive", False, {}, {}) is None
    source = MigrateFolderConnection(search=("NO", []))
    assert migrate.migrate_folder(source, MigrateFolderConnection(), "Archive", False, {}, {}) is None

    deleted = []
    monkeypatch.setattr(imap_common, "delete_orphan_emails", lambda *_args: deleted.append(True))
    source = MigrateFolderConnection()
    assert migrate.migrate_folder(source, MigrateFolderConnection(), "INBOX", False, {}, {}, dest_delete=True) is None
    assert deleted
    source = MigrateFolderConnection()
    assert (
        migrate.migrate_folder(source, MigrateFolderConnection(), "INBOX", False, {}, {}, True, gmail_mode=True) is None
    )
