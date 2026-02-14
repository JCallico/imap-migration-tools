"""
Tests for restore_imap_emails.py

Tests cover:
- Email parsing from .eml files
- Basic email restoration
- Gmail labels application
- Duplicate detection
- Configuration validation
"""

import imaplib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_common
import imap_restore as restore_imap_emails
import restore_cache
from conftest import temp_argv, temp_env


def _mock_restore_env(port):
    return {
        "DEST_IMAP_HOST": f"imap://localhost:{port}",
        "DEST_IMAP_USERNAME": "user",
        "DEST_IMAP_PASSWORD": "pass",
        "MAX_WORKERS": "1",
        "BATCH_SIZE": "1",
    }


class TestLoadLabelsManifest:
    """Tests for loading labels manifest."""

    def test_load_existing_manifest(self, tmp_path):
        """Test loading existing manifest file (old format - list of labels)."""
        manifest_data = {
            "<msg1@test.com>": ["INBOX", "Work"],
            "<msg2@test.com>": ["Sent Mail", "Personal"],
        }
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))

        result = imap_common.load_manifest(str(tmp_path), "labels_manifest.json")
        assert result == manifest_data

    def test_load_manifest_new_format(self, tmp_path):
        """Test loading manifest with new format (dict with labels and flags)."""
        manifest_data = {
            "<msg1@test.com>": {"labels": ["INBOX", "Work"], "flags": ["\\Seen", "\\Flagged"]},
            "<msg2@test.com>": {"labels": ["Sent Mail"], "flags": []},
        }
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))

        result = imap_common.load_manifest(str(tmp_path), "labels_manifest.json")
        assert result == manifest_data
        assert "\\Seen" in result["<msg1@test.com>"]["flags"]
        assert result["<msg2@test.com>"]["flags"] == []

    def test_load_nonexistent_manifest(self, tmp_path):
        """Test loading when manifest doesn't exist."""
        result = imap_common.load_manifest(str(tmp_path), "labels_manifest.json")
        assert result == {}

    def test_load_invalid_json_manifest(self, tmp_path):
        """Test loading invalid JSON manifest."""
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text("not valid json {{{")

        result = imap_common.load_manifest(str(tmp_path), "labels_manifest.json")
        assert result == {}


class TestGetFlagsFromManifest:
    """Tests for extracting flags from manifest."""

    def test_get_flags_new_format(self):
        """Test getting flags from manifest."""
        manifest = {
            "<msg1@test.com>": {"labels": ["INBOX"], "flags": ["\\Seen", "\\Flagged"]},
        }
        result = restore_imap_emails.get_flags_from_manifest(manifest, "<msg1@test.com>")
        assert result == "\\Seen \\Flagged"

    def test_get_flags_single_flag(self):
        """Test getting a single flag from manifest."""
        manifest = {
            "<msg1@test.com>": {"labels": ["INBOX"], "flags": ["\\Seen"]},
        }
        result = restore_imap_emails.get_flags_from_manifest(manifest, "<msg1@test.com>")
        assert result == "\\Seen"

    def test_get_flags_empty(self):
        """Test getting flags when no flags set."""
        manifest = {
            "<msg1@test.com>": {"labels": ["INBOX"], "flags": []},
        }
        result = restore_imap_emails.get_flags_from_manifest(manifest, "<msg1@test.com>")
        assert result is None

    def test_get_flags_not_in_manifest(self):
        """Test getting flags for message not in manifest."""
        manifest = {}
        result = restore_imap_emails.get_flags_from_manifest(manifest, "<msg1@test.com>")
        assert result is None


class TestParseEmlFile:
    """Tests for parsing .eml files."""

    def test_parse_simple_eml(self, tmp_path):
        """Test parsing a simple .eml file."""
        eml_content = b"""From: sender@test.com
To: recipient@test.com
Subject: Test Email
Message-ID: <test123@test.com>
Date: Mon, 15 Jan 2024 10:30:00 +0000

This is the body of the email.
"""
        eml_file = tmp_path / "test.eml"
        eml_file.write_bytes(eml_content)

        message_id, date_str, raw_content, subject = restore_imap_emails.parse_eml_file(str(eml_file))

        assert message_id == "<test123@test.com>"
        assert "Test Email" in subject
        assert raw_content == eml_content

    def test_parse_eml_no_message_id(self, tmp_path):
        """Test parsing .eml without Message-ID."""
        eml_content = b"""From: sender@test.com
To: recipient@test.com
Subject: No ID Email
Date: Mon, 15 Jan 2024 10:30:00 +0000

Body content.
"""
        eml_file = tmp_path / "test.eml"
        eml_file.write_bytes(eml_content)

        message_id, date_str, raw_content, subject = restore_imap_emails.parse_eml_file(str(eml_file))

        assert message_id is None
        assert raw_content is not None

    def test_parse_nonexistent_file(self):
        """Test parsing non-existent file."""
        message_id, date_str, raw_content, subject = restore_imap_emails.parse_eml_file("/nonexistent/file.eml")

        assert message_id is None
        assert raw_content is None

    def test_parse_eml_file_unknown_charset_subject(self, tmp_path):
        """Test parsing with a subject that uses an unknown charset."""
        file_path = tmp_path / "unknown_charset.eml"
        file_path.write_text("Subject: =?X-UNKNOWN?B?SGVsbG8=?=\r\nMessage-ID: <unknown@test>\r\n\r\nBody")

        message_id, _date_str, _raw_content, subject = restore_imap_emails.parse_eml_file(str(file_path))
        assert message_id == "<unknown@test>"
        assert "Hello" in subject


class TestGetEmlFiles:
    """Tests for getting .eml files from a folder."""

    def test_get_eml_files(self, tmp_path):
        """Test getting .eml files from a folder."""
        (tmp_path / "email1.eml").write_text("content1")
        (tmp_path / "email2.eml").write_text("content2")
        (tmp_path / "other.txt").write_text("not an email")

        result = restore_imap_emails.get_eml_files(str(tmp_path))

        assert len(result) == 2
        filenames = [f[1] for f in result]
        assert "email1.eml" in filenames
        assert "email2.eml" in filenames

    def test_get_eml_files_empty_folder(self, tmp_path):
        """Test getting .eml files from empty folder."""
        result = restore_imap_emails.get_eml_files(str(tmp_path))
        assert result == []

    def test_get_eml_files_nonexistent_folder(self):
        """Test getting .eml files from non-existent folder."""
        result = restore_imap_emails.get_eml_files("/nonexistent/folder")
        assert result == []


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_credentials(self, capsys, tmp_path):
        """Test that missing credentials cause exit."""
        with temp_env({}), temp_argv(["restore_imap_emails.py", "--src-path", str(tmp_path)]):
            with pytest.raises(SystemExit) as exc_info:
                restore_imap_emails.main()

        assert exc_info.value.code == 2

    def test_missing_src_path(self, capsys):
        """Test that missing source path causes exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "user",
            "DEST_IMAP_PASSWORD": "pass",
        }
        with temp_env(env), temp_argv(["restore_imap_emails.py"]):
            with pytest.raises(SystemExit) as exc_info:
                restore_imap_emails.main()

        assert exc_info.value.code == 2

    def test_nonexistent_src_path(self, capsys):
        """Test that non-existent source path causes exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "user",
            "DEST_IMAP_PASSWORD": "pass",
        }
        with temp_env(env), temp_argv(["restore_imap_emails.py", "--src-path", "/nonexistent/path"]):
            with pytest.raises(SystemExit) as exc_info:
                restore_imap_emails.main()

        assert exc_info.value.code == 1


class TestRestoreIntegration:
    """Integration tests for restore functionality."""

    def test_restore_single_folder(self, single_mock_server, tmp_path):
        """Test restoring a single folder."""
        # Create backup structure
        inbox = tmp_path / "INBOX"
        inbox.mkdir()

        eml_content = b"""From: sender@test.com
To: recipient@test.com
Subject: Test Email
Message-ID: <test123@test.com>
Date: Mon, 15 Jan 2024 10:30:00 +0000

Body content.
"""
        (inbox / "1_Test_Email.eml").write_bytes(eml_content)

        # Start mock server (with empty data - we're uploading TO it)
        src_data = {"INBOX": []}
        server, port = single_mock_server(src_data)

        env = _mock_restore_env(port)
        with temp_env(env), temp_argv(["restore_imap_emails.py", "--src-path", str(tmp_path), "INBOX"]):
            restore_imap_emails.main()

    def test_restore_all_folders_scans_backup(self, single_mock_server, tmp_path):
        """End-to-end: restore all folders from a backup tree."""
        inbox = tmp_path / "INBOX"
        inbox.mkdir()
        (inbox / "1_Test_Email.eml").write_text("Subject: Inbox\nMessage-ID: <inbox@test>\n\nBody")

        archive = tmp_path / "Archive"
        archive.mkdir()
        subfolder = archive / "Sub"
        subfolder.mkdir()
        (subfolder / "2_Test_Email.eml").write_text("Subject: Archive\nMessage-ID: <archive@test>\n\nBody")

        empty_folder = tmp_path / "Empty"
        empty_folder.mkdir()

        dest_data = {"INBOX": []}
        server, port = single_mock_server(dest_data)

        env = _mock_restore_env(port)
        with temp_env(env), temp_argv(["restore_imap_emails.py", "--src-path", str(tmp_path)]):
            restore_imap_emails.main()

        assert "INBOX" in server.folders
        assert "Archive/Sub" in server.folders
        assert len(server.folders["INBOX"]) == 1
        assert len(server.folders["Archive/Sub"]) == 1
        assert "Empty" not in server.folders

    def test_restore_single_folder_full_restore_flag(self, single_mock_server, tmp_path):
        """Smoke test: --full-restore flag is accepted."""
        inbox = tmp_path / "INBOX"
        inbox.mkdir()

        eml_content = b"""From: sender@test.com
To: recipient@test.com
Subject: Test Email
Message-ID: <test123@test.com>
Date: Mon, 15 Jan 2024 10:30:00 +0000

Body content.
"""
        (inbox / "1_Test_Email.eml").write_bytes(eml_content)

        src_data = {"INBOX": []}
        _server, port = single_mock_server(src_data)

        env = _mock_restore_env(port)
        with (
            temp_env(env),
            temp_argv(["restore_imap_emails.py", "--src-path", str(tmp_path), "--full-restore", "INBOX"]),
        ):
            restore_imap_emails.main()

    def test_restore_with_labels_manifest(self, tmp_path):
        """Test that labels manifest is loaded correctly."""
        # Create manifest
        manifest_data = {
            "<msg1@test.com>": ["INBOX", "Work"],
            "<msg2@test.com>": ["Personal"],
        }
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))

        # Load and verify
        result = imap_common.load_manifest(str(tmp_path), "labels_manifest.json")
        assert len(result) == 2
        assert result["<msg1@test.com>"] == ["INBOX", "Work"]

    def test_restore_gmail_mode_fallback_folder(self, single_mock_server, tmp_path):
        """End-to-end: Gmail mode with no labels uses fallback folder."""
        gmail_all_mail = tmp_path / "[Gmail]" / "All Mail"
        gmail_all_mail.mkdir(parents=True)
        (gmail_all_mail / "1_Test.eml").write_text("Subject: X\nMessage-ID: <no-labels@test>\n\nBody")

        dest_data = {"INBOX": []}
        server, port = single_mock_server(dest_data)

        env = _mock_restore_env(port)
        with temp_env(env), temp_argv(["restore_imap_emails.py", "--src-path", str(tmp_path), "--gmail-mode"]):
            restore_imap_emails.main()

        assert imap_common.FOLDER_RESTORED_UNLABELED in server.folders
        assert len(server.folders[imap_common.FOLDER_RESTORED_UNLABELED]) == 1

    def test_restore_dest_delete_removes_orphans(self, single_mock_server, tmp_path):
        """End-to-end: --dest-delete removes messages not in local backup."""
        inbox = tmp_path / "INBOX"
        inbox.mkdir()
        (inbox / "1_keep.eml").write_text("Subject: Keep\nMessage-ID: <keep@test>\n\nBody")

        dest_data = {
            "INBOX": [
                b"Subject: Keep\r\nMessage-ID: <keep@test>\r\n\r\nBody",
                b"Subject: Orphan\r\nMessage-ID: <orphan@test>\r\n\r\nBody",
            ]
        }
        server, port = single_mock_server(dest_data)

        env = _mock_restore_env(port)
        with (
            temp_env(env),
            temp_argv(["restore_imap_emails.py", "--src-path", str(tmp_path), "--dest-delete", "INBOX"]),
        ):
            restore_imap_emails.main()

        assert len(server.folders["INBOX"]) == 1
        assert b"Message-ID: <keep@test>" in server.folders["INBOX"][0]["content"]


class TestRestoreProgressCache:
    def test_progress_cache_add_get_persist(self, tmp_path):
        import threading

        cache_path = restore_cache.get_dest_index_cache_path(str(tmp_path), "imap.example.com", "user@example.com")
        cache_data = restore_cache.load_dest_index_cache(cache_path)
        lock = threading.Lock()

        assert (
            restore_cache.get_cached_message_ids(cache_data, lock, "imap.example.com", "user@example.com", "INBOX")
            == set()
        )

        assert (
            restore_cache.add_cached_message_id(
                cache_data, lock, "imap.example.com", "user@example.com", "INBOX", "<a@test>"
            )
            is True
        )
        assert (
            restore_cache.add_cached_message_id(
                cache_data, lock, "imap.example.com", "user@example.com", "INBOX", "<a@test>"
            )
            is False
        )
        assert (
            restore_cache.add_cached_message_id(
                cache_data, lock, "imap.example.com", "user@example.com", "INBOX", "<b@test>"
            )
            is True
        )

        restore_cache.maybe_save_dest_index_cache(cache_path, cache_data, lock, force=True)

        cache_data2 = restore_cache.load_dest_index_cache(cache_path)
        ids = restore_cache.get_cached_message_ids(cache_data2, lock, "imap.example.com", "user@example.com", "INBOX")
        assert "<a@test>" in ids
        assert "<b@test>" in ids


class TestBackupFolderDiscovery:
    """Tests for backup folder discovery helpers."""

    def test_get_backup_folders_skips_unreadable(self, tmp_path):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1.eml").write_bytes(b"Subject: Inbox\r\n\r\nBody")

        parent_path = tmp_path / "Parent"
        parent_path.mkdir()

        unreadable_path = parent_path / "Unreadable"
        unreadable_path.mkdir()
        (unreadable_path / "1.eml").write_bytes(b"Subject: Hidden\r\n\r\nBody")
        os.chmod(unreadable_path, 0)

        try:
            folders = imap_common.get_backup_folders(str(tmp_path))
        finally:
            os.chmod(unreadable_path, 0o700)

        folder_names = {name for name, _path in folders}
        assert "INBOX" in folder_names
        assert "Unreadable" not in folder_names

    def test_extract_message_id_from_eml_missing_file(self, tmp_path):
        missing_path = tmp_path / "missing.eml"
        assert imap_common.extract_message_id_from_eml(str(missing_path)) is None

    def test_extract_message_id_from_eml_success(self, tmp_path):
        eml_path = tmp_path / "message.eml"
        eml_path.write_text("Message-ID: <ok@test>\r\nSubject: Hi\r\n\r\nBody")

        assert imap_common.extract_message_id_from_eml(str(eml_path)) == "<ok@test>"


class TestTrashFolderDetection:
    """Tests for trash folder detection with string LIST entries."""

    def test_detect_trash_folder_with_string_entries(self):
        class FakeConn:
            def list(self):
                return (
                    "OK",
                    [
                        '(\\HasNoChildren) "/" "INBOX"',
                        '(\\HasNoChildren \\Trash) "/" "Trash"',
                    ],
                )

        result = imap_common.detect_trash_folder(FakeConn())
        assert result == "Trash"


class TestGetLabelsFromManifest:
    """Tests for get_labels_from_manifest function."""

    def test_get_labels_dict_format(self):
        """Test getting labels from dict format manifest."""
        manifest = {
            "<msg1@test.com>": {"labels": ["INBOX", "Work"], "flags": ["\\Seen"]},
        }
        result = restore_imap_emails.get_labels_from_manifest(manifest, "<msg1@test.com>")
        assert result == ["INBOX", "Work"]

    def test_get_labels_list_format(self):
        """Test getting labels from old list format manifest."""
        manifest = {
            "<msg1@test.com>": ["INBOX", "Personal"],
        }
        result = restore_imap_emails.get_labels_from_manifest(manifest, "<msg1@test.com>")
        assert result == ["INBOX", "Personal"]

    def test_get_labels_not_in_manifest(self):
        """Test getting labels for message not in manifest."""
        manifest = {}
        result = restore_imap_emails.get_labels_from_manifest(manifest, "<msg1@test.com>")
        assert result == []

    def test_get_labels_none_message_id(self):
        """Test getting labels with None message ID."""
        manifest = {"<msg1@test.com>": ["INBOX"]}
        result = restore_imap_emails.get_labels_from_manifest(manifest, None)
        assert result == []


class TestRestoreE2EHelpers:
    """End-to-end tests for restore helper functions using the mock IMAP server."""

    def test_upload_email_success(self, single_mock_server):
        dest_data = {"INBOX": []}
        server, port = single_mock_server(dest_data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        result = restore_imap_emails.upload_email(
            conn,
            "INBOX",
            b"Subject: Upload\r\nMessage-ID: <up@test>\r\n\r\nBody",
            '"15-Jan-2024 10:30:00 +0000"',
        )

        assert result == restore_imap_emails.UploadResult.SUCCESS
        assert len(server.folders["INBOX"]) == 1
        conn.logout()

    def test_sync_flags_on_existing(self, single_mock_server):
        dest_data = {
            "INBOX": [{"uid": 1, "flags": set(), "content": b"Subject: Flag\r\nMessage-ID: <flag@test>\r\n\r\nBody"}]
        }
        _server, port = single_mock_server(dest_data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        imap_common.sync_flags_on_existing(conn, "INBOX", "<flag@test>", "\\Seen \\Flagged", 1000)

        conn.select('"INBOX"')
        resp, data = conn.search(None, 'HEADER Message-ID "<flag@test>"')
        assert resp == "OK"
        msg_num = data[0].split()[0]
        resp, flag_data = conn.fetch(msg_num, "(FLAGS)")
        assert resp == "OK"
        flag_text = str(flag_data[0])
        assert "\\Seen" in flag_text
        assert "\\Flagged" in flag_text
        conn.logout()


class TestDestDeleteRestoreArgument:
    """Tests for --dest-delete argument in restore script."""

    def test_dest_delete_default_false(self):
        """Test that --dest-delete defaults to False."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("folder", nargs="?")
        parser.add_argument("--dest-delete", action="store_true", default=False)
        args = parser.parse_args([])
        assert args.dest_delete is False

    def test_dest_delete_when_set(self):
        """Test that --dest-delete can be set to True."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("folder", nargs="?")
        parser.add_argument("--dest-delete", action="store_true", default=False)
        args = parser.parse_args(["--dest-delete"])
        assert args.dest_delete is True


class TestDestDeleteRestoreFunctionality:
    """Tests for --dest-delete actual deletion behavior in restore script."""

    def test_delete_orphan_emails_from_dest_removes_extra(self, single_mock_server):
        """Test that emails in dest but not in local backup are deleted."""
        # Destination has 3 emails
        dest_data = {
            "INBOX": [
                b"Subject: Keep\r\nMessage-ID: <keep@test>\r\n\r\nBody",
                b"Subject: Delete 1\r\nMessage-ID: <delete1@test>\r\n\r\nBody",
                b"Subject: Delete 2\r\nMessage-ID: <delete2@test>\r\n\r\nBody",
            ]
        }

        server, port = single_mock_server(dest_data)

        import imaplib

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        # Local backup only has one email
        local_msg_ids = {"<keep@test>"}

        deleted = imap_common.delete_orphan_emails(conn, "INBOX", local_msg_ids)

        assert deleted == 2
        # Verify only 1 email remains
        assert len(server.folders["INBOX"]) == 1
        assert b"Message-ID: <keep@test>" in server.folders["INBOX"][0]["content"]

        conn.logout()

    def test_delete_orphan_empty_local_deletes_all(self, single_mock_server):
        """Test that if local backup is empty, all dest emails are deleted."""
        dest_data = {
            "INBOX": [
                b"Subject: Delete 1\r\nMessage-ID: <d1@test>\r\n\r\nBody",
                b"Subject: Delete 2\r\nMessage-ID: <d2@test>\r\n\r\nBody",
            ]
        }

        server, port = single_mock_server(dest_data)

        import imaplib

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        # Empty local backup
        local_msg_ids = set()

        deleted = imap_common.delete_orphan_emails(conn, "INBOX", local_msg_ids)

        assert deleted == 2
        assert len(server.folders["INBOX"]) == 0

        conn.logout()

    def test_delete_orphan_no_orphans(self, single_mock_server):
        """Test that when all dest emails exist locally, none are deleted."""
        dest_data = {
            "INBOX": [
                b"Subject: Email 1\r\nMessage-ID: <e1@test>\r\n\r\nBody",
                b"Subject: Email 2\r\nMessage-ID: <e2@test>\r\n\r\nBody",
            ]
        }

        server, port = single_mock_server(dest_data)

        import imaplib

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        # Local has both emails
        local_msg_ids = {"<e1@test>", "<e2@test>"}

        deleted = imap_common.delete_orphan_emails(conn, "INBOX", local_msg_ids)

        assert deleted == 0
        assert len(server.folders["INBOX"]) == 2

        conn.logout()

    def test_get_local_message_ids(self, tmp_path):
        """Test get_local_message_ids extracts Message-IDs from .eml files."""
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        # Create test .eml files
        (inbox_path / "1_Email1.eml").write_bytes(b"Subject: Test 1\r\nMessage-ID: <local1@test>\r\n\r\nBody")
        (inbox_path / "2_Email2.eml").write_bytes(b"Subject: Test 2\r\nMessage-ID: <local2@test>\r\n\r\nBody")
        (inbox_path / "3_Email3.eml").write_bytes(b"Subject: Test 3\r\nMessage-ID: <local3@test>\r\n\r\nBody")

        msg_ids = restore_imap_emails.get_local_message_ids(str(inbox_path))

        assert "<local1@test>" in msg_ids
        assert "<local2@test>" in msg_ids
        assert "<local3@test>" in msg_ids
        assert len(msg_ids) == 3

    def test_get_local_message_ids_empty_folder(self, tmp_path):
        """Test get_local_message_ids with empty folder."""
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        msg_ids = restore_imap_emails.get_local_message_ids(str(inbox_path))

        assert len(msg_ids) == 0

    def test_get_local_message_ids_ignores_non_eml(self, tmp_path):
        """Test get_local_message_ids ignores non-.eml files."""
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        (inbox_path / "1_Email.eml").write_bytes(b"Subject: Test\r\nMessage-ID: <valid@test>\r\n\r\nBody")
        (inbox_path / "notes.txt").write_bytes(b"Some notes")
        (inbox_path / "data.json").write_bytes(b"{}")

        msg_ids = restore_imap_emails.get_local_message_ids(str(inbox_path))

        assert len(msg_ids) == 1
        assert "<valid@test>" in msg_ids

    def test_dest_delete_enabled_via_env_var_main_deletes_all_in_folder(self, single_mock_server, tmp_path):
        """End-to-end: DEST_DELETE=true triggers deletion when local folder has no .eml files."""
        dest_data = {
            "INBOX": [
                b"Subject: Delete 1\r\nMessage-ID: <d1@test>\r\n\r\nBody",
                b"Subject: Delete 2\r\nMessage-ID: <d2@test>\r\n\r\nBody",
            ]
        }

        server, port = single_mock_server(dest_data)

        backup_root = tmp_path / "backup"
        (backup_root / "INBOX").mkdir(parents=True)

        env = _mock_restore_env(port)
        env.update(
            {
                "BACKUP_LOCAL_PATH": str(backup_root),
                "DEST_DELETE": "true",
            }
        )
        with temp_env(env), temp_argv(["restore_imap_emails.py", "INBOX"]):
            restore_imap_emails.main()

        assert len(server.folders["INBOX"]) == 0


class TestAppendEmailReturnValueChecking:
    """Tests that verify append_email return values are checked before recording progress."""

    def test_record_progress_not_called_on_append_failure(self, tmp_path):
        """Test that record_progress is not called when append_email fails during label application."""
        from unittest.mock import Mock, patch

        # Create test email file
        backup_root = tmp_path / "backup"
        inbox = backup_root / "INBOX"
        inbox.mkdir(parents=True)

        eml_content = b"""From: sender@test.com
To: recipient@test.com
Subject: Test Email
Message-ID: <test123@test.com>
Date: Mon, 15 Jan 2024 10:30:00 +0000

Body content.
"""
        (inbox / "1_Test_Email.eml").write_bytes(eml_content)

        # Create labels manifest with multiple labels
        manifest = {"<test123@test.com>": {"labels": ["INBOX", "Work"], "flags": []}}
        manifest_path = backup_root / "labels_manifest.json"
        manifest_path.write_text(json.dumps(manifest))

        # Mock IMAP connection that fails on the second append (for label)
        mock_conn = Mock()
        mock_conn.select.return_value = ("OK", [b"0"])
        mock_conn.search.return_value = ("OK", [b""])  # No duplicates

        # First append succeeds (INBOX), second append fails (Work label)
        mock_conn.append.side_effect = [
            ("OK", []),  # INBOX upload succeeds
            ("NO", []),  # Work label append fails
        ]

        # Track calls to record_progress
        with (
            patch("restore_cache.record_progress") as mock_record_progress,
            patch("imap_common.get_imap_connection", return_value=mock_conn),
        ):
            env = {
                "DEST_IMAP_HOST": "localhost",
                "DEST_IMAP_USERNAME": "user",
                "DEST_IMAP_PASSWORD": "pass",
                "MAX_WORKERS": "1",
            }
            with temp_env(env), temp_argv(["restore_imap_emails.py", "--src-path", str(backup_root), "INBOX"]):
                restore_imap_emails.main()

            # Verify record_progress was called only once (for successful INBOX upload)
            # and NOT called for the failed Work label append
            assert mock_record_progress.call_count == 1
            # Verify it was called for INBOX only
            call_args = mock_record_progress.call_args
            assert call_args[1]["folder_name"] == "INBOX"
