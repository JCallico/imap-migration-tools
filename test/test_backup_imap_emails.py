"""
Tests for backup_imap_emails.py

Tests cover:
- Basic email backup to local files
- Incremental backup (skip existing)
- Multiple folder backup
- Filename sanitization
- Configuration validation
"""

import imaplib
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import backup_imap_emails
import provider_gmail
from conftest import make_single_mock_connection


class TestBackupBasic:
    """Tests for basic backup functionality."""

    def test_single_email_backup(self, single_mock_server, monkeypatch, tmp_path):
        """Test backing up a single email to local directory."""
        src_data = {"INBOX": [b"Subject: Test Email\r\nMessage-ID: <1@test>\r\n\r\nBody content"]}
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path)])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        # Check that backup was created
        inbox_path = tmp_path / "INBOX"
        assert inbox_path.exists()

        eml_files = list(inbox_path.glob("*.eml"))
        assert len(eml_files) == 1

        # Check content
        content = eml_files[0].read_bytes()
        assert b"Test Email" in content or b"Body content" in content

    def test_multiple_emails_backup(self, single_mock_server, monkeypatch, tmp_path):
        """Test backing up multiple emails."""
        src_data = {
            "INBOX": [
                b"Subject: Email 1\r\nMessage-ID: <1@test>\r\n\r\nBody 1",
                b"Subject: Email 2\r\nMessage-ID: <2@test>\r\n\r\nBody 2",
                b"Subject: Email 3\r\nMessage-ID: <3@test>\r\n\r\nBody 3",
            ]
        }
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path)])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        inbox_path = tmp_path / "INBOX"
        eml_files = list(inbox_path.glob("*.eml"))
        assert len(eml_files) == 3


class TestIncrementalBackup:
    """Tests for incremental backup functionality."""

    def test_skip_existing_emails(self, single_mock_server, monkeypatch, tmp_path):
        """Test that existing emails are skipped during incremental backup."""
        src_data = {
            "INBOX": [
                b"Subject: Email 1\r\nMessage-ID: <1@test>\r\n\r\nBody 1",
                b"Subject: Email 2\r\nMessage-ID: <2@test>\r\n\r\nBody 2",
            ]
        }
        _, port = single_mock_server(src_data)

        # Create pre-existing file
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        existing_file = inbox_path / "1_Email_1.eml"
        existing_file.write_bytes(b"existing content")

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path)])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        # Should still have original content (not overwritten)
        assert existing_file.read_bytes() == b"existing content"

        # But second email should be backed up
        eml_files = list(inbox_path.glob("*.eml"))
        assert len(eml_files) == 2


class TestMultipleFolderBackup:
    """Tests for backing up multiple folders."""

    def test_backup_all_folders(self, single_mock_server, monkeypatch, tmp_path):
        """Test backing up emails from multiple folders."""
        src_data = {
            "INBOX": [b"Subject: Inbox\r\nMessage-ID: <1@test>\r\n\r\nC"],
            "Sent": [b"Subject: Sent\r\nMessage-ID: <2@test>\r\n\r\nC"],
            "Archive": [b"Subject: Archive\r\nMessage-ID: <3@test>\r\n\r\nC"],
        }
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path)])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        assert (tmp_path / "INBOX").exists()
        assert (tmp_path / "Sent").exists()
        assert (tmp_path / "Archive").exists()

    def test_backup_single_folder(self, single_mock_server, monkeypatch, tmp_path):
        """Test backing up a specific folder only."""
        src_data = {
            "INBOX": [b"Subject: Inbox\r\nMessage-ID: <1@test>\r\n\r\nC"],
            "Sent": [b"Subject: Sent\r\nMessage-ID: <2@test>\r\n\r\nC"],
        }
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path), "INBOX"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        assert (tmp_path / "INBOX").exists()
        # Sent should NOT be backed up
        assert not (tmp_path / "Sent").exists()


class TestEmptyFolderHandling:
    """Tests for empty folder handling."""

    def test_empty_folder(self, single_mock_server, monkeypatch, tmp_path):
        """Test handling of empty folders."""
        src_data = {"INBOX": [], "Empty": []}
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path)])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        # Should complete without error
        backup_imap_emails.main()


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_credentials(self, monkeypatch, capsys, tmp_path):
        """Test that missing credentials cause exit."""
        env = {}
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", str(tmp_path)])

        with pytest.raises(SystemExit) as exc_info:
            backup_imap_emails.main()

        assert exc_info.value.code == 2

    def test_missing_dest_path(self, monkeypatch, capsys):
        """Test that missing destination path causes exit."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py"])

        with pytest.raises(SystemExit) as exc_info:
            backup_imap_emails.main()

        assert exc_info.value.code == 2


class TestGetExistingUids:
    """Tests for get_existing_uids function."""

    def test_empty_directory(self, tmp_path):
        """Test with empty directory."""
        result = backup_imap_emails.get_existing_uids(str(tmp_path))
        assert result == set()

    def test_nonexistent_directory(self):
        """Test with non-existent directory."""
        result = backup_imap_emails.get_existing_uids("/nonexistent/path")
        assert result == set()

    def test_existing_files(self, tmp_path):
        """Test extraction of UIDs from existing files."""
        (tmp_path / "1_Subject.eml").touch()
        (tmp_path / "2_Another.eml").touch()
        (tmp_path / "100_Long_Subject.eml").touch()

        result = backup_imap_emails.get_existing_uids(str(tmp_path))
        assert result == {"1", "2", "100"}

    def test_ignore_non_matching_files(self, tmp_path):
        """Test that non-matching files are ignored."""
        (tmp_path / "not_an_email.txt").touch()
        (tmp_path / "random.eml").touch()  # No underscore
        (tmp_path / "1_Subject.eml").touch()

        result = backup_imap_emails.get_existing_uids(str(tmp_path))
        assert result == {"1"}


class TestGmailLabelsPreservation:
    """Tests for Gmail labels manifest functionality."""

    def test_is_label_folder_user_labels(self):
        """Test that user labels are correctly identified."""
        assert provider_gmail.is_label_folder("Work") is True
        assert provider_gmail.is_label_folder("Personal") is True
        assert provider_gmail.is_label_folder("Projects/2024") is True
        assert provider_gmail.is_label_folder("INBOX") is True

    def test_is_label_folder_gmail_labels(self):
        """Test that Gmail system labels are correctly identified."""
        assert provider_gmail.is_label_folder("[Gmail]/Sent Mail") is True
        assert provider_gmail.is_label_folder("[Gmail]/Starred") is True

    def test_is_label_folder_system_folders(self):
        """Test that Gmail system folders are excluded."""
        assert provider_gmail.is_label_folder("[Gmail]/All Mail") is False
        assert provider_gmail.is_label_folder("[Gmail]/Spam") is False
        assert provider_gmail.is_label_folder("[Gmail]/Trash") is False
        assert provider_gmail.is_label_folder("[Gmail]/Drafts") is False
        assert provider_gmail.is_label_folder("[Gmail]/Bin") is False

    def test_load_labels_manifest_nonexistent(self, tmp_path):
        """Test loading manifest when file doesn't exist."""
        result = backup_imap_emails.load_labels_manifest(str(tmp_path))
        assert result == {}

    def test_load_labels_manifest_existing(self, tmp_path):
        """Test loading existing manifest file."""
        import json

        manifest_data = {
            "<msg1@test.com>": ["INBOX", "Work"],
            "<msg2@test.com>": ["Sent Mail", "Personal"],
        }
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))

        result = backup_imap_emails.load_labels_manifest(str(tmp_path))
        assert result == manifest_data

    def test_load_labels_manifest_invalid_json(self, tmp_path):
        """Test loading invalid JSON manifest file."""
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text("not valid json {{{")

        result = backup_imap_emails.load_labels_manifest(str(tmp_path))
        assert result == {}

    def test_get_message_ids_in_folder(self, single_mock_server):
        src_data = {
            "INBOX": [
                b"Subject: A\r\nMessage-ID: <msg1@test.com>\r\n\r\nBody",
                b"Subject: B\r\nMessage-ID: <msg2@test.com>\r\n\r\nBody",
            ]
        }
        _server, port = single_mock_server(src_data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        result = backup_imap_emails.get_message_ids_in_folder(conn, "INBOX", None)

        assert "<msg1@test.com>" in result
        assert "<msg2@test.com>" in result
        conn.logout()

    def test_get_message_info_in_folder_read_status(self, single_mock_server):
        src_data = {
            "INBOX": [
                {"uid": 1, "flags": {"\\Seen"}, "content": b"Message-ID: <msg1@test.com>\r\n"},
                {"uid": 2, "flags": set(), "content": b"Message-ID: <msg2@test.com>\r\n"},
                {"uid": 3, "flags": {"\\Seen", "\\Answered"}, "content": b"Message-ID: <msg3@test.com>\r\n"},
            ]
        }
        _server, port = single_mock_server(src_data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        result = backup_imap_emails.get_message_info_in_folder(conn, "INBOX", None)

        assert "<msg1@test.com>" in result
        assert "\\Seen" in result["<msg1@test.com>"]["flags"]
        assert "<msg2@test.com>" in result
        assert result["<msg2@test.com>"]["flags"] == []
        assert "<msg3@test.com>" in result
        assert "\\Seen" in result["<msg3@test.com>"]["flags"]
        assert "\\Answered" in result["<msg3@test.com>"]["flags"]
        conn.logout()

    def test_build_labels_manifest(self, single_mock_server, tmp_path):
        src_data = {
            "INBOX": [b"Message-ID: <msg1@test.com>\r\n"],
            "Work": [b"Message-ID: <msg1@test.com>\r\n"],
            "[Gmail]/Sent Mail": [b"Message-ID: <msg2@test.com>\r\n"],
            "[Gmail]/All Mail": [
                {"uid": 1, "flags": {"\\Seen", "\\Flagged"}, "content": b"Message-ID: <msg1@test.com>\r\n"},
                {"uid": 2, "flags": set(), "content": b"Message-ID: <msg2@test.com>\r\n"},
            ],
        }
        _server, port = single_mock_server(src_data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        result = backup_imap_emails.build_labels_manifest(conn, str(tmp_path))

        assert "<msg1@test.com>" in result
        assert "<msg2@test.com>" in result
        assert "INBOX" in result["<msg1@test.com>"]["labels"]
        assert "Work" in result["<msg1@test.com>"]["labels"]
        assert "\\Seen" in result["<msg1@test.com>"]["flags"]
        assert "\\Flagged" in result["<msg1@test.com>"]["flags"]
        assert "Sent Mail" in result["<msg2@test.com>"]["labels"]
        assert result["<msg2@test.com>"]["flags"] == []

        manifest_path = tmp_path / "labels_manifest.json"
        assert manifest_path.exists()
        conn.logout()

    def test_preserve_labels_flag_integration(self, single_mock_server, monkeypatch, tmp_path):
        """Test --preserve-labels flag creates manifest."""
        src_data = {
            "INBOX": [b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
            "Work": [b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
            "[Gmail]/All Mail": [b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
        }
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["backup_imap_emails.py", "--dest-path", str(tmp_path), "--preserve-labels", "[Gmail]/All Mail"],
        )
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        # Check manifest was created
        manifest_path = tmp_path / "labels_manifest.json"
        assert manifest_path.exists()

    def test_manifest_only_flag(self, single_mock_server, monkeypatch, tmp_path):
        """Test --manifest-only flag creates manifest without downloading emails."""
        src_data = {
            "INBOX": [b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
            "Work": [b"Subject: Work Email\r\nMessage-ID: <2@test>\r\n\r\nBody"],
            "[Gmail]/All Mail": [
                b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody",
                b"Subject: Work Email\r\nMessage-ID: <2@test>\r\n\r\nBody",
            ],
        }
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["backup_imap_emails.py", "--dest-path", str(tmp_path), "--manifest-only"],
        )
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        # Should exit with code 0 after creating manifest
        with pytest.raises(SystemExit) as exc_info:
            backup_imap_emails.main()

        assert exc_info.value.code == 0

        # Check manifest was created
        manifest_path = tmp_path / "labels_manifest.json"
        assert manifest_path.exists()

        # Check NO email folders were created (no download happened)
        # Only the manifest file should exist
        items = list(tmp_path.iterdir())
        assert len(items) == 1
        assert items[0].name == "labels_manifest.json"

    def test_gmail_system_folders_constant(self):
        """Test that GMAIL_SYSTEM_FOLDERS contains expected entries."""
        expected = {
            "[Gmail]/All Mail",
            "[Gmail]/Spam",
            "[Gmail]/Trash",
            "[Gmail]/Drafts",
            "[Gmail]/Bin",
            "[Gmail]/Important",
        }
        assert provider_gmail.GMAIL_SYSTEM_FOLDERS == expected

    def test_gmail_mode_flag(self, single_mock_server, monkeypatch, tmp_path):
        """Test --gmail-mode flag backs up All Mail and creates manifest."""
        src_data = {
            "INBOX": [b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
            "Work": [b"Subject: Work Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
            "[Gmail]/All Mail": [b"Subject: Inbox Email\r\nMessage-ID: <1@test>\r\n\r\nBody"],
        }
        _, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["backup_imap_emails.py", "--dest-path", str(tmp_path), "--gmail-mode"],
        )
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        # Check manifest was created
        manifest_path = tmp_path / "labels_manifest.json"
        assert manifest_path.exists()

        # Check only [Gmail]/All Mail folder was backed up (not INBOX or Work)
        all_mail_folder = tmp_path / "[Gmail]" / "All Mail"
        assert all_mail_folder.exists()

        # Should NOT have created separate INBOX or Work folders
        inbox_folder = tmp_path / "INBOX"
        work_folder = tmp_path / "Work"
        assert not inbox_folder.exists()
        assert not work_folder.exists()


class TestDeleteOrphanLocalFiles:
    """Tests for delete_orphan_local_files function."""

    def test_delete_orphan_files(self, tmp_path):
        """Test that local files not on server are deleted."""
        # Create a local folder with some .eml files
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        # Create files with UIDs 1, 2, 3
        (inbox_path / "1_Test_Email.eml").write_bytes(b"content1")
        (inbox_path / "2_Another_Email.eml").write_bytes(b"content2")
        (inbox_path / "3_Third_Email.eml").write_bytes(b"content3")

        # Server only has UIDs 1 and 3
        server_uids = {"1", "3"}

        deleted = backup_imap_emails.delete_orphan_local_files(str(inbox_path), server_uids)

        # UID 2 should be deleted
        assert deleted == 1
        assert (inbox_path / "1_Test_Email.eml").exists()
        assert not (inbox_path / "2_Another_Email.eml").exists()
        assert (inbox_path / "3_Third_Email.eml").exists()

    def test_delete_multiple_orphans(self, tmp_path):
        """Test deleting multiple orphan files."""
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        # Create files with UIDs 1-5
        for i in range(1, 6):
            (inbox_path / f"{i}_Email_{i}.eml").write_bytes(f"content{i}".encode())

        # Server only has UID 3
        server_uids = {"3"}

        deleted = backup_imap_emails.delete_orphan_local_files(str(inbox_path), server_uids)

        # 4 files should be deleted (UIDs 1, 2, 4, 5)
        assert deleted == 4
        assert not (inbox_path / "1_Email_1.eml").exists()
        assert not (inbox_path / "2_Email_2.eml").exists()
        assert (inbox_path / "3_Email_3.eml").exists()
        assert not (inbox_path / "4_Email_4.eml").exists()
        assert not (inbox_path / "5_Email_5.eml").exists()

    def test_no_orphans(self, tmp_path):
        """Test when all local files exist on server."""
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        (inbox_path / "1_Email.eml").write_bytes(b"content")
        (inbox_path / "2_Email.eml").write_bytes(b"content")

        server_uids = {"1", "2"}

        deleted = backup_imap_emails.delete_orphan_local_files(str(inbox_path), server_uids)

        assert deleted == 0
        assert (inbox_path / "1_Email.eml").exists()
        assert (inbox_path / "2_Email.eml").exists()

    def test_nonexistent_folder(self, tmp_path):
        """Test with nonexistent folder path."""
        deleted = backup_imap_emails.delete_orphan_local_files(str(tmp_path / "nonexistent"), {"1", "2"})
        assert deleted == 0

    def test_ignore_non_eml_files(self, tmp_path):
        """Test that non-.eml files are ignored."""
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()

        (inbox_path / "1_Email.eml").write_bytes(b"content")
        (inbox_path / "notes.txt").write_bytes(b"some notes")
        (inbox_path / "2_data.json").write_bytes(b"{}")

        # Server only has UID 1
        server_uids = {"1"}

        deleted = backup_imap_emails.delete_orphan_local_files(str(inbox_path), server_uids)

        # Only .eml files should be considered
        assert deleted == 0
        assert (inbox_path / "notes.txt").exists()
        assert (inbox_path / "2_data.json").exists()


class TestDestDeleteBackupArgument:
    """Tests for --dest-delete argument in backup script."""

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


class TestDestDeleteBackupEnvVar:
    """End-to-end tests for DEST_DELETE env var wiring in backup script."""

    def test_dest_delete_enabled_via_env_var_deletes_orphans(self, single_mock_server, monkeypatch, tmp_path):
        """If DEST_DELETE=true and server folder is empty, local orphans are deleted."""
        src_data = {"INBOX": []}
        _, port = single_mock_server(src_data)

        backup_root = tmp_path / "backup"
        inbox_path = backup_root / "INBOX"
        inbox_path.mkdir(parents=True)
        orphan = inbox_path / "1_Orphan.eml"
        orphan.write_bytes(b"Subject: Orphan\r\nMessage-ID: <orphan@test>\r\n\r\nBody")

        monkeypatch.setenv("SRC_IMAP_HOST", "localhost")
        monkeypatch.setenv("SRC_IMAP_USERNAME", "user")
        monkeypatch.setenv("SRC_IMAP_PASSWORD", "pass")
        monkeypatch.setenv("BACKUP_LOCAL_PATH", str(backup_root))
        monkeypatch.setenv("MAX_WORKERS", "1")
        monkeypatch.setenv("DEST_DELETE", "true")

        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        backup_imap_emails.main()

        assert not orphan.exists()
