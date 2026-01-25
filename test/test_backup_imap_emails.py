"""
Tests for backup_imap_emails.py

Tests cover:
- Basic email backup to local files
- Incremental backup (skip existing)
- Multiple folder backup
- Filename sanitization
- Configuration validation
"""

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import backup_imap_emails
from conftest import make_single_mock_connection


class TestBackupBasic:
    """Tests for basic backup functionality."""

    def test_single_email_backup(self, single_mock_server, monkeypatch, tmp_path):
        """Test backing up a single email to local directory."""
        src_data = {"INBOX": [b"Subject: Test Email\r\nMessage-ID: <1@test>\r\n\r\nBody content"]}
        server, port = single_mock_server(src_data)

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
        server, port = single_mock_server(src_data)

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
        server, port = single_mock_server(src_data)

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
        server, port = single_mock_server(src_data)

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
        server, port = single_mock_server(src_data)

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
        server, port = single_mock_server(src_data)

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

    def test_missing_credentials(self, monkeypatch, capsys):
        """Test that missing credentials cause exit."""
        env = {}
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup_imap_emails.py", "--dest-path", "/tmp"])

        with pytest.raises(SystemExit) as exc_info:
            backup_imap_emails.main()

        assert exc_info.value.code == 1

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

        assert exc_info.value.code == 1


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

    def test_os_error_handling(self, monkeypatch):
        """Test handling of OS errors during listing."""

        def mock_listdir(path):
            raise OSError("Access denied")

        monkeypatch.setattr(os, "listdir", mock_listdir)

        uids = backup_imap_emails.get_existing_uids("/some/path")
        assert len(uids) == 0


class TestBackupErrorHandling:
    """Tests for error handling scenarios in backup."""

    def test_connection_error_in_worker(self, monkeypatch):
        """Test worker handles connection failure gracefully."""
        # Mock get_imap_connection to fail
        monkeypatch.setattr("imap_common.get_imap_connection", lambda *args: None)

        # Should return None/Exit without crashing
        backup_imap_emails.process_batch([], "INBOX", ("h", "u", "p"), "/tmp")

    def test_select_error_in_worker(self, monkeypatch):
        """Test worker handles SELECT failure."""
        mock_conn = MagicMock()
        mock_conn.select.side_effect = Exception("Select error")
        monkeypatch.setattr("imap_common.get_imap_connection", lambda *args: mock_conn)

        # Should log error and return
        backup_imap_emails.process_batch([], "INBOX", ("h", "u", "p"), "/tmp")
        mock_conn.select.assert_called()

    def test_fetch_body_error(self, monkeypatch, tmp_path):
        """Test handling of fetch body failure."""
        mock_conn = MagicMock()
        mock_conn.select.return_value = "OK"
        # get_msg_details calls fetch headers, make it work
        monkeypatch.setattr("imap_common.get_msg_details", lambda conn, uid: (uid, 100, "Subject"))

        # Fetch body fails
        mock_conn.uid.return_value = ("NO", [None])

        monkeypatch.setattr("imap_common.get_imap_connection", lambda *args: mock_conn)

        # Try processing one UID
        backup_imap_emails.process_batch([b"1"], "INBOX", ("h", "u", "p"), str(tmp_path))

        # File should not exist
        assert not list(tmp_path.glob("*.eml"))

    def test_write_error(self, monkeypatch, tmp_path):
        """Test handling of file write error."""
        mock_conn = MagicMock()
        monkeypatch.setattr("imap_common.get_imap_connection", lambda *args: mock_conn)

        # Mock fetched data
        monkeypatch.setattr("imap_common.get_msg_details", lambda conn, uid: (uid, 100, "Subject"))
        mock_conn.uid.return_value = ("OK", [(b"1 (RFC822 {10}", b"Content")])

        # Mock open to fail
        def mock_open(*args, **kwargs):
            raise OSError("Disk full")

        monkeypatch.setattr("builtins.open", mock_open)

        backup_imap_emails.process_batch([b"1"], "INBOX", ("h", "u", "p"), str(tmp_path))

    def test_folder_creation_error(self, monkeypatch):
        """Test handling failure to create local folder."""

        def mock_makedirs(path, exist_ok=False):
            raise OSError("Permission denied")

        monkeypatch.setattr(os, "makedirs", mock_makedirs)

        mock_conn = MagicMock()

        # backup_folder should return early
        backup_imap_emails.backup_folder(mock_conn, "INBOX", "/tmp", ("h", "u", "p"))
        mock_conn.select.assert_not_called()

    def test_select_folder_error(self, monkeypatch):
        """Test handling of select folder failure in main loop."""
        mock_conn = MagicMock()
        mock_conn.select.side_effect = Exception("Select failed")
        monkeypatch.setattr(os, "makedirs", lambda p, exist_ok: None)

        backup_imap_emails.backup_folder(mock_conn, "INBOX", "/tmp", ("h", "u", "p"))
        mock_conn.uid.assert_not_called()

    def test_search_error(self, monkeypatch):
        """Test handling of search failure."""
        mock_conn = MagicMock()
        mock_conn.uid.return_value = ("NO", [])
        monkeypatch.setattr(os, "makedirs", lambda p, exist_ok: None)

        backup_imap_emails.backup_folder(mock_conn, "INBOX", "/tmp", ("h", "u", "p"))

    def test_main_makedirs_error(self, monkeypatch, capsys):
        """Test failure to create main backup directory."""
        env = {
            "SRC_IMAP_HOST": "h",
            "SRC_IMAP_USERNAME": "u",
            "SRC_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["backup.py", "--dest-path", "/protected/path"])

        def mock_makedirs(path):
            raise OSError("No permission")

        monkeypatch.setattr(os, "makedirs", mock_makedirs)
        monkeypatch.setattr(os.path, "exists", lambda p: False)

        with pytest.raises(SystemExit):
            backup_imap_emails.main()

        captured = capsys.readouterr()
        assert "Error creating backup directory" in captured.out
