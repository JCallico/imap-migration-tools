"""
Tests for restore_imap_emails.py

Tests cover:
- Email parsing from .eml files
- Basic email restoration
- Gmail labels application
- Duplicate detection
- Configuration validation
"""

import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import restore_imap_emails
from conftest import make_single_mock_connection


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

        result = restore_imap_emails.load_labels_manifest(str(tmp_path))
        assert result == manifest_data

    def test_load_manifest_new_format(self, tmp_path):
        """Test loading manifest with new format (dict with labels and flags)."""
        manifest_data = {
            "<msg1@test.com>": {"labels": ["INBOX", "Work"], "flags": ["\\Seen", "\\Flagged"]},
            "<msg2@test.com>": {"labels": ["Sent Mail"], "flags": []},
        }
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))

        result = restore_imap_emails.load_labels_manifest(str(tmp_path))
        assert result == manifest_data
        assert "\\Seen" in result["<msg1@test.com>"]["flags"]
        assert result["<msg2@test.com>"]["flags"] == []

    def test_load_nonexistent_manifest(self, tmp_path):
        """Test loading when manifest doesn't exist."""
        result = restore_imap_emails.load_labels_manifest(str(tmp_path))
        assert result == {}

    def test_load_invalid_json_manifest(self, tmp_path):
        """Test loading invalid JSON manifest."""
        manifest_path = tmp_path / "labels_manifest.json"
        manifest_path.write_text("not valid json {{{")

        result = restore_imap_emails.load_labels_manifest(str(tmp_path))
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

        assert message_id == ""
        assert raw_content is not None

    def test_parse_nonexistent_file(self):
        """Test parsing non-existent file."""
        message_id, date_str, raw_content, subject = restore_imap_emails.parse_eml_file("/nonexistent/file.eml")

        assert message_id is None
        assert raw_content is None


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


class TestGetBackupFolders:
    """Tests for scanning backup folder structure."""

    def test_get_backup_folders(self, tmp_path):
        """Test scanning backup folders."""
        # Create folder structure
        inbox = tmp_path / "INBOX"
        inbox.mkdir()
        (inbox / "email1.eml").write_text("content")

        sent = tmp_path / "Sent"
        sent.mkdir()
        (sent / "email2.eml").write_text("content")

        result = restore_imap_emails.get_backup_folders(str(tmp_path))

        assert len(result) == 2
        folder_names = [f[0] for f in result]
        assert "INBOX" in folder_names
        assert "Sent" in folder_names

    def test_get_backup_folders_nested(self, tmp_path):
        """Test scanning nested folder structure."""
        gmail = tmp_path / "[Gmail]"
        gmail.mkdir()
        all_mail = gmail / "All Mail"
        all_mail.mkdir()
        (all_mail / "email.eml").write_text("content")

        result = restore_imap_emails.get_backup_folders(str(tmp_path))

        assert len(result) == 1
        assert result[0][0] == "[Gmail]/All Mail"

    def test_get_backup_folders_empty(self, tmp_path):
        """Test scanning empty backup folder."""
        result = restore_imap_emails.get_backup_folders(str(tmp_path))
        assert result == []


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_credentials(self, monkeypatch, capsys):
        """Test that missing credentials cause exit."""
        env = {}
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["restore_imap_emails.py", "--src-path", "/tmp"])

        with pytest.raises(SystemExit) as exc_info:
            restore_imap_emails.main()

        assert exc_info.value.code == 1

    def test_missing_src_path(self, monkeypatch, capsys):
        """Test that missing source path causes exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "user",
            "DEST_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["restore_imap_emails.py"])

        with pytest.raises(SystemExit) as exc_info:
            restore_imap_emails.main()

        assert exc_info.value.code == 1

    def test_nonexistent_src_path(self, monkeypatch, capsys):
        """Test that non-existent source path causes exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "user",
            "DEST_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["restore_imap_emails.py", "--src-path", "/nonexistent/path"],
        )

        with pytest.raises(SystemExit) as exc_info:
            restore_imap_emails.main()

        assert exc_info.value.code == 1


class TestUploadEmail:
    """Tests for email upload functionality."""

    def test_upload_email_success(self, monkeypatch):
        """Test successful email upload."""
        mock_conn = MagicMock()
        mock_conn.create.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [b"1"])
        mock_conn.append.return_value = ("OK", [])

        # Mock message_exists_in_folder to return False (not a duplicate)
        monkeypatch.setattr("imap_common.message_exists_in_folder", lambda *args: False)

        result = restore_imap_emails.upload_email(
            mock_conn,
            "INBOX",
            b"raw email content",
            '"15-Jan-2024 10:30:00 +0000"',
            "<test@test.com>",
            "Test Subject",
        )

        assert result is True
        mock_conn.append.assert_called_once()

    def test_upload_email_duplicate(self, monkeypatch):
        """Test upload skips duplicate."""
        mock_conn = MagicMock()
        mock_conn.select.return_value = ("OK", [b"1"])

        # Mock message_exists_in_folder to return True (is a duplicate)
        monkeypatch.setattr("imap_common.message_exists_in_folder", lambda *args: True)

        result = restore_imap_emails.upload_email(
            mock_conn,
            "INBOX",
            b"raw email content",
            '"15-Jan-2024 10:30:00 +0000"',
            "<test@test.com>",
            "Test Subject",
        )

        assert result is False
        mock_conn.append.assert_not_called()

    def test_upload_email_with_seen_flag(self, monkeypatch):
        """Test upload with \\Seen flag for read emails."""
        mock_conn = MagicMock()
        mock_conn.create.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [b"1"])
        mock_conn.append.return_value = ("OK", [])

        # Mock message_exists_in_folder to return False (not a duplicate)
        monkeypatch.setattr("imap_common.message_exists_in_folder", lambda *args: False)

        result = restore_imap_emails.upload_email(
            mock_conn,
            "INBOX",
            b"raw email content",
            '"15-Jan-2024 10:30:00 +0000"',
            "<test@test.com>",
            "Test Subject",
            flags="\\Seen",  # Mark as read
        )

        assert result is True
        # Check that append was called with the \\Seen flag
        call_args = mock_conn.append.call_args
        assert call_args[0][1] == "\\Seen"


class TestRestoreIntegration:
    """Integration tests for restore functionality."""

    def test_restore_single_folder(self, single_mock_server, monkeypatch, tmp_path):
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

        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "user",
            "DEST_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["restore_imap_emails.py", "--src-path", str(tmp_path), "INBOX"],
        )
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        # Run restore
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
        result = restore_imap_emails.load_labels_manifest(str(tmp_path))
        assert len(result) == 2
        assert result["<msg1@test.com>"] == ["INBOX", "Work"]


class TestEmailExistsInFolder:
    """Tests for duplicate detection."""

    def test_email_exists_true(self, monkeypatch):
        """Test detecting existing email."""
        mock_conn = MagicMock()
        monkeypatch.setattr("imap_common.message_exists_in_folder", lambda *args: True)

        result = restore_imap_emails.email_exists_in_folder(mock_conn, "<test@test.com>", 1000)
        assert result is True

    def test_email_exists_false(self, monkeypatch):
        """Test detecting non-existing email."""
        mock_conn = MagicMock()
        monkeypatch.setattr("imap_common.message_exists_in_folder", lambda *args: False)

        result = restore_imap_emails.email_exists_in_folder(mock_conn, "<test@test.com>", 1000)
        assert result is False

    def test_email_exists_no_message_id(self, monkeypatch):
        """Test with no message ID."""
        mock_conn = MagicMock()

        result = restore_imap_emails.email_exists_in_folder(mock_conn, None, 1000)
        assert result is False

    def test_email_exists_exception(self, monkeypatch):
        """Test handling exception."""
        mock_conn = MagicMock()
        monkeypatch.setattr(
            "imap_common.message_exists_in_folder",
            lambda *args: (_ for _ in ()).throw(Exception("Error")),
        )

        result = restore_imap_emails.email_exists_in_folder(mock_conn, "<test@test.com>", 1000)
        assert result is False
