"""
Tests for migrate_imap_emails.py

Tests cover:
- Basic email migration
- Duplicate detection and skipping
- Delete from source after migration
- Folder creation on destination
- Multiple folder migration
- Error handling
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import migrate_imap_emails
from conftest import make_mock_connection


class TestBasicMigration:
    """Tests for basic migration functionality."""

    def test_single_email_migration(self, mock_server_factory, monkeypatch):
        """Test migrating a single email from source to destination."""
        src_data = {"INBOX": [b"Subject: Hello\r\nMessage-ID: <1@test>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert b"Subject: Hello" in dest_server.folders["INBOX"][0]["content"]

    def test_multiple_emails_migration(self, mock_server_factory, monkeypatch):
        """Test migrating multiple emails."""
        src_data = {
            "INBOX": [
                b"Subject: Email 1\r\nMessage-ID: <1@test>\r\n\r\nBody 1",
                b"Subject: Email 2\r\nMessage-ID: <2@test>\r\n\r\nBody 2",
                b"Subject: Email 3\r\nMessage-ID: <3@test>\r\n\r\nBody 3",
            ]
        }
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 3


class TestDuplicateHandling:
    """Tests for duplicate detection and skipping."""

    def test_skip_duplicate_by_message_id(self, mock_server_factory, monkeypatch):
        """Test that emails with existing Message-ID are skipped."""
        msg = b"Subject: Dup\r\nMessage-ID: <dup-id>\r\n\r\nContent"
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": [msg]}  # Already exists

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        # Should still be 1 message (duplicate skipped)
        assert len(dest_server.folders["INBOX"]) == 1

    def test_migrate_non_duplicate(self, mock_server_factory, monkeypatch):
        """Test that non-duplicate emails are migrated even when others exist."""
        existing = b"Subject: Existing\r\nMessage-ID: <existing>\r\n\r\nOld"
        new_msg = b"Subject: New\r\nMessage-ID: <new>\r\n\r\nNew content"

        src_data = {"INBOX": [new_msg]}
        dest_data = {"INBOX": [existing]}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        # Should now have 2 messages
        assert len(dest_server.folders["INBOX"]) == 2


class TestDeleteFromSource:
    """Tests for delete-after-migration functionality."""

    def test_delete_after_migration(self, mock_server_factory, monkeypatch):
        """Test that emails are deleted from source after successful migration."""
        src_data = {"INBOX": [b"Subject: Del\r\nMessage-ID: <del>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
            "DELETE_FROM_SOURCE": "true",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert len(src_server.folders["INBOX"]) == 0

    def test_no_delete_when_disabled(self, mock_server_factory, monkeypatch):
        """Test that emails remain in source when delete is not enabled."""
        src_data = {"INBOX": [b"Subject: Keep\r\nMessage-ID: <keep>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
            # DELETE_FROM_SOURCE not set
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert len(src_server.folders["INBOX"]) == 1


class TestFolderHandling:
    """Tests for folder creation and multi-folder migration."""

    def test_folder_creation(self, mock_server_factory, monkeypatch):
        """Test that folders are created on destination."""
        src_data = {"INBOX": [], "Archive": [b"Subject: A\r\nMessage-ID: <a>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        assert "Archive" in dest_server.folders
        assert len(dest_server.folders["Archive"]) == 1

    def test_multiple_folders_migration(self, mock_server_factory, monkeypatch):
        """Test migrating emails from multiple folders."""
        src_data = {
            "INBOX": [b"Subject: Inbox\r\nMessage-ID: <inbox>\r\n\r\nC"],
            "Sent": [b"Subject: Sent\r\nMessage-ID: <sent>\r\n\r\nC"],
            "Drafts": [b"Subject: Draft\r\nMessage-ID: <draft>\r\n\r\nC"],
        }
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert "Sent" in dest_server.folders
        assert "Drafts" in dest_server.folders

    def test_empty_folder_handling(self, mock_server_factory, monkeypatch):
        """Test that empty folders are handled gracefully."""
        src_data = {"INBOX": [], "Empty": []}
        dest_data = {"INBOX": []}

        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
            "MAX_WORKERS": "1",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        # Should complete without error
        migrate_imap_emails.main()


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_source_credentials(self, monkeypatch, capsys):
        """Test that missing source credentials cause exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)

        with pytest.raises(SystemExit) as exc_info:
            migrate_imap_emails.main()

        assert exc_info.value.code == 1

    def test_missing_dest_credentials(self, monkeypatch, capsys):
        """Test that missing destination credentials cause exit."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src",
            "SRC_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)

        with pytest.raises(SystemExit) as exc_info:
            migrate_imap_emails.main()

        assert exc_info.value.code == 1
