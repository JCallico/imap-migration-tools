"""
Tests for provider_gmail.py

Tests cover:
- Gmail label folder detection
- Folder name to label name conversion
- Label name to folder path conversion
- Gmail label index building
"""

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import provider_gmail


class TestIsLabelFolder:
    """Tests for is_label_folder function."""

    def test_user_labels(self):
        """Test that user-created labels are correctly identified."""
        assert provider_gmail.is_label_folder("Work") is True
        assert provider_gmail.is_label_folder("Personal") is True
        assert provider_gmail.is_label_folder("Projects/2024") is True

    def test_inbox_is_label(self):
        """Test that INBOX is considered a label."""
        assert provider_gmail.is_label_folder("INBOX") is True

    def test_gmail_sent_and_starred_labels(self):
        """Test that Gmail Sent and Starred are labels worth preserving."""
        assert provider_gmail.is_label_folder("[Gmail]/Sent Mail") is True
        assert provider_gmail.is_label_folder("[Gmail]/Starred") is True

    def test_gmail_system_folders_excluded(self):
        """Test that Gmail system folders are not considered labels."""
        assert provider_gmail.is_label_folder("[Gmail]/All Mail") is False
        assert provider_gmail.is_label_folder("[Gmail]/Spam") is False
        assert provider_gmail.is_label_folder("[Gmail]/Trash") is False
        assert provider_gmail.is_label_folder("[Gmail]/Drafts") is False
        assert provider_gmail.is_label_folder("[Gmail]/Bin") is False
        assert provider_gmail.is_label_folder("[Gmail]/Important") is False

    def test_other_gmail_folders_excluded(self):
        """Test that other [Gmail]/ folders are not considered labels."""
        assert provider_gmail.is_label_folder("[Gmail]/Archive") is False

    def test_empty_string(self):
        """Test handling of empty string."""
        assert provider_gmail.is_label_folder("") is True  # Empty string doesn't start with [Gmail]/

    def test_nested_labels(self):
        """Test nested user labels."""
        assert provider_gmail.is_label_folder("Work/Projects") is True
        assert provider_gmail.is_label_folder("Personal/Family/Photos") is True


class TestFolderToLabel:
    """Tests for folder_to_label function."""

    def test_inbox_unchanged(self):
        """Test that INBOX stays as INBOX."""
        assert provider_gmail.folder_to_label("INBOX") == "INBOX"

    def test_gmail_sent_mail(self):
        """Test conversion of [Gmail]/Sent Mail."""
        assert provider_gmail.folder_to_label("[Gmail]/Sent Mail") == "Sent Mail"

    def test_gmail_starred(self):
        """Test conversion of [Gmail]/Starred."""
        assert provider_gmail.folder_to_label("[Gmail]/Starred") == "Starred"

    def test_gmail_drafts(self):
        """Test conversion of [Gmail]/Drafts."""
        assert provider_gmail.folder_to_label("[Gmail]/Drafts") == "Drafts"

    def test_user_label_unchanged(self):
        """Test that user labels remain unchanged."""
        assert provider_gmail.folder_to_label("Work") == "Work"
        assert provider_gmail.folder_to_label("Personal") == "Personal"

    def test_nested_label_unchanged(self):
        """Test that nested user labels remain unchanged."""
        assert provider_gmail.folder_to_label("Work/Projects") == "Work/Projects"


class TestLabelToFolder:
    """Tests for label_to_folder function."""

    def test_inbox_unchanged(self):
        """Test that INBOX stays as INBOX."""
        assert provider_gmail.label_to_folder("INBOX") == "INBOX"

    def test_sent_mail_to_gmail_folder(self):
        """Test conversion of Sent Mail label to [Gmail]/ folder."""
        assert provider_gmail.label_to_folder("Sent Mail") == "[Gmail]/Sent Mail"

    def test_starred_to_gmail_folder(self):
        """Test conversion of Starred label to [Gmail]/ folder."""
        assert provider_gmail.label_to_folder("Starred") == "[Gmail]/Starred"

    def test_drafts_to_gmail_folder(self):
        """Test conversion of Drafts label to [Gmail]/ folder."""
        assert provider_gmail.label_to_folder("Drafts") == "[Gmail]/Drafts"

    def test_important_to_gmail_folder(self):
        """Test conversion of Important label to [Gmail]/ folder."""
        assert provider_gmail.label_to_folder("Important") == "[Gmail]/Important"

    def test_user_label_unchanged(self):
        """Test that user labels remain unchanged."""
        assert provider_gmail.label_to_folder("Work") == "Work"
        assert provider_gmail.label_to_folder("Personal") == "Personal"

    def test_nested_label_unchanged(self):
        """Test that nested user labels remain unchanged."""
        assert provider_gmail.label_to_folder("Work/Projects") == "Work/Projects"


class TestResolveTarget:
    """Tests for resolve_target function."""

    def test_picks_first_valid_label_as_target(self):
        target, remaining = provider_gmail.resolve_target(["Work", "Personal"])
        assert target == "Work"
        assert remaining == ["Personal"]

    def test_skips_system_folders(self):
        target, remaining = provider_gmail.resolve_target(["[Gmail]/All Mail", "[Gmail]/Spam", "[Gmail]/Trash", "Work"])
        assert target == "Work"
        assert remaining == []

    def test_all_system_labels_returns_unlabeled(self):
        target, remaining = provider_gmail.resolve_target(["[Gmail]/All Mail", "[Gmail]/Spam"])
        assert target == "Restored/Unlabeled"
        assert remaining == []

    def test_empty_labels_returns_unlabeled(self):
        target, remaining = provider_gmail.resolve_target([])
        assert target == "Restored/Unlabeled"
        assert remaining == []

    def test_special_labels_mapped_to_gmail_folders(self):
        target, remaining = provider_gmail.resolve_target(["Sent Mail", "Work"])
        assert target == "[Gmail]/Sent Mail"
        assert remaining == ["Work"]

    def test_multiple_remaining_labels(self):
        target, remaining = provider_gmail.resolve_target(["Work", "Personal", "Finance"])
        assert target == "Work"
        assert remaining == ["Personal", "Finance"]


class TestBuildGmailLabelIndex:
    """Tests for build_gmail_label_index function."""

    def test_builds_index_from_label_folders(self):
        """Test building label index from multiple label folders."""
        mock_conn = MagicMock()

        # Mock list_selectable_folders to return a mix of folders
        def mock_list_folders(conn):
            return ["INBOX", "[Gmail]/All Mail", "Work", "Personal", "[Gmail]/Sent Mail"]

        # Mock get_message_ids_in_folder to return different messages for each folder
        folder_messages = {
            "INBOX": {"1": "<msg1@test.com>", "2": "<msg2@test.com>"},
            "Work": {"3": "<msg1@test.com>", "4": "<msg3@test.com>"},
            "Personal": {"5": "<msg2@test.com>", "6": "<msg4@test.com>"},
            "[Gmail]/Sent Mail": {"7": "<msg1@test.com>"},
        }

        def mock_get_message_ids(conn):
            # Determine which folder we're in based on the select call
            selected_folder = mock_conn.select.call_args[0][0].strip('"')
            return folder_messages.get(selected_folder, {})

        def mock_safe_print(msg):
            pass

        import imap_common

        with pytest.MonkeyPatch.context() as m:
            m.setattr(imap_common, "list_selectable_folders", mock_list_folders)
            m.setattr(imap_common, "get_message_ids_in_folder", mock_get_message_ids)

            result = provider_gmail.build_gmail_label_index(mock_conn, mock_safe_print)

        # Verify the index contains the expected mappings
        assert "<msg1@test.com>" in result
        assert "INBOX" in result["<msg1@test.com>"]
        assert "Work" in result["<msg1@test.com>"]
        assert "Sent Mail" in result["<msg1@test.com>"]

        assert "<msg2@test.com>" in result
        assert "INBOX" in result["<msg2@test.com>"]
        assert "Personal" in result["<msg2@test.com>"]

        assert "<msg3@test.com>" in result
        assert "Work" in result["<msg3@test.com>"]

        assert "<msg4@test.com>" in result
        assert "Personal" in result["<msg4@test.com>"]

    def test_excludes_system_folders(self):
        """Test that system folders like [Gmail]/All Mail are excluded from the index."""
        mock_conn = MagicMock()

        def mock_list_folders(conn):
            return ["[Gmail]/All Mail", "[Gmail]/Spam", "[Gmail]/Trash", "Work"]

        def mock_get_message_ids(conn):
            selected_folder = mock_conn.select.call_args[0][0].strip('"')
            if selected_folder == "Work":
                return {"1": "<msg1@test.com>"}
            return {}

        def mock_safe_print(msg):
            pass

        import imap_common

        with pytest.MonkeyPatch.context() as m:
            m.setattr(imap_common, "list_selectable_folders", mock_list_folders)
            m.setattr(imap_common, "get_message_ids_in_folder", mock_get_message_ids)

            result = provider_gmail.build_gmail_label_index(mock_conn, mock_safe_print)

        # Should only have the Work label, system folders should be excluded
        assert "<msg1@test.com>" in result
        assert "Work" in result["<msg1@test.com>"]
        assert "All Mail" not in result.get("<msg1@test.com>", set())

    def test_handles_folder_error_gracefully(self):
        """Test that errors in individual folders don't stop the entire process."""
        mock_conn = MagicMock()

        def mock_list_folders(conn):
            return ["INBOX", "Work"]

        def mock_get_message_ids(conn):
            selected_folder = mock_conn.select.call_args[0][0].strip('"')
            if selected_folder == "INBOX":
                return {"1": "<msg1@test.com>"}
            # Simulate error for Work folder
            raise Exception("Failed to fetch Work folder")

        def mock_safe_print(msg):
            pass

        import imap_common

        with pytest.MonkeyPatch.context() as m:
            m.setattr(imap_common, "list_selectable_folders", mock_list_folders)
            m.setattr(imap_common, "get_message_ids_in_folder", mock_get_message_ids)

            # Should not raise, should continue and build partial index
            result = provider_gmail.build_gmail_label_index(mock_conn, mock_safe_print)

        # Should have INBOX data despite Work folder error
        assert "<msg1@test.com>" in result
        assert "INBOX" in result["<msg1@test.com>"]


class TestGmailConstants:
    """Tests for Gmail constants."""

    def test_gmail_system_folders_constant(self):
        """Test that GMAIL_SYSTEM_FOLDERS contains expected folders."""
        assert "[Gmail]/All Mail" in provider_gmail.GMAIL_SYSTEM_FOLDERS
        assert "[Gmail]/Spam" in provider_gmail.GMAIL_SYSTEM_FOLDERS
        assert "[Gmail]/Trash" in provider_gmail.GMAIL_SYSTEM_FOLDERS
        assert "[Gmail]/Drafts" in provider_gmail.GMAIL_SYSTEM_FOLDERS
        assert "[Gmail]/Bin" in provider_gmail.GMAIL_SYSTEM_FOLDERS
        assert "[Gmail]/Important" in provider_gmail.GMAIL_SYSTEM_FOLDERS

    def test_gmail_sent_not_in_system_folders(self):
        """Test that [Gmail]/Sent Mail is not in GMAIL_SYSTEM_FOLDERS."""
        assert "[Gmail]/Sent Mail" not in provider_gmail.GMAIL_SYSTEM_FOLDERS

    def test_gmail_starred_not_in_system_folders(self):
        """Test that [Gmail]/Starred is not in GMAIL_SYSTEM_FOLDERS."""
        assert "[Gmail]/Starred" not in provider_gmail.GMAIL_SYSTEM_FOLDERS
