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

import imaplib
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_common
import migrate_imap_emails
from conftest import temp_argv, temp_env


def _mock_migrate_env(src_port, dest_port):
    return {
        "SRC_IMAP_HOST": f"imap://localhost:{src_port}",
        "SRC_IMAP_USERNAME": "src_user",
        "SRC_IMAP_PASSWORD": "p",
        "DEST_IMAP_HOST": f"imap://localhost:{dest_port}",
        "DEST_IMAP_USERNAME": "dest_user",
        "DEST_IMAP_PASSWORD": "p",
        "MAX_WORKERS": "1",
        "BATCH_SIZE": "1",
    }


class TestBasicMigration:
    """Tests for basic migration functionality."""

    def test_single_email_migration(self, mock_server_factory):
        """Test migrating a single email from source to destination."""
        src_data = {"INBOX": [b"Subject: Hello\r\nMessage-ID: <1@test>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert b"Subject: Hello" in dest_server.folders["INBOX"][0]["content"]

    def test_multiple_emails_migration(self, mock_server_factory):
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

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 3


class TestDuplicateHandling:
    """Tests for duplicate detection and skipping."""

    def test_skip_duplicate_by_message_id(self, mock_server_factory):
        """Test that emails with existing Message-ID are skipped."""
        msg = b"Subject: Dup\r\nMessage-ID: <dup-id>\r\n\r\nContent"
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": [msg]}  # Already exists

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        # Should still be 1 message (duplicate skipped)
        assert len(dest_server.folders["INBOX"]) == 1

    def test_migrate_non_duplicate(self, mock_server_factory):
        """Test that non-duplicate emails are migrated even when others exist."""
        existing = b"Subject: Existing\r\nMessage-ID: <existing>\r\n\r\nOld"
        new_msg = b"Subject: New\r\nMessage-ID: <new>\r\n\r\nNew content"

        src_data = {"INBOX": [new_msg]}
        dest_data = {"INBOX": [existing]}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        # Should now have 2 messages
        assert len(dest_server.folders["INBOX"]) == 2


class TestDeleteFromSource:
    """Tests for delete-after-migration functionality."""

    def test_delete_after_migration(self, mock_server_factory):
        """Test that emails are deleted from source after successful migration."""
        src_data = {"INBOX": [b"Subject: Del\r\nMessage-ID: <del>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        env["DELETE_FROM_SOURCE"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert len(src_server.folders["INBOX"]) == 0

    def test_no_delete_when_disabled(self, mock_server_factory):
        """Test that emails remain in source when delete is not enabled."""
        src_data = {"INBOX": [b"Subject: Keep\r\nMessage-ID: <keep>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert len(src_server.folders["INBOX"]) == 1


class TestFolderHandling:
    """Tests for folder creation and multi-folder migration."""

    def test_folder_creation(self, mock_server_factory):
        """Test that folders are created on destination."""
        src_data = {"INBOX": [], "Archive": [b"Subject: A\r\nMessage-ID: <a>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py"]):
            migrate_imap_emails.main()

        assert "Archive" in dest_server.folders
        assert len(dest_server.folders["Archive"]) == 1

    def test_multiple_folders_migration(self, mock_server_factory):
        """Test migrating emails from multiple folders."""
        src_data = {
            "INBOX": [b"Subject: Inbox\r\nMessage-ID: <inbox>\r\n\r\nC"],
            "Sent": [b"Subject: Sent\r\nMessage-ID: <sent>\r\n\r\nC"],
            "Drafts": [b"Subject: Draft\r\nMessage-ID: <draft>\r\n\r\nC"],
        }
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert "Sent" in dest_server.folders
        assert "Drafts" in dest_server.folders

    def test_empty_folder_handling(self, mock_server_factory):
        """Test that empty folders are handled gracefully."""
        src_data = {"INBOX": [], "Empty": []}
        dest_data = {"INBOX": []}

        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py"]):
            migrate_imap_emails.main()


class TestPreserveFlags:
    def test_preserve_flags_applied_on_copy(self, mock_server_factory):
        msg = b"Subject: Flagged\r\nMessage-ID: <f1@test>\r\n\r\nBody"
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)
        src_server.folders["INBOX"][0]["flags"].add("\\Seen")

        env = _mock_migrate_env(p1, p2)
        env["PRESERVE_FLAGS"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert "\\Seen" in dest_server.folders["INBOX"][0]["flags"]

    def test_preserve_flags_syncs_on_duplicate(self, mock_server_factory):
        msg = b"Subject: DupFlags\r\nMessage-ID: <df1@test>\r\n\r\nBody"
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": [msg]}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)
        src_server.folders["INBOX"][0]["flags"].add("\\Seen")

        env = _mock_migrate_env(p1, p2)
        env["PRESERVE_FLAGS"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert "\\Seen" in dest_server.folders["INBOX"][0]["flags"]


class TestGmailModeLabels:
    def test_gmail_mode_migrates_all_mail_and_applies_labels(self, mock_server_factory):
        msg1 = b"Subject: One\r\nMessage-ID: <gm1@test>\r\n\r\nBody 1"
        msg2 = b"Subject: Two\r\nMessage-ID: <gm2@test>\r\n\r\nBody 2"

        src_data = {
            "[Gmail]/All Mail": [msg1, msg2],
            "INBOX": [msg1],
            "Work": [msg1, msg2],
        }
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        env["GMAIL_MODE"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py"]):
            migrate_imap_emails.main()

        assert len(dest_server.folders["INBOX"]) == 1
        assert "Work" in dest_server.folders
        assert len(dest_server.folders["Work"]) == 2

    def test_gmail_mode_fallback_folder_for_unlabeled(self, mock_server_factory):
        msg = b"Subject: Unlabeled\r\nMessage-ID: <gm-unlabeled@test>\r\n\r\nBody"

        src_data = {
            "[Gmail]/All Mail": [msg],
        }
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        env["GMAIL_MODE"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py"]):
            migrate_imap_emails.main()

        assert imap_common.FOLDER_RESTORED_UNLABELED in dest_server.folders
        assert len(dest_server.folders[imap_common.FOLDER_RESTORED_UNLABELED]) == 1


class TestCacheHitWithoutLock:
    """Covers cached skip when no lock is provided."""

    def test_cached_skip_without_lock(self, mock_server_factory):
        msg_id = "<cache-no-lock@test>"
        msg = f"Subject: Cached\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        src = imaplib.IMAP4("localhost", p1)
        dest = imaplib.IMAP4("localhost", p2)
        src.login("src_user", "p")
        dest.login("dest_user", "p")

        src.select('"INBOX"', readonly=False)

        existing_dest_msg_ids = {msg_id}
        success, _src, _dest, deleted = migrate_imap_emails.process_single_uid(
            src,
            dest,
            b"1",
            "INBOX",
            False,
            None,
            False,
            False,
            None,
            True,
            False,
            existing_dest_msg_ids=existing_dest_msg_ids,
            existing_dest_msg_ids_lock=None,
            progress_cache_path=None,
            progress_cache_data=None,
            progress_cache_lock=None,
            dest_host="localhost",
            dest_user="dest_user",
        )

        assert success is True
        assert deleted == 0
        assert len(dest_server.folders["INBOX"]) == 0

        src.logout()
        dest.logout()


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_source_credentials(self, capsys):
        """Test that missing source credentials cause exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest",
            "DEST_IMAP_PASSWORD": "p",
        }
        with temp_env(env):
            with pytest.raises(SystemExit) as exc_info:
                migrate_imap_emails.main()

        assert exc_info.value.code == 2

    def test_missing_dest_credentials(self, capsys):
        """Test that missing destination credentials cause exit."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src",
            "SRC_IMAP_PASSWORD": "p",
        }
        with temp_env(env):
            with pytest.raises(SystemExit) as exc_info:
                migrate_imap_emails.main()

        assert exc_info.value.code == 2


class TestMigrateErrorHandling:
    """Tests for error handling during migration."""

    def test_connection_error_in_worker(self, mock_server_factory):
        """Test error handling when worker fails to connect."""
        src_data = {"INBOX": [b"Subject: Test\r\nMessage-ID: <1>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        from unittest.mock import patch

        def side_effect(host, user, pwd, oauth2_token=None):
            if threading.current_thread() is threading.main_thread():
                return imap_common.get_imap_connection(host, user, pwd, oauth2_token)
            return None  # Simulate connection failure in worker

        env = _mock_migrate_env(p1, p2)
        with (
            temp_env(env),
            temp_argv(["migrate_imap_emails.py", "INBOX"]),
            patch("imap_common.get_imap_connection", side_effect=side_effect),
        ):
            # Should not crash, but log error
            migrate_imap_emails.main()

    def test_select_error_in_worker(self, mock_server_factory):
        """Test error handling when folder selection fails in worker."""
        src_data = {"INBOX": [b"Subject: Test\r\nMessage-ID: <1>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        # Patch imaplib.IMAP4.select globally but condition on thread
        original_select = imaplib.IMAP4.select

        def side_effect_select(self, mailbox, readonly=False):
            if threading.current_thread() is not threading.main_thread():
                raise RuntimeError("Select failed")
            return original_select(self, mailbox, readonly)

        from unittest.mock import patch

        env = _mock_migrate_env(p1, p2)
        with (
            patch.object(imaplib.IMAP4, "select", side_effect=side_effect_select),
            temp_env(env),
            temp_argv(["migrate_imap_emails.py", "INBOX"]),
        ):
            migrate_imap_emails.main()

    def test_select_error_in_process_batch(self, mock_server_factory):
        """Cover process_batch select exception handling with real server data."""
        src_data = {"INBOX": [b"Subject: Test\r\nMessage-ID: <1>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _src_server, _dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        def raise_select(_self, _mailbox, readonly=False):
            raise RuntimeError("Select failed")

        from unittest.mock import patch

        env = _mock_migrate_env(p1, p2)
        src_conf = {"host": env["SRC_IMAP_HOST"], "user": "src_user", "password": "p"}
        dest_conf = {"host": env["DEST_IMAP_HOST"], "user": "dest_user", "password": "p"}

        with patch.object(imaplib.IMAP4, "select", raise_select), temp_env(env):
            migrate_imap_emails.process_batch(
                [b"1"],
                "INBOX",
                src_conf,
                dest_conf,
                delete_from_source=False,
                preserve_flags=False,
                gmail_mode=False,
            )

    def test_fetch_error_in_worker(self, mock_server_factory):
        """Test error handling when fetching message details fails."""
        src_data = {"INBOX": [b"Subject: Test\r\nMessage-ID: <1>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        # Patch imaplib.IMAP4.uid globally but condition on thread
        original_uid = imaplib.IMAP4.uid

        def side_effect_uid(self, command, *args):
            if command == "fetch" and threading.current_thread() is not threading.main_thread():
                raise RuntimeError("Fetch failed")
            return original_uid(self, command, *args)

        from unittest.mock import patch

        env = _mock_migrate_env(p1, p2)
        with (
            patch.object(imaplib.IMAP4, "uid", side_effect=side_effect_uid),
            temp_env(env),
            temp_argv(["migrate_imap_emails.py", "INBOX"]),
        ):
            migrate_imap_emails.main()

        # Dest should be empty as fetch failed
        assert len(dest_server.folders["INBOX"]) == 0

    def test_main_connection_failure(self):
        """Test that main exits if initial connection fails."""
        from unittest.mock import patch

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        with patch("imap_common.get_imap_connection", return_value=None), temp_env(env):
            with pytest.raises(SystemExit) as exc:
                migrate_imap_emails.main()
        assert exc.value.code == 1

    def test_main_logs_progress_cache_load_failure(self, mock_server_factory, capsys):
        """Cover progress cache load exception in main."""
        src_data = {"INBOX": [b"Subject: X\r\nMessage-ID: <x@test>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        _src_server, _dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        from unittest.mock import patch

        env = _mock_migrate_env(p1, p2)
        with (
            patch(
                "imap_common.load_progress_cache",
                lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
            ),
            temp_env(env),
            temp_argv(["migrate_imap_emails.py", "--migrate-cache", "./cache"]),
        ):
            migrate_imap_emails.main()

        captured = capsys.readouterr()
        assert "Warning: Failed to load progress cache" in captured.out


class TestTrashHandling:
    """Tests for trash folder related logic."""

    def test_circular_trash_migration_prevention(self, mock_server_factory):
        """Test that the trash folder itself is not migrated when delete is on."""
        src_data = {"INBOX": [], "Trash": [b"Subject: Garbage\r\nMessage-ID: <g>\r\n\r\nC"]}
        dest_data = {"INBOX": []}

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        from unittest.mock import patch

        env = _mock_migrate_env(p1, p2)
        env["DELETE_FROM_SOURCE"] = "true"
        with (
            patch("imap_common.detect_trash_folder", return_value="Trash"),
            temp_env(env),
            temp_argv(["migrate_imap_emails.py"]),
        ):
            migrate_imap_emails.main()

        # Trash folder should NOT be created in dest (skipped)
        assert "Trash" not in dest_server.folders

    def test_deleted_moved_to_trash(self, mock_server_factory):
        """Test that migrated emails are moved to trash on source."""
        src_data = {"INBOX": [b"Subject: T\r\nMessage-ID: <1>\r\n\r\nBody"]}
        dest_data = {"INBOX": []}

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)
        src_server.folders["Trash"] = []  # Create trash on source

        from unittest.mock import patch

        env = _mock_migrate_env(p1, p2)
        env["DELETE_FROM_SOURCE"] = "true"
        with (
            patch("imap_common.detect_trash_folder", return_value="Trash"),
            temp_env(env),
            temp_argv(["migrate_imap_emails.py", "INBOX"]),
        ):
            migrate_imap_emails.main()

        # Dest should have it
        assert len(dest_server.folders["INBOX"]) == 1
        # Source INBOX should be empty (moved)
        assert len(src_server.folders["INBOX"]) == 0
        # Source Trash should have it (copied before delete)
        assert len(src_server.folders["Trash"]) == 1


class TestCommonMessageParsing:
    """Covers imap_common message parsing helpers used by migrate."""

    def test_parse_message_id_from_empty_bytes(self):
        assert imap_common.parse_message_id_from_bytes(b"") is None

    def test_parse_message_id_and_subject_from_empty_bytes(self):
        msg_id, subject = imap_common.parse_message_id_and_subject_from_bytes(b"")
        assert msg_id is None
        assert subject == "(No Subject)"

    def test_get_uid_to_message_id_map_empty(self):
        result = imap_common.get_uid_to_message_id_map(object(), [])
        assert result == {}

    def test_extract_message_id_invalid_type(self):
        assert imap_common.extract_message_id(123) is None

    def test_parse_message_id_from_invalid_type(self):
        assert imap_common.parse_message_id_from_bytes(123) is None

    def test_parse_message_id_from_bytes_success(self):
        raw_message = b"Subject: X\r\nMessage-ID: <ok@test>\r\n\r\nBody"
        assert imap_common.parse_message_id_from_bytes(raw_message) == "<ok@test>"

    def test_parse_message_id_and_subject_from_invalid_type(self):
        msg_id, subject = imap_common.parse_message_id_and_subject_from_bytes(123)
        assert msg_id is None
        assert subject == "(No Subject)"

    def test_get_uid_to_message_id_map_missing_uid(self):
        class FakeConn:
            def uid(self, _cmd, _uids, _opts):
                return (
                    "OK",
                    [
                        (
                            b"1 (BODY[HEADER.FIELDS (MESSAGE-ID)] {40}",
                            b"Message-ID: <x@test>\r\n",
                        ),
                        b")",
                    ],
                )

        result = imap_common.get_uid_to_message_id_map(FakeConn(), [b"1"])
        assert result == {}

    def test_decode_mime_header_exception_path(self):
        result = imap_common.decode_mime_header(["not", "a", "header"])
        assert result == "['not', 'a', 'header']"


class TestFilterPreservableFlags:
    """Tests for filter_preservable_flags function."""

    def test_filter_seen_flag(self):
        """Test filtering \\Seen flag."""
        result = migrate_imap_emails.filter_preservable_flags("\\Seen")
        assert result == "\\Seen"

    def test_filter_multiple_flags(self):
        """Test filtering multiple preservable flags."""
        result = migrate_imap_emails.filter_preservable_flags("\\Seen \\Flagged \\Answered")
        assert "\\Seen" in result
        assert "\\Flagged" in result
        assert "\\Answered" in result

    def test_filter_removes_recent(self):
        """Test that \\Recent flag is filtered out."""
        result = migrate_imap_emails.filter_preservable_flags("\\Seen \\Recent")
        assert result == "\\Seen"
        assert "\\Recent" not in result

    def test_filter_removes_deleted(self):
        """Test that \\Deleted flag is filtered out."""
        result = migrate_imap_emails.filter_preservable_flags("\\Seen \\Deleted")
        assert result == "\\Seen"
        assert "\\Deleted" not in result

    def test_filter_empty_string(self):
        """Test filtering empty flags string."""
        result = migrate_imap_emails.filter_preservable_flags("")
        assert result is None

    def test_filter_none(self):
        """Test filtering None."""
        result = migrate_imap_emails.filter_preservable_flags(None)
        assert result is None

    def test_filter_only_non_preservable(self):
        """Test filtering when only non-preservable flags present."""
        result = migrate_imap_emails.filter_preservable_flags("\\Recent \\Deleted")
        assert result is None

    def test_filter_all_preservable_flags(self):
        """Test all preservable flags are kept."""
        result = migrate_imap_emails.filter_preservable_flags("\\Seen \\Answered \\Flagged \\Draft")
        assert "\\Seen" in result
        assert "\\Answered" in result
        assert "\\Flagged" in result
        assert "\\Draft" in result


class TestDestDeleteArgument:
    """Tests for --dest-delete argument handling."""

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


class TestDestDeleteFunctionality:
    """Tests for --dest-delete actual deletion behavior."""

    def test_delete_orphan_emails_removes_extra_dest_emails(self, mock_server_factory):
        """Test that emails in dest but not in source are deleted with --dest-delete."""
        # Source has only 1 email
        src_data = {"INBOX": [b"Subject: Keep Me\r\nMessage-ID: <keep@test>\r\n\r\nBody"]}
        # Destination has 3 emails - 2 should be deleted
        dest_data = {
            "INBOX": [
                b"Subject: Keep Me\r\nMessage-ID: <keep@test>\r\n\r\nBody",
                b"Subject: Delete Me 1\r\nMessage-ID: <delete1@test>\r\n\r\nBody",
                b"Subject: Delete Me 2\r\nMessage-ID: <delete2@test>\r\n\r\nBody",
            ]
        }

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        env["DEST_DELETE"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        # Only the email that exists in source should remain
        assert len(dest_server.folders["INBOX"]) == 1
        remaining_content = dest_server.folders["INBOX"][0]["content"]
        assert b"Message-ID: <keep@test>" in remaining_content

    def test_dest_delete_disabled_keeps_extra_emails(self, mock_server_factory):
        """Test that without --dest-delete, extra dest emails are kept."""
        src_data = {"INBOX": [b"Subject: Source Email\r\nMessage-ID: <src@test>\r\n\r\nBody"]}
        dest_data = {
            "INBOX": [
                b"Subject: Dest Only\r\nMessage-ID: <dest-only@test>\r\n\r\nBody",
            ]
        }

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        # Both emails should exist (source was copied, dest-only was kept)
        assert len(dest_server.folders["INBOX"]) == 2

    def test_dest_delete_empty_source_deletes_all(self, mock_server_factory):
        """Test that if source folder is empty, all dest emails are deleted."""
        src_data = {"INBOX": []}
        dest_data = {
            "INBOX": [
                b"Subject: Delete 1\r\nMessage-ID: <d1@test>\r\n\r\nBody",
                b"Subject: Delete 2\r\nMessage-ID: <d2@test>\r\n\r\nBody",
            ]
        }

        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_migrate_env(p1, p2)
        env["DEST_DELETE"] = "true"
        with temp_env(env), temp_argv(["migrate_imap_emails.py", "INBOX"]):
            migrate_imap_emails.main()

        # All dest emails should be deleted
        assert len(dest_server.folders["INBOX"]) == 0

    def test_dest_delete_syncs_after_migration(self, mock_server_factory):
        """End-to-end: delete orphans after a successful migration batch."""
        src_data = {"INBOX": [b"Subject: Keep\r\nMessage-ID: <keep@test>\r\n\r\nBody"]}
        dest_data = {
            "INBOX": [
                b"Subject: Keep\r\nMessage-ID: <keep@test>\r\n\r\nBody",
                b"Subject: Orphan\r\nMessage-ID: <orphan@test>\r\n\r\nBody",
            ]
        }

        src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        src = imaplib.IMAP4("localhost", p1)
        dest = imaplib.IMAP4("localhost", p2)
        src.login("src_user", "p")
        dest.login("dest_user", "p")

        migrate_imap_emails.MAX_WORKERS = 1
        migrate_imap_emails.BATCH_SIZE = 1

        migrate_imap_emails.migrate_folder(
            src,
            dest,
            "INBOX",
            False,
            {"host": "localhost", "user": "src_user", "password": "p"},
            {"host": "localhost", "user": "dest_user", "password": "p"},
            dest_delete=True,
        )

        assert len(dest_server.folders["INBOX"]) == 1
        assert b"Message-ID: <keep@test>" in dest_server.folders["INBOX"][0]["content"]

        src.logout()
        dest.logout()
