"""
Tests for imap_common.py

Tests cover:
- Environment variable verification
- IMAP connection handling
- Folder name normalization
- MIME header decoding
- Message details extraction
- Duplicate detection
- Filename sanitization
- Trash folder detection
"""

import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_common
from conftest import temp_env


class TestVerifyEnvVars:
    """Tests for verify_env_vars function."""

    def test_all_vars_present(self):
        """Test returns True when all variables are set."""
        with temp_env({"VAR1": "value1", "VAR2": "value2"}):
            result = imap_common.verify_env_vars(["VAR1", "VAR2"])
            assert result is True

    def test_missing_vars(self, capsys):
        """Test returns False and prints error when variables are missing."""
        with temp_env({}):
            result = imap_common.verify_env_vars(["MISSING_VAR"])
            assert result is False

            captured = capsys.readouterr()
            assert "MISSING_VAR" in captured.err

    def test_partial_vars_present(self, capsys):
        """Test with some variables present and some missing."""
        with temp_env({"PRESENT": "value"}):
            result = imap_common.verify_env_vars(["PRESENT", "MISSING"])
            assert result is False


class TestGetImapConnection:
    """Tests for get_imap_connection function."""

    def test_invalid_credentials_empty(self, capsys):
        """Test returns None when credentials are empty."""
        result = imap_common.get_imap_connection("", "user", "pass")
        assert result is None

        result = imap_common.get_imap_connection("host", "", "pass")
        assert result is None

        result = imap_common.get_imap_connection("host", "user", "")
        assert result is None

    def test_connection_error(self, capsys):
        """Test returns None on connection error."""
        # Try to connect to an invalid host
        result = imap_common.get_imap_connection("invalid.nonexistent.host", "u", "p")
        assert result is None

        captured = capsys.readouterr()
        assert "Connection error" in captured.out or "Error" in captured.out


class TestNormalizeFolderName:
    """Tests for normalize_folder_name function."""

    def test_standard_format(self):
        """Test parsing standard IMAP list response."""
        folder_info = b'(\\HasNoChildren) "/" "INBOX"'
        result = imap_common.normalize_folder_name(folder_info)
        assert result == "INBOX"

    def test_unquoted_name(self):
        """Test parsing unquoted folder name."""
        folder_info = b'(\\HasNoChildren) "/" Drafts'
        result = imap_common.normalize_folder_name(folder_info)
        assert result == "Drafts"

    def test_with_special_flags(self):
        """Test parsing folder with special-use flags."""
        folder_info = b'(\\HasNoChildren \\Trash) "/" "Trash"'
        result = imap_common.normalize_folder_name(folder_info)
        assert result == "Trash"

    def test_gmail_folder(self):
        """Test parsing Gmail-style folder."""
        folder_info = b'(\\HasNoChildren) "/" "[Gmail]/All Mail"'
        result = imap_common.normalize_folder_name(folder_info)
        assert result == "[Gmail]/All Mail"

    def test_string_input(self):
        """Test with string input instead of bytes."""
        folder_info = '(\\HasNoChildren) "/" "Archive"'
        result = imap_common.normalize_folder_name(folder_info)
        assert result == "Archive"

    def test_fallback_parsing(self):
        """Test fallback when regex doesn't match."""
        folder_info = "simple_folder"
        result = imap_common.normalize_folder_name(folder_info)
        assert result == "simple_folder"


class TestDecodeMimeHeader:
    """Tests for decode_mime_header function."""

    def test_plain_ascii(self):
        """Test decoding plain ASCII header."""
        result = imap_common.decode_mime_header("Hello World")
        assert result == "Hello World"

    def test_none_input(self):
        """Test with None input."""
        result = imap_common.decode_mime_header(None)
        assert result == "(No Subject)"

    def test_empty_string(self):
        """Test with empty string."""
        result = imap_common.decode_mime_header("")
        assert result == "(No Subject)"

    def test_utf8_encoded(self):
        """Test decoding UTF-8 MIME encoded header."""
        # =?UTF-8?B?SGVsbG8gV29ybGQ=?= is "Hello World" in base64
        result = imap_common.decode_mime_header("=?UTF-8?B?SGVsbG8gV29ybGQ=?=")
        assert "Hello" in result

    def test_quoted_printable(self):
        """Test decoding quoted-printable header."""
        # =?UTF-8?Q?Hello_World?= is "Hello World" in quoted-printable
        result = imap_common.decode_mime_header("=?UTF-8?Q?Hello_World?=")
        assert "Hello" in result


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_valid_filename(self):
        """Test that valid filename passes through."""
        result = imap_common.sanitize_filename("valid_filename")
        assert result == "valid_filename"

    def test_invalid_characters(self):
        """Test that invalid characters are replaced."""
        result = imap_common.sanitize_filename('file<>:"/\\|?*name')
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result
        assert '"' not in result
        assert "/" not in result
        assert "\\" not in result
        assert "|" not in result
        assert "?" not in result
        assert "*" not in result

    def test_empty_input(self):
        """Test that empty input returns 'untitled'."""
        result = imap_common.sanitize_filename("")
        assert result == "untitled"

    def test_none_input(self):
        """Test that None input returns 'untitled'."""
        result = imap_common.sanitize_filename(None)
        assert result == "untitled"

    def test_long_filename_truncation(self):
        """Test that long filenames are truncated."""
        long_name = "a" * 300
        result = imap_common.sanitize_filename(long_name)
        assert len(result) <= 250

    def test_strip_leading_trailing(self):
        """Test that leading/trailing whitespace and dots are stripped."""
        result = imap_common.sanitize_filename("  ..filename..  ")
        assert not result.startswith(" ")
        assert not result.startswith(".")
        assert not result.endswith(" ")
        assert not result.endswith(".")


class TestDetectTrashFolder:
    """Tests for detect_trash_folder function."""

    def test_detect_by_special_use_flag(self):
        """Test detection via \\Trash flag."""
        mock_conn = Mock()
        mock_conn.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\Trash) "/" "Deleted Items"',
            ],
        )

        result = imap_common.detect_trash_folder(mock_conn)
        assert result == "Deleted Items"

    def test_detect_gmail_trash(self):
        """Test detection of Gmail Trash folder."""
        mock_conn = Mock()
        mock_conn.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\Trash) "/" "[Gmail]/Trash"',
            ],
        )

        result = imap_common.detect_trash_folder(mock_conn)
        assert result == "[Gmail]/Trash"

    def test_detect_by_name_fallback(self):
        """Test detection by common name when no flag present."""
        mock_conn = Mock()
        mock_conn.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren) "/" "Trash"',
            ],
        )

        result = imap_common.detect_trash_folder(mock_conn)
        assert result == "Trash"

    def test_no_trash_folder(self):
        """Test returns None when no trash folder found."""
        mock_conn = Mock()
        mock_conn.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren) "/" "Sent"',
            ],
        )

        result = imap_common.detect_trash_folder(mock_conn)
        assert result is None

    def test_list_error(self):
        """Test returns None on list error."""
        mock_conn = Mock()
        mock_conn.list.return_value = ("NO", [])

        result = imap_common.detect_trash_folder(mock_conn)
        assert result is None

    def test_exception_handling(self):
        """Test returns None on exception."""
        mock_conn = Mock()
        mock_conn.list.side_effect = Exception("Connection error")

        result = imap_common.detect_trash_folder(mock_conn)
        assert result is None


class TestMessageExistsInFolder:
    """Tests for message_exists_in_folder function."""

    def test_no_message_id(self):
        """Test returns False when message_id is None."""
        mock_conn = Mock()
        result = imap_common.message_exists_in_folder(mock_conn, None)
        assert result is False

    def test_search_fails(self):
        """Test returns False when search fails."""
        mock_conn = Mock()
        mock_conn.search.return_value = ("NO", [])

        result = imap_common.message_exists_in_folder(mock_conn, "<msg-id>")
        assert result is False

    def test_no_matches(self):
        """Test returns False when no matches found."""
        mock_conn = Mock()
        mock_conn.search.return_value = ("OK", [b""])

        result = imap_common.message_exists_in_folder(mock_conn, "<msg-id>")
        assert result is False

    def test_match_found(self):
        """Test returns True when message with same ID found."""
        mock_conn = Mock()
        mock_conn.search.return_value = ("OK", [b"1"])

        result = imap_common.message_exists_in_folder(mock_conn, "<msg-id>")
        assert result is True

    def test_search_exception(self):
        """Test returns False when search raises an exception."""
        mock_conn = Mock()
        mock_conn.search.side_effect = Exception("Connection error")

        result = imap_common.message_exists_in_folder(mock_conn, "<msg-id>")
        assert result is False


class TestExtractMessageId:
    """Tests for extract_message_id function."""

    def test_standard_header(self):
        """Test extracting standard Message-ID."""
        header = b"Message-ID: <test@example.com>\r\nSubject: Test"
        result = imap_common.extract_message_id(header)
        assert result == "<test@example.com>"

    def test_lowercase_header(self):
        """Test extracting Message-ID with lowercase header name."""
        header = b"message-id: <lower@example.com>\r\nSubject: Test"
        result = imap_common.extract_message_id(header)
        assert result == "<lower@example.com>"

    def test_folded_header(self):
        """Test extracting folded Message-ID."""
        # BytesParser unfolds values (replacing newline+indent with space)
        header = b"Message-ID: <part1\r\n part2@example.com>\r\nSubject: Test"
        result = imap_common.extract_message_id(header)
        assert result == "<part1 part2@example.com>"

    def test_string_input(self):
        """Test with string input."""
        header = "Message-ID: <str@example.com>\nSubject: Test"
        result = imap_common.extract_message_id(header)
        assert result == "<str@example.com>"

    def test_no_message_id(self):
        """Test header without Message-ID."""
        header = b"Subject: Test\r\nFrom: sender"
        result = imap_common.extract_message_id(header)
        assert result is None

    def test_empty_input(self):
        """Test empty input."""
        assert imap_common.extract_message_id(None) is None
        assert imap_common.extract_message_id(b"") is None


class TestEnsureFolderExists:
    """Tests for ensure_folder_exists function."""

    def test_creates_folder_successfully(self):
        """Test folder is created when it doesn't exist."""
        mock_conn = Mock()
        mock_conn.create.return_value = ("OK", [])

        # Should not raise any exception
        imap_common.ensure_folder_exists(mock_conn, "TestFolder")
        mock_conn.create.assert_called_once_with('"TestFolder"')

    def test_folder_already_exists(self):
        """Test exception is suppressed when folder already exists."""
        mock_conn = Mock()
        mock_conn.create.side_effect = Exception("Folder already exists")

        # Should not raise any exception
        imap_common.ensure_folder_exists(mock_conn, "ExistingFolder")
        mock_conn.create.assert_called_once_with('"ExistingFolder"')

    def test_inbox_folder_skipped(self):
        """Test INBOX folder is not created."""
        mock_conn = Mock()

        imap_common.ensure_folder_exists(mock_conn, "INBOX")
        mock_conn.create.assert_not_called()

        # Also test lowercase
        imap_common.ensure_folder_exists(mock_conn, "inbox")
        mock_conn.create.assert_not_called()

    def test_empty_folder_name(self):
        """Test empty folder name is skipped."""
        mock_conn = Mock()

        imap_common.ensure_folder_exists(mock_conn, "")
        mock_conn.create.assert_not_called()

    def test_none_folder_name(self):
        """Test None folder name is skipped."""
        mock_conn = Mock()

        imap_common.ensure_folder_exists(mock_conn, None)
        mock_conn.create.assert_not_called()

    def test_server_restriction_error_suppressed(self):
        """Test server restriction errors are suppressed."""
        mock_conn = Mock()
        mock_conn.create.side_effect = Exception("Permission denied")

        # Should not raise any exception
        imap_common.ensure_folder_exists(mock_conn, "RestrictedFolder")
        mock_conn.create.assert_called_once()


class TestAppendEmail:
    """Tests for append_email function."""

    def test_successful_append(self):
        """Test successful email append returns True."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            ensure_folder=False,
        )

        assert result is True
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            None,
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )

    def test_append_with_flags_with_parentheses(self):
        """Test flag normalization when flags already have parentheses."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            flags="(\\Seen \\Flagged)",
            ensure_folder=False,
        )

        assert result is True
        # Flags should remain unchanged
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            "(\\Seen \\Flagged)",
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )

    def test_append_with_flags_without_parentheses(self):
        """Test flag normalization when flags lack parentheses."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            flags="\\Seen",
            ensure_folder=False,
        )

        assert result is True
        # Flags should be wrapped in parentheses
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            "(\\Seen)",
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )

    def test_append_with_none_flags(self):
        """Test append with None flags."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            flags=None,
            ensure_folder=False,
        )

        assert result is True
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            None,
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )

    def test_append_with_empty_flags(self):
        """Test append with empty string flags."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            flags="",
            ensure_folder=False,
        )

        assert result is True
        # Empty flags should result in None
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            None,
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )

    def test_append_with_whitespace_only_flags(self):
        """Test append with whitespace-only flags."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            flags="   ",
            ensure_folder=False,
        )

        assert result is True
        # Whitespace-only flags should result in None
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            None,
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )

    def test_append_with_ensure_folder_enabled(self):
        """Test append with ensure_folder enabled."""
        mock_conn = Mock()
        mock_conn.create.return_value = ("OK", [])
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            ensure_folder=True,
        )

        assert result is True
        mock_conn.create.assert_called_once_with('"TestFolder"')
        mock_conn.append.assert_called_once()

    def test_append_with_ensure_folder_disabled(self):
        """Test append with ensure_folder disabled."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            ensure_folder=False,
        )

        assert result is True
        mock_conn.create.assert_not_called()
        mock_conn.append.assert_called_once()

    def test_append_failure_returns_false(self):
        """Test append returns False on failure."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("NO", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            ensure_folder=False,
        )

        assert result is False

    def test_append_exception_propagates(self):
        """Test append propagates exceptions so callers can handle/log."""
        mock_conn = Mock()
        mock_conn.append.side_effect = Exception("Connection error")

        import pytest

        with pytest.raises(Exception, match="Connection error"):
            imap_common.append_email(
                mock_conn,
                "TestFolder",
                b"email content",
                "01-Jan-2024 12:00:00 +0000",
                ensure_folder=False,
            )

    def test_append_with_multiple_flags(self):
        """Test append with multiple flags."""
        mock_conn = Mock()
        mock_conn.append.return_value = ("OK", [])

        result = imap_common.append_email(
            mock_conn,
            "TestFolder",
            b"email content",
            "01-Jan-2024 12:00:00 +0000",
            flags="\\Seen \\Flagged \\Answered",
            ensure_folder=False,
        )

        assert result is True
        # Multiple flags without parentheses should be wrapped
        mock_conn.append.assert_called_once_with(
            '"TestFolder"',
            "(\\Seen \\Flagged \\Answered)",
            "01-Jan-2024 12:00:00 +0000",
            b"email content",
        )


class TestGetMessageIdsInFolder:
    """Tests for get_message_ids_in_folder function."""

    def test_empty_folder(self):
        """Test returns empty dict for folder with no messages."""
        mock_conn = Mock()
        mock_conn.uid.return_value = ("OK", [b""])

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert result == {}

    def test_search_fails(self):
        """Test returns empty dict when search fails."""
        mock_conn = Mock()
        mock_conn.uid.return_value = ("NO", [])

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert result == {}

    def test_search_non_auth_exception_returns_empty(self):
        """Test returns empty dict when search raises non-auth exception."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = Exception("Connection error")

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert result == {}

    def test_search_auth_error_reraises(self):
        """Test re-raises auth errors so callers can handle reconnection."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = Exception("User not authenticated")

        with pytest.raises(Exception, match="not authenticated"):
            imap_common.get_message_ids_in_folder(mock_conn)

    def test_single_message(self):
        """Test fetching single message ID."""
        mock_conn = Mock()
        # First call: search returns one UID
        # Second call: fetch returns the Message-ID header (with UID in response)
        mock_conn.uid.side_effect = [
            ("OK", [b"1"]),
            ("OK", [(b"1 (UID 1 BODY[HEADER.FIELDS (MESSAGE-ID)] {50}", b"Message-ID: <test@example.com>\r\n"), b")"]),
        ]

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert result == {b"1": "<test@example.com>"}
        assert set(result.values()) == {"<test@example.com>"}

    def test_multiple_messages(self):
        """Test fetching multiple message IDs."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = [
            ("OK", [b"1 2 3"]),
            (
                "OK",
                [
                    (b"1 (UID 1 BODY[HEADER.FIELDS (MESSAGE-ID)] {50}", b"Message-ID: <msg1@example.com>\r\n"),
                    b")",
                    (b"2 (UID 2 BODY[HEADER.FIELDS (MESSAGE-ID)] {50}", b"Message-ID: <msg2@example.com>\r\n"),
                    b")",
                    (b"3 (UID 3 BODY[HEADER.FIELDS (MESSAGE-ID)] {50}", b"Message-ID: <msg3@example.com>\r\n"),
                    b")",
                ],
            ),
        ]

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert set(result.values()) == {"<msg1@example.com>", "<msg2@example.com>", "<msg3@example.com>"}

    def test_fetch_fails_for_batch(self):
        """Test continues when fetch fails for a batch."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = [
            ("OK", [b"1"]),
            ("NO", []),  # Fetch fails
        ]

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert result == {}

    def test_fetch_non_auth_exception_continues(self):
        """Test continues when fetch raises non-auth exception for a batch."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = [
            ("OK", [b"1"]),
            Exception("Fetch error"),
        ]

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert result == {}

    def test_fetch_auth_error_reraises(self):
        """Test re-raises auth errors during fetch so callers can handle reconnection."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = [
            ("OK", [b"1"]),
            Exception("AccessTokenExpired"),
        ]

        with pytest.raises(Exception, match="AccessTokenExpired"):
            imap_common.get_message_ids_in_folder(mock_conn)

    def test_skips_empty_message_id(self):
        """Test that empty message IDs are not added to dict."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = [
            ("OK", [b"1 2"]),
            (
                "OK",
                [
                    (b"1 (UID 1 BODY[HEADER.FIELDS (MESSAGE-ID)] {50}", b"Message-ID: <valid@example.com>\r\n"),
                    b")",
                    (b"2 (UID 2 BODY[HEADER.FIELDS (MESSAGE-ID)] {50}", b"Message-ID: \r\n"),  # Empty
                    b")",
                ],
            ),
        ]

        result = imap_common.get_message_ids_in_folder(mock_conn)
        assert set(result.values()) == {"<valid@example.com>"}
