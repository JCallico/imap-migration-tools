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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_common


class TestVerifyEnvVars:
    """Tests for verify_env_vars function."""

    def test_all_vars_present(self, monkeypatch):
        """Test returns True when all variables are set."""
        monkeypatch.setenv("VAR1", "value1")
        monkeypatch.setenv("VAR2", "value2")

        result = imap_common.verify_env_vars(["VAR1", "VAR2"])
        assert result is True

    def test_missing_vars(self, monkeypatch, capsys):
        """Test returns False and prints error when variables are missing."""
        monkeypatch.delenv("MISSING_VAR", raising=False)

        result = imap_common.verify_env_vars(["MISSING_VAR"])
        assert result is False

        captured = capsys.readouterr()
        assert "MISSING_VAR" in captured.err

    def test_partial_vars_present(self, monkeypatch, capsys):
        """Test with some variables present and some missing."""
        monkeypatch.setenv("PRESENT", "value")
        monkeypatch.delenv("MISSING", raising=False)

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


class TestGetMsgDetails:
    """Tests for get_msg_details function."""

    def test_fetch_error(self):
        """Test returns None tuple on fetch error."""
        mock_conn = Mock()
        mock_conn.uid.side_effect = Exception("Fetch error")

        msg_id, size, subject = imap_common.get_msg_details(mock_conn, b"1")
        assert msg_id is None
        assert size is None
        assert subject is None

    def test_not_ok_response(self):
        """Test returns None tuple on non-OK response."""
        mock_conn = Mock()
        mock_conn.uid.return_value = ("NO", None)

        msg_id, size, subject = imap_common.get_msg_details(mock_conn, b"1")
        assert msg_id is None
        assert size is None
        assert subject is None
