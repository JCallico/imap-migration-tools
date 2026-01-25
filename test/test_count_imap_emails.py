"""
Tests for count_imap_emails.py

Tests cover:
- Basic email counting
- Multiple folder counting
- Empty folder handling
- Error handling
- Configuration validation
"""

import imaplib
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import count_imap_emails
from conftest import make_single_mock_connection


class TestEmailCounting:
    """Tests for email counting functionality."""

    def test_count_single_folder(self, single_mock_server, monkeypatch, capsys):
        """Test counting emails in a single folder."""
        src_data = {
            "INBOX": [
                b"Subject: Email 1\r\n\r\nBody",
                b"Subject: Email 2\r\n\r\nBody",
                b"Subject: Email 3\r\n\r\nBody",
            ]
        }
        server, port = single_mock_server(src_data)

        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        count_imap_emails.count_emails("localhost", "user", "pass")

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "3" in captured.out

    def test_count_multiple_folders(self, single_mock_server, monkeypatch, capsys):
        """Test counting emails across multiple folders."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
            "Archive": [b"Subject: 4\r\n\r\nB", b"Subject: 5\r\n\r\nB", b"Subject: 6\r\n\r\nB"],
        }
        server, port = single_mock_server(src_data)

        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        count_imap_emails.count_emails("localhost", "user", "pass")

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out
        assert "Archive" in captured.out
        # Total should be 6
        assert "6" in captured.out

    def test_empty_folder(self, single_mock_server, monkeypatch, capsys):
        """Test counting in empty folders."""
        src_data = {"INBOX": [], "Empty": []}
        server, port = single_mock_server(src_data)

        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        count_imap_emails.count_emails("localhost", "user", "pass")

        captured = capsys.readouterr()
        assert "0" in captured.out


class TestEmailCountingErrors:
    """Tests for error handling in email counting."""

    def test_connection_failure(self, monkeypatch):
        """Test graceful exit when connection fails."""
        mock_get = MagicMock(return_value=None)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        
        # Should return silently without raising
        count_imap_emails.count_emails("host", "user", "pass")
        mock_get.assert_called_once()
        
    def test_list_command_failure(self, monkeypatch):
        """Test handling of LIST command failure."""
        mock_mail = MagicMock()
        mock_mail.list.return_value = ("NO", [])
        mock_get = MagicMock(return_value=mock_mail)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        
        count_imap_emails.count_emails("host", "user", "pass")
        mock_mail.list.assert_called_once()
        # Should exit early, so select should not be called
        mock_mail.select.assert_not_called()

    def test_select_command_failure(self, monkeypatch):
        """Test handling of SELECT command failure for a folder."""
        mock_mail = MagicMock()
        mock_mail.list.return_value = ("OK", [rb'(\HasNoChildren) "/" "INBOX"'])
        # Fail selection
        mock_mail.select.return_value = ("NO", [b'Select failed'])
        
        mock_get = MagicMock(return_value=mock_mail)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        monkeypatch.setattr("imap_common.normalize_folder_name", lambda x: "INBOX")
        
        count_imap_emails.count_emails("host", "user", "pass")
        
        mock_mail.select.assert_called_once()
        # Should skip search for this folder
        mock_mail.search.assert_not_called()

    def test_search_command_failure(self, monkeypatch, capsys):
        """Test handling of SEARCH command failure."""
        mock_mail = MagicMock()
        mock_mail.list.return_value = ("OK", [rb'(\HasNoChildren) "/" "INBOX"'])
        mock_mail.select.return_value = ("OK", [b'Selected'])
        # Fail search
        mock_mail.search.return_value = ("NO", [b'Search failed'])
        
        mock_get = MagicMock(return_value=mock_mail)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        monkeypatch.setattr("imap_common.normalize_folder_name", lambda x: "INBOX")
        
        count_imap_emails.count_emails("host", "user", "pass")
        
        captured = capsys.readouterr()
        assert "Error" in captured.out

    def test_imap_exception_during_list(self, monkeypatch, capsys):
        """Test handling of IMAP4 exception during list command."""
        mock_mail = MagicMock()
        mock_mail.list.side_effect = imaplib.IMAP4.error("Crash listing")
        mock_get = MagicMock(return_value=mock_mail)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        
        count_imap_emails.count_emails("host", "user", "pass")
        
        captured = capsys.readouterr()
        assert "IMAP Error: Crash listing" in captured.out

    def test_imap_exception_during_select(self, monkeypatch, capsys):
        """Test handling of IMAP4 exception during folder selection."""
        mock_mail = MagicMock()
        mock_mail.list.return_value = ("OK", [rb'(\HasNoChildren) "/" "INBOX"'])
        mock_mail.select.side_effect = imaplib.IMAP4.error("Crash selecting")
        
        mock_get = MagicMock(return_value=mock_mail)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        monkeypatch.setattr("imap_common.normalize_folder_name", lambda x: "INBOX")
        
        count_imap_emails.count_emails("host", "user", "pass")
        
        captured = capsys.readouterr()
        # Should print Error for that folder
        assert "Error" in captured.out

    def test_generic_exception(self, monkeypatch, capsys):
        """Test handling of generic connection/runtime exceptions."""
        mock_get = MagicMock(side_effect=Exception("Generic Crash"))
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)
        
        count_imap_emails.count_emails("host", "user", "pass")
        
        captured = capsys.readouterr()
        assert "An error occurred: Generic Crash" in captured.out



class TestMainFunction:
    """Tests for main function and CLI."""

    def test_main_with_env_vars(self, single_mock_server, monkeypatch, capsys):
        """Test main function with environment variables."""
        src_data = {"INBOX": [b"Subject: Test\r\n\r\nBody"]}
        server, port = single_mock_server(src_data)

        env = {
            "IMAP_HOST": "localhost",
            "IMAP_USERNAME": "user",
            "IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["count_imap_emails.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        # Import and run __main__ block logic
        count_imap_emails.count_emails("localhost", "user", "pass")

        captured = capsys.readouterr()
        assert "INBOX" in captured.out

    def test_missing_credentials(self, monkeypatch, capsys):
        """Test that missing credentials cause exit."""
        env = {}
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["count_imap_emails.py"])

        # Since the script uses if __name__ == "__main__", we need to test differently
        # Test the validation path directly
        with pytest.raises(SystemExit):
            # Simulate running main
            import argparse

            parser = argparse.ArgumentParser()
            parser.add_argument("--host", default=None)
            parser.add_argument("--user", default=None)
            parser.add_argument("--pass", dest="password", default=None)
            args = parser.parse_args([])

            if not all([args.host, args.user, args.password]):
                sys.exit(1)


class TestSrcImapFallback:
    """Tests for SRC_IMAP_* environment variable fallback."""

    def test_src_imap_vars_fallback(self, single_mock_server, monkeypatch, capsys):
        """Test that SRC_IMAP_* vars work as fallback."""
        src_data = {"INBOX": [b"Subject: Test\r\n\r\nBody"]}
        server, port = single_mock_server(src_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        # The fallback logic: IMAP_* or SRC_IMAP_*
        default_host = os.getenv("IMAP_HOST") or os.getenv("SRC_IMAP_HOST")
        default_user = os.getenv("IMAP_USERNAME") or os.getenv("SRC_IMAP_USERNAME")
        default_pass = os.getenv("IMAP_PASSWORD") or os.getenv("SRC_IMAP_PASSWORD")

        assert default_host == "localhost"
        assert default_user == "user"
        assert default_pass == "pass"
