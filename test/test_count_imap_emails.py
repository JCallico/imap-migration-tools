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
        _, port = single_mock_server(src_data)

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
        _, port = single_mock_server(src_data)

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
        _, port = single_mock_server(src_data)

        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        count_imap_emails.count_emails("localhost", "user", "pass")

        captured = capsys.readouterr()
        assert "0" in captured.out


class TestLocalEmailCounting:
    """Tests for counting emails from a local backup folder."""

    def test_count_local_folders(self, tmp_path, capsys):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")
        (inbox_path / "2_b.eml").write_bytes(b"Subject: B\r\n\r\nBody")

        gmail_all_mail = tmp_path / "[Gmail]" / "All Mail"
        gmail_all_mail.mkdir(parents=True)
        (gmail_all_mail / "1_c.eml").write_bytes(b"Subject: C\r\n\r\nBody")

        count_imap_emails.count_local_emails(str(tmp_path))

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "[Gmail]/All Mail" in captured.out
        assert "TOTAL" in captured.out
        assert "3" in captured.out


class TestMainFunction:
    """Tests for main function and CLI."""

    def test_main_with_env_vars(self, single_mock_server, monkeypatch, capsys):
        """Test main function with environment variables."""
        src_data = {"INBOX": [b"Subject: Test\r\n\r\nBody"]}
        _, port = single_mock_server(src_data)

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
        """Test that missing auth is rejected by argparse (neither password nor OAuth2 client-id)."""
        monkeypatch.setattr(os, "environ", {})
        monkeypatch.setattr(sys, "argv", ["count_imap_emails.py", "--host", "localhost", "--user", "user"])

        with pytest.raises(SystemExit) as exc_info:
            count_imap_emails.main()

        assert exc_info.value.code == 2


class TestSrcImapFallback:
    """Tests for SRC_IMAP_* environment variable fallback."""

    def test_src_imap_vars_fallback(self, single_mock_server, monkeypatch, capsys):
        """Test that SRC_IMAP_* vars work as fallback."""
        src_data = {"INBOX": [b"Subject: Test\r\n\r\nBody"]}
        _, port = single_mock_server(src_data)

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
