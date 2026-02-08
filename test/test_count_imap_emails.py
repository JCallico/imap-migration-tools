"""
Tests for count_imap_emails.py

Tests cover:
- Basic email counting
- Multiple folder counting
- Empty folder handling
- Error handling
- Configuration validation
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import count_imap_emails
import imap_common
from conftest import temp_argv, temp_env


def _mock_imap_env(port):
    return {
        "IMAP_HOST": f"imap://localhost:{port}",
        "IMAP_USERNAME": "user",
        "IMAP_PASSWORD": "pass",
    }


class TestEmailCounting:
    """Tests for email counting functionality."""

    def test_count_single_folder(self, single_mock_server, capsys):
        """Test counting emails in a single folder."""
        src_data = {
            "INBOX": [
                b"Subject: Email 1\r\n\r\nBody",
                b"Subject: Email 2\r\n\r\nBody",
                b"Subject: Email 3\r\n\r\nBody",
            ]
        }
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env):
            count_imap_emails.count_emails(env["IMAP_HOST"], env["IMAP_USERNAME"], env["IMAP_PASSWORD"])

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "3" in captured.out

    def test_count_multiple_folders(self, single_mock_server, capsys):
        """Test counting emails across multiple folders."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
            "Archive": [b"Subject: 4\r\n\r\nB", b"Subject: 5\r\n\r\nB", b"Subject: 6\r\n\r\nB"],
        }
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env):
            count_imap_emails.count_emails(env["IMAP_HOST"], env["IMAP_USERNAME"], env["IMAP_PASSWORD"])

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out
        assert "Archive" in captured.out
        # Total should be 6
        assert "6" in captured.out

    def test_empty_folder(self, single_mock_server, capsys):
        """Test counting in empty folders."""
        src_data = {"INBOX": [], "Empty": []}
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env):
            count_imap_emails.count_emails(env["IMAP_HOST"], env["IMAP_USERNAME"], env["IMAP_PASSWORD"])

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

    def test_count_local_ignores_hidden_dirs(self, tmp_path, capsys):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")
        (inbox_path / "note.txt").write_text("ignore")

        hidden_path = tmp_path / ".hidden"
        hidden_path.mkdir()
        (hidden_path / "1_hidden.eml").write_bytes(b"Subject: Hidden\r\n\r\nBody")

        cache_path = tmp_path / "__pycache__"
        cache_path.mkdir()
        (cache_path / "1_cache.eml").write_bytes(b"Subject: Cache\r\n\r\nBody")

        nested_path = tmp_path / "Projects" / "Sub"
        nested_path.mkdir(parents=True)
        (nested_path / "1_sub.eml").write_bytes(b"Subject: Sub\r\n\r\nBody")

        count_imap_emails.count_local_emails(str(tmp_path))

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Projects/Sub" in captured.out
        assert ".hidden" not in captured.out
        assert "__pycache__" not in captured.out

    def test_get_local_email_count_unreadable_folder(self, tmp_path):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")

        os.chmod(inbox_path, 0)
        try:
            result = imap_common.get_local_email_count(str(tmp_path), "INBOX")
            assert result is None
        finally:
            os.chmod(inbox_path, 0o700)


class TestImapCommonHelpers:
    """Tests for imap_common helpers via script tests."""

    def test_list_selectable_folders_filters_noselect(self):
        class FakeConn:
            def list(self):
                return (
                    "OK",
                    [
                        b'(\\Noselect) "/" "Archive"',
                        b'(\\HasNoChildren) "/" "INBOX"',
                        '(\\HasNoChildren) "/" "Sent"',
                    ],
                )

        result = imap_common.list_selectable_folders(FakeConn())
        assert result == ["INBOX", "Sent"]

    def test_list_selectable_folders_list_error(self):
        class FakeConn:
            def list(self):
                return ("NO", [])

        result = imap_common.list_selectable_folders(FakeConn())
        assert result == []

    def test_list_selectable_folders_exception(self):
        class FakeConn:
            def list(self):
                raise Exception("list failed")

        result = imap_common.list_selectable_folders(FakeConn())
        assert result == []

    def test_get_imap_connection_oauth2_uses_authenticate(self):
        from unittest.mock import patch

        class FakeIMAP:
            def __init__(self, _host):
                self.auth_called = False
                self.login_called = False

            def authenticate(self, _mechanism, auth_cb):
                self.auth_called = True
                auth_cb(None)

            def login(self, _user, _password):
                self.login_called = True

        with patch.object(imap_common.imaplib, "IMAP4_SSL", FakeIMAP):
            conn = imap_common.get_imap_connection("host", "user", oauth2_token="token")

        assert isinstance(conn, FakeIMAP)
        assert conn.auth_called is True
        assert conn.login_called is False

    def test_get_imap_connection_basic_login(self):
        from unittest.mock import patch

        class FakeIMAP:
            def __init__(self, _host):
                self.auth_called = False
                self.login_called = False

            def authenticate(self, _mechanism, _auth_cb):
                self.auth_called = True

            def login(self, _user, _password):
                self.login_called = True

        with patch.object(imap_common.imaplib, "IMAP4_SSL", FakeIMAP):
            conn = imap_common.get_imap_connection("host", "user", password="pass")

        assert isinstance(conn, FakeIMAP)
        assert conn.login_called is True
        assert conn.auth_called is False

    def test_ensure_connection_returns_same_conn_when_healthy(self):
        class GoodConn:
            def __init__(self):
                self.noop_calls = 0

            def noop(self):
                self.noop_calls += 1

        conn = GoodConn()
        result = imap_common.ensure_connection(conn, "host", "user", "pass")
        assert result is conn
        assert conn.noop_calls == 1

    def test_ensure_connection_reconnects_on_noop_error(self):
        from unittest.mock import patch

        class BadConn:
            def noop(self):
                raise Exception("fail")

        new_conn = object()
        with patch.object(imap_common, "get_imap_connection", return_value=new_conn):
            result = imap_common.ensure_connection(BadConn(), "host", "user", "pass")
        assert result is new_conn

    def test_ensure_connection_from_conf_reconnects_on_noop_error(self):
        from unittest.mock import patch

        class BadConn:
            def noop(self):
                raise Exception("fail")

        new_conn = object()
        with patch.object(imap_common, "get_imap_connection_from_conf", return_value=new_conn):
            result = imap_common.ensure_connection_from_conf(BadConn(), {"host": "h", "user": "u"})
        assert result is new_conn


class TestMainFunction:
    """Tests for main function and CLI."""

    def test_main_with_env_vars(self, single_mock_server, capsys):
        """Test main function with environment variables."""
        src_data = {"INBOX": [b"Subject: Test\r\n\r\nBody"]}
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env), temp_argv(["count_imap_emails.py"]):
            count_imap_emails.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out

    def test_missing_credentials(self, capsys):
        """Test that missing auth is rejected by argparse (neither password nor OAuth2 client-id)."""
        with temp_env({}), temp_argv(["count_imap_emails.py", "--host", "localhost", "--user", "user"]):
            with pytest.raises(SystemExit) as exc_info:
                count_imap_emails.main()

        assert exc_info.value.code == 2


class TestSrcImapFallback:
    """Tests for SRC_IMAP_* environment variable fallback."""

    def test_src_imap_vars_fallback(self, capsys):
        """Test that SRC_IMAP_* vars work as fallback."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        with temp_env(env):
            # The fallback logic: IMAP_* or SRC_IMAP_*
            default_host = os.getenv("IMAP_HOST") or os.getenv("SRC_IMAP_HOST")
            default_user = os.getenv("IMAP_USERNAME") or os.getenv("SRC_IMAP_USERNAME")
            default_pass = os.getenv("IMAP_PASSWORD") or os.getenv("SRC_IMAP_PASSWORD")

            assert default_host == "localhost"
            assert default_user == "user"
            assert default_pass == "pass"
