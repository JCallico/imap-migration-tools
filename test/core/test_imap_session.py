"""
Tests for imap_session.py

Tests cover:
- ensure_connection() behavior with and without OAuth2
- ensure_folder_session() connection change detection
- Folder selection and re-selection logic
- Error handling for connection and folder failures
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from core import imap_session


class TestBuildImapConf:
    """Tests for build_imap_conf function."""

    def test_password_auth_returns_correct_dict(self):
        """Test builds correct config for password authentication."""
        conf = imap_session.build_imap_conf("imap.example.com", "user@example.com", "pass123")

        assert conf["host"] == "imap.example.com"
        assert conf["user"] == "user@example.com"
        assert conf["password"] == "pass123"
        assert conf["oauth2_token"] is None
        assert conf["oauth2"] is None

    def test_oauth2_auth_acquires_token(self):
        """Test acquires token and builds oauth2 config when client_id is provided."""
        with patch.object(
            imap_session.imap_oauth2, "acquire_token", return_value=("my_token", "microsoft")
        ) as mock_acquire:
            conf = imap_session.build_imap_conf(
                "outlook.office365.com",
                "user@example.com",
                "pass",
                client_id="cid",
                client_secret="csecret",
                label="source",
            )

        mock_acquire.assert_called_once_with("outlook.office365.com", "cid", "user@example.com", "csecret", "source")
        assert conf["host"] == "outlook.office365.com"
        assert conf["user"] == "user@example.com"
        assert conf["password"] == "pass"
        assert conf["oauth2_token"] == "my_token"
        assert conf["oauth2"] == {
            "provider": "microsoft",
            "client_id": "cid",
            "email": "user@example.com",
            "client_secret": "csecret",
        }

    def test_no_client_id_skips_oauth2(self):
        """Test that oauth2 is None when client_id is not provided."""
        with patch.object(imap_session.imap_oauth2, "acquire_token") as mock_acquire:
            conf = imap_session.build_imap_conf("imap.example.com", "user", "pass")

        mock_acquire.assert_not_called()
        assert conf["oauth2"] is None
        assert conf["oauth2_token"] is None

    def test_empty_client_id_skips_oauth2(self):
        """Test that empty string client_id is treated as no OAuth2."""
        with patch.object(imap_session.imap_oauth2, "acquire_token") as mock_acquire:
            conf = imap_session.build_imap_conf("imap.example.com", "user", "pass", client_id="")

        mock_acquire.assert_not_called()
        assert conf["oauth2"] is None

    def test_none_client_secret_passed_through(self):
        """Test that client_secret=None is correctly passed to acquire_token and stored."""
        with patch.object(imap_session.imap_oauth2, "acquire_token", return_value=("tok", "microsoft")):
            conf = imap_session.build_imap_conf("outlook.office365.com", "user@example.com", "pass", client_id="cid")

        assert conf["oauth2"]["client_secret"] is None

    def test_label_forwarded_to_acquire_token(self):
        """Test that label is passed through to acquire_token."""
        with patch.object(imap_session.imap_oauth2, "acquire_token", return_value=("tok", "google")) as mock_acquire:
            imap_session.build_imap_conf(
                "imap.gmail.com", "user@gmail.com", "pass", client_id="cid", client_secret="sec", label="destination"
            )

        mock_acquire.assert_called_once_with("imap.gmail.com", "cid", "user@gmail.com", "sec", "destination")


class TestEnsureConnection:
    """Tests for ensure_connection function."""

    def test_with_oauth2_calls_refresh(self):
        """Test that OAuth2 token refresh is called when oauth2 config is present."""
        conf = {
            "host": "imap.example.com",
            "user": "user@example.com",
            "password": "pass",
            "oauth2_token": "old_token",
            "oauth2": {
                "provider": "microsoft",
                "client_id": "client-id",
                "email": "user@example.com",
            },
        }
        mock_conn = MagicMock()

        with patch.object(imap_session.imap_oauth2, "refresh_oauth2_token") as mock_refresh:
            with patch.object(
                imap_session.imap_common, "ensure_connection_from_conf", return_value=mock_conn
            ) as mock_ensure:
                result = imap_session.ensure_connection(mock_conn, conf)

        mock_refresh.assert_called_once_with(conf, "old_token")
        mock_ensure.assert_called_once_with(mock_conn, conf)
        assert result is mock_conn

    def test_without_oauth2_skips_refresh(self):
        """Test that token refresh is skipped when oauth2 config is not present."""
        conf = {
            "host": "imap.example.com",
            "user": "user@example.com",
            "password": "pass",
            "oauth2": None,
        }
        mock_conn = MagicMock()

        with patch.object(imap_session.imap_oauth2, "refresh_oauth2_token") as mock_refresh:
            with patch.object(imap_session.imap_common, "ensure_connection_from_conf", return_value=mock_conn):
                imap_session.ensure_connection(mock_conn, conf)

        mock_refresh.assert_not_called()

    def test_without_oauth2_key_skips_refresh(self):
        """Test that token refresh is skipped when oauth2 key is missing entirely."""
        conf = {
            "host": "imap.example.com",
            "user": "user@example.com",
            "password": "pass",
        }
        mock_conn = MagicMock()

        with patch.object(imap_session.imap_oauth2, "refresh_oauth2_token") as mock_refresh:
            with patch.object(imap_session.imap_common, "ensure_connection_from_conf", return_value=mock_conn):
                imap_session.ensure_connection(mock_conn, conf)

        mock_refresh.assert_not_called()

    def test_returns_connection_from_ensure_connection_from_conf(self):
        """Test returns the connection from ensure_connection_from_conf."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        old_conn = MagicMock()
        new_conn = MagicMock()

        with patch.object(imap_session.imap_common, "ensure_connection_from_conf", return_value=new_conn):
            result = imap_session.ensure_connection(old_conn, conf)

        assert result is new_conn

    def test_returns_none_when_connection_fails(self):
        """Test returns None when ensure_connection_from_conf fails."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}

        with patch.object(imap_session.imap_common, "ensure_connection_from_conf", return_value=None):
            result = imap_session.ensure_connection(MagicMock(), conf)

        assert result is None

    def test_with_none_connection(self):
        """Test works correctly when passed None as connection."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        new_conn = MagicMock()

        with patch.object(
            imap_session.imap_common, "ensure_connection_from_conf", return_value=new_conn
        ) as mock_ensure:
            result = imap_session.ensure_connection(None, conf)

        mock_ensure.assert_called_once_with(None, conf)
        assert result is new_conn


class TestEnsureFolderSession:
    """Tests for ensure_folder_session function."""

    def test_same_connection_no_folder_select(self):
        """Test that folder is not re-selected when connection stays the same."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        mock_conn = MagicMock()

        with patch.object(imap_session, "ensure_connection", return_value=mock_conn):
            result_conn, success = imap_session.ensure_folder_session(mock_conn, conf, "INBOX", readonly=True)

        assert result_conn is mock_conn
        assert success is True
        mock_conn.select.assert_not_called()

    def test_new_connection_selects_folder(self):
        """Test that folder is selected when connection changes."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        old_conn = MagicMock()
        new_conn = MagicMock()

        with patch.object(imap_session, "ensure_connection", return_value=new_conn):
            result_conn, success = imap_session.ensure_folder_session(old_conn, conf, "INBOX", readonly=True)

        assert result_conn is new_conn
        assert success is True
        new_conn.select.assert_called_once_with('"INBOX"', readonly=True)

    def test_new_connection_selects_folder_readwrite(self):
        """Test that folder is selected with readonly=False when specified."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        old_conn = MagicMock()
        new_conn = MagicMock()

        with patch.object(imap_session, "ensure_connection", return_value=new_conn):
            result_conn, success = imap_session.ensure_folder_session(
                old_conn, conf, "[Gmail]/All Mail", readonly=False
            )

        assert result_conn is new_conn
        assert success is True
        new_conn.select.assert_called_once_with('"[Gmail]/All Mail"', readonly=False)

    def test_none_connection_returns_failure(self):
        """Test returns (None, False) when ensure_connection returns None."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        mock_conn = MagicMock()

        with patch.object(imap_session, "ensure_connection", return_value=None):
            result_conn, success = imap_session.ensure_folder_session(mock_conn, conf, "INBOX", readonly=True)

        assert result_conn is None
        assert success is False

    def test_folder_select_failure_returns_false(self):
        """Test returns (conn, False) when folder selection fails."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        old_conn = MagicMock()
        new_conn = MagicMock()
        new_conn.select.side_effect = Exception("Folder not found")

        with patch.object(imap_session, "ensure_connection", return_value=new_conn):
            result_conn, success = imap_session.ensure_folder_session(old_conn, conf, "NonExistent", readonly=True)

        assert result_conn is new_conn
        assert success is False

    def test_none_old_connection_selects_folder(self):
        """Test that folder is selected when old connection was None."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        new_conn = MagicMock()

        with patch.object(imap_session, "ensure_connection", return_value=new_conn):
            result_conn, success = imap_session.ensure_folder_session(None, conf, "INBOX", readonly=True)

        assert result_conn is new_conn
        assert success is True
        new_conn.select.assert_called_once_with('"INBOX"', readonly=True)

    def test_folder_name_with_spaces(self):
        """Test folder selection with folder names containing spaces."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        old_conn = MagicMock()
        new_conn = MagicMock()

        with patch.object(imap_session, "ensure_connection", return_value=new_conn):
            result_conn, success = imap_session.ensure_folder_session(old_conn, conf, "My Folder", readonly=True)

        assert success is True
        new_conn.select.assert_called_once_with('"My Folder"', readonly=True)

    def test_folder_select_imap_error(self):
        """Test handles IMAP-specific errors during folder selection."""
        conf = {"host": "imap.example.com", "user": "user", "password": "pass"}
        old_conn = MagicMock()
        new_conn = MagicMock()
        new_conn.select.side_effect = Exception("IMAP error: NO SELECT failed")

        with patch.object(imap_session, "ensure_connection", return_value=new_conn):
            result_conn, success = imap_session.ensure_folder_session(old_conn, conf, "INBOX", readonly=True)

        assert result_conn is new_conn
        assert success is False


class TestEnsureFolderSessionWithOAuth2:
    """Integration-style tests for ensure_folder_session with OAuth2."""

    def test_oauth2_refresh_triggers_folder_reselect(self):
        """Test that OAuth2 token refresh (new connection) triggers folder reselection."""
        conf = {
            "host": "outlook.office365.com",
            "user": "user@example.com",
            "password": "oauth2_token_here",
            "oauth2_token": "old_token",
            "oauth2": {
                "provider": "microsoft",
                "client_id": "client-id",
                "email": "user@example.com",
            },
        }
        old_conn = MagicMock()
        new_conn = MagicMock()

        # Simulate token refresh causing a new connection
        with patch.object(imap_session.imap_oauth2, "refresh_oauth2_token"):
            with patch.object(imap_session.imap_common, "ensure_connection_from_conf", return_value=new_conn):
                result_conn, success = imap_session.ensure_folder_session(old_conn, conf, "INBOX", readonly=True)

        assert result_conn is new_conn
        assert success is True
        new_conn.select.assert_called_once_with('"INBOX"', readonly=True)

    def test_healthy_connection_no_reselect(self):
        """Test that healthy connection (same object) doesn't reselect folder."""
        conf = {
            "host": "outlook.office365.com",
            "user": "user@example.com",
            "password": "oauth2_token_here",
            "oauth2_token": "valid_token",
            "oauth2": {
                "provider": "microsoft",
                "client_id": "client-id",
                "email": "user@example.com",
            },
        }
        mock_conn = MagicMock()

        # Simulate healthy connection (same object returned)
        with patch.object(imap_session.imap_oauth2, "refresh_oauth2_token"):
            with patch.object(imap_session.imap_common, "ensure_connection_from_conf", return_value=mock_conn):
                result_conn, success = imap_session.ensure_folder_session(mock_conn, conf, "INBOX", readonly=True)

        assert result_conn is mock_conn
        assert success is True
        mock_conn.select.assert_not_called()
