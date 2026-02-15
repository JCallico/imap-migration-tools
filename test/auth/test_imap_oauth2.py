"""
Tests for imap_oauth2.py

Tests cover:
- OAuth2 provider detection
- Provider dispatch
- Thread-safe token refresh
- Token expiration and auth error detection
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from auth import imap_oauth2, oauth2_google, oauth2_microsoft


@pytest.fixture(autouse=True)
def clear_oauth2_caches():
    """Clear module-level OAuth2 caches between tests."""
    imap_oauth2._msal_app_cache.clear()
    imap_oauth2._google_creds_cache.clear()
    imap_oauth2._tenant_cache.clear()
    yield
    imap_oauth2._msal_app_cache.clear()
    imap_oauth2._google_creds_cache.clear()
    imap_oauth2._tenant_cache.clear()


class TestDetectOauth2Provider:
    """Tests for detect_oauth2_provider function."""

    def test_microsoft_outlook(self):
        """Test detects Microsoft from outlook host."""
        assert imap_oauth2.detect_oauth2_provider("outlook.office365.com") == "microsoft"

    def test_microsoft_office365(self):
        """Test detects Microsoft from office365 host."""
        assert imap_oauth2.detect_oauth2_provider("imap.office365.com") == "microsoft"

    def test_microsoft_mixed_case(self):
        """Test detects Microsoft case-insensitively."""
        assert imap_oauth2.detect_oauth2_provider("Outlook.Office365.COM") == "microsoft"

    def test_google_gmail(self):
        """Test detects Google from gmail host."""
        assert imap_oauth2.detect_oauth2_provider("imap.gmail.com") == "google"

    def test_google_googlemail(self):
        """Test detects Google from google host."""
        assert imap_oauth2.detect_oauth2_provider("imap.google.com") == "google"

    def test_unknown_provider(self):
        """Test returns None for unrecognized host."""
        assert imap_oauth2.detect_oauth2_provider("imap.example.com") is None

    def test_unknown_yahoo(self):
        """Test returns None for Yahoo host."""
        assert imap_oauth2.detect_oauth2_provider("imap.mail.yahoo.com") is None


class TestAcquireOauth2TokenForProvider:
    """Tests for acquire_oauth2_token_for_provider dispatch function."""

    def test_dispatch_to_microsoft(self):
        """Test dispatches to Microsoft when provider is 'microsoft'."""
        with patch.object(oauth2_microsoft, "acquire_token", return_value="ms_token") as mock_ms:
            result = imap_oauth2.acquire_oauth2_token_for_provider("microsoft", "cid", "user@test.com")

        assert result == "ms_token"
        mock_ms.assert_called_once_with("cid", "user@test.com")

    def test_dispatch_to_google(self):
        """Test dispatches to Google when provider is 'google'."""
        with patch.object(oauth2_google, "acquire_token", return_value="g_token") as mock_g:
            result = imap_oauth2.acquire_oauth2_token_for_provider("google", "cid", "user@gmail.com", "secret")

        assert result == "g_token"
        mock_g.assert_called_once_with("cid", "secret")

    def test_google_requires_client_secret(self, capsys):
        """Test returns None when Google is selected without client_secret."""
        result = imap_oauth2.acquire_oauth2_token_for_provider("google", "cid", "user@gmail.com")

        assert result is None
        captured = capsys.readouterr()
        assert "--oauth2-client-secret" in captured.out

    def test_unknown_provider(self, capsys):
        """Test returns None for unknown provider."""
        result = imap_oauth2.acquire_oauth2_token_for_provider("yahoo", "cid", "user@yahoo.com")

        assert result is None
        captured = capsys.readouterr()
        assert "Unknown OAuth2 provider" in captured.out


class TestRefreshOauth2Token:
    """Tests for thread-safe refresh_oauth2_token function."""

    def test_refreshes_token_and_updates_conf(self):
        """Test that a new token is acquired and conf["oauth2_token"] is updated."""
        conf = {
            "host": "host",
            "user": "user",
            "password": "pass",
            "oauth2_token": "old_token",
            "oauth2": {
                "provider": "microsoft",
                "client_id": "client-id",
                "email": "user@test.com",
                "client_secret": None,
            },
        }

        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value="new_token") as mock_acquire:
            result = imap_oauth2.refresh_oauth2_token(conf, "old_token")

        assert result == "new_token"
        assert conf["oauth2_token"] == "new_token"
        mock_acquire.assert_called_once_with("microsoft", "client-id", "user@test.com", None)

    def test_skips_refresh_when_token_already_updated(self):
        """Test that refresh is skipped if another thread already updated the token."""
        conf = {
            "host": "host",
            "user": "user",
            "password": "pass",
            "oauth2_token": "already_refreshed_token",
            "oauth2": {
                "provider": "microsoft",
                "client_id": "client-id",
                "email": "user@test.com",
                "client_secret": None,
            },
        }

        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider") as mock_acquire:
            result = imap_oauth2.refresh_oauth2_token(conf, "old_token")

        assert result == "already_refreshed_token"
        assert conf["oauth2_token"] == "already_refreshed_token"
        mock_acquire.assert_not_called()

    def test_returns_none_on_refresh_failure(self):
        """Test returns None and leaves conf unchanged when refresh fails."""
        conf = {
            "host": "host",
            "user": "user",
            "password": "pass",
            "oauth2_token": "old_token",
            "oauth2": {
                "provider": "google",
                "client_id": "client-id",
                "email": "user@gmail.com",
                "client_secret": "secret",
            },
        }

        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value=None):
            result = imap_oauth2.refresh_oauth2_token(conf, "old_token")

        assert result is None
        assert conf["oauth2_token"] == "old_token"

    def test_returns_none_when_no_oauth2_context(self):
        """Test returns None when oauth2 context is not set."""
        conf = {
            "host": "host",
            "user": "user",
            "password": "pass",
            "oauth2_token": "old_token",
            "oauth2": None,
        }

        result = imap_oauth2.refresh_oauth2_token(conf, "old_token")

        assert result is None
        assert conf["oauth2_token"] == "old_token"

    def test_concurrent_threads_only_one_refreshes(self):
        """Test that only one thread performs the refresh when multiple threads compete."""
        import threading
        import time

        conf = {
            "host": "host",
            "user": "user",
            "password": "pass",
            "oauth2_token": "expired_token",
            "oauth2": {
                "provider": "microsoft",
                "client_id": "client-id",
                "email": "user@test.com",
                "client_secret": None,
            },
        }
        call_count = {"value": 0}
        barrier = threading.Barrier(3)  # 3 threads

        def slow_acquire(provider, client_id, email, client_secret):
            call_count["value"] += 1
            time.sleep(0.05)  # Simulate network delay
            return "fresh_token"

        def thread_func():
            barrier.wait()  # Ensure all threads start at the same time
            imap_oauth2.refresh_oauth2_token(conf, "expired_token")

        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", side_effect=slow_acquire):
            threads = [threading.Thread(target=thread_func) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        # Only one thread should have called acquire (the first to get the lock).
        # The other two should see conf["oauth2_token"] changed and skip.
        assert call_count["value"] == 1
        assert conf["oauth2_token"] == "fresh_token"


class TestIsTokenExpiredError:
    """Tests for is_token_expired_error function."""

    def test_detects_access_token_expired(self):
        """Test detects 'accesstokenexpired' error."""
        error = Exception("AUTHENTICATE failed: AccessTokenExpired")
        assert imap_oauth2.is_token_expired_error(error) is True

    def test_detects_session_invalidated(self):
        """Test detects 'session invalidated' error."""
        error = Exception("Session invalidated by server")
        assert imap_oauth2.is_token_expired_error(error) is True

    def test_case_insensitive_access_token_expired(self):
        """Test case-insensitive matching for accesstokenexpired."""
        error = Exception("ACCESSTOKENEXPIRED")
        assert imap_oauth2.is_token_expired_error(error) is True

    def test_case_insensitive_session_invalidated(self):
        """Test case-insensitive matching for session invalidated."""
        error = Exception("SESSION INVALIDATED")
        assert imap_oauth2.is_token_expired_error(error) is True

    def test_false_for_connection_error(self):
        """Test returns False for connection errors."""
        error = Exception("Connection refused")
        assert imap_oauth2.is_token_expired_error(error) is False

    def test_false_for_timeout_error(self):
        """Test returns False for timeout errors."""
        error = Exception("The read operation timed out")
        assert imap_oauth2.is_token_expired_error(error) is False

    def test_false_for_generic_error(self):
        """Test returns False for generic errors."""
        error = Exception("Something went wrong")
        assert imap_oauth2.is_token_expired_error(error) is False

    def test_false_for_not_authenticated(self):
        """Test returns False for 'not authenticated' (handled by is_auth_error)."""
        error = Exception("User not authenticated")
        assert imap_oauth2.is_token_expired_error(error) is False


class TestIsAuthError:
    """Tests for is_auth_error function."""

    def test_detects_access_token_expired(self):
        """Test detects 'accesstokenexpired' error (via is_token_expired_error)."""
        error = Exception("AUTHENTICATE failed: AccessTokenExpired")
        assert imap_oauth2.is_auth_error(error) is True

    def test_detects_session_invalidated(self):
        """Test detects 'session invalidated' error (via is_token_expired_error)."""
        error = Exception("Session invalidated by server")
        assert imap_oauth2.is_auth_error(error) is True

    def test_detects_not_authenticated(self):
        """Test detects 'not authenticated' error."""
        error = Exception("User not authenticated")
        assert imap_oauth2.is_auth_error(error) is True

    def test_detects_authentication_failed(self):
        """Test detects 'authentication failed' error."""
        error = Exception("Authentication failed for user@example.com")
        assert imap_oauth2.is_auth_error(error) is True

    def test_case_insensitive_not_authenticated(self):
        """Test case-insensitive matching for not authenticated."""
        error = Exception("NOT AUTHENTICATED")
        assert imap_oauth2.is_auth_error(error) is True

    def test_case_insensitive_authentication_failed(self):
        """Test case-insensitive matching for authentication failed."""
        error = Exception("AUTHENTICATION FAILED")
        assert imap_oauth2.is_auth_error(error) is True

    def test_false_for_connection_error(self):
        """Test returns False for connection errors."""
        error = Exception("Connection refused")
        assert imap_oauth2.is_auth_error(error) is False

    def test_false_for_timeout_error(self):
        """Test returns False for timeout errors."""
        error = Exception("The read operation timed out")
        assert imap_oauth2.is_auth_error(error) is False

    def test_false_for_generic_error(self):
        """Test returns False for generic errors."""
        error = Exception("Something went wrong")
        assert imap_oauth2.is_auth_error(error) is False

    def test_false_for_folder_not_found(self):
        """Test returns False for folder errors."""
        error = Exception("Folder not found: INBOX")
        assert imap_oauth2.is_auth_error(error) is False


class TestAcquireToken:
    """Tests for the acquire_token convenience function."""

    def test_returns_token_and_provider_for_microsoft(self, capsys):
        """Test successful token acquisition for Microsoft host."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value="ms_token"):
            token, provider = imap_oauth2.acquire_token("outlook.office365.com", "cid", "user@example.com")

        assert token == "ms_token"
        assert provider == "microsoft"
        out = capsys.readouterr().out
        assert "Acquiring OAuth2 token (microsoft)" in out
        assert "OAuth2 token acquired successfully" in out

    def test_returns_token_and_provider_for_google(self, capsys):
        """Test successful token acquisition for Google host."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value="g_token"):
            token, provider = imap_oauth2.acquire_token(
                "imap.gmail.com", "cid", "user@gmail.com", client_secret="secret"
            )

        assert token == "g_token"
        assert provider == "google"

    def test_label_appears_in_messages(self, capsys):
        """Test that label is included in status messages."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value="tok"):
            imap_oauth2.acquire_token("outlook.office365.com", "cid", "user@example.com", label="source")

        out = capsys.readouterr().out
        assert "Acquiring OAuth2 token for source (microsoft)" in out
        assert "Source OAuth2 token acquired successfully" in out

    def test_exits_on_unrecognized_host(self):
        """Test sys.exit(1) when provider cannot be detected from host."""
        with pytest.raises(SystemExit) as exc_info:
            imap_oauth2.acquire_token("imap.example.com", "cid", "user@example.com")
        assert exc_info.value.code == 1

    def test_exits_on_token_acquisition_failure(self):
        """Test sys.exit(1) when token acquisition returns None."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value=None):
            with pytest.raises(SystemExit) as exc_info:
                imap_oauth2.acquire_token("outlook.office365.com", "cid", "user@example.com")
        assert exc_info.value.code == 1

    def test_exit_message_includes_label(self, capsys):
        """Test that failure message includes the label when provided."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value=None):
            with pytest.raises(SystemExit):
                imap_oauth2.acquire_token("outlook.office365.com", "cid", "user@example.com", label="destination")

        out = capsys.readouterr().out
        assert "Failed to acquire OAuth2 token for destination" in out

    def test_exit_message_without_label(self, capsys):
        """Test that failure message works without a label."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value=None):
            with pytest.raises(SystemExit):
                imap_oauth2.acquire_token("imap.gmail.com", "cid", "user@gmail.com", client_secret="s")

        out = capsys.readouterr().out
        assert "Error: Failed to acquire OAuth2 token." in out

    def test_passes_client_secret_to_provider(self):
        """Test that client_secret is forwarded to acquire_oauth2_token_for_provider."""
        with patch.object(imap_oauth2, "acquire_oauth2_token_for_provider", return_value="tok") as mock_acq:
            imap_oauth2.acquire_token("imap.gmail.com", "cid", "user@gmail.com", client_secret="my_secret")

        mock_acq.assert_called_once_with("google", "cid", "user@gmail.com", "my_secret")


class TestAuthDescription:
    """Tests for the auth_description function."""

    def test_microsoft_provider(self):
        """Test returns OAuth2 description for Microsoft provider."""
        assert imap_oauth2.auth_description("microsoft") == "OAuth2/microsoft (XOAUTH2)"

    def test_google_provider(self):
        """Test returns OAuth2 description for Google provider."""
        assert imap_oauth2.auth_description("google") == "OAuth2/google (XOAUTH2)"

    def test_none_provider(self):
        """Test returns Basic description when provider is None."""
        assert imap_oauth2.auth_description(None) == "Basic (password)"

    def test_falsy_provider(self):
        """Test returns Basic description for any falsy value."""
        assert imap_oauth2.auth_description("") == "Basic (password)"
        assert imap_oauth2.auth_description(0) == "Basic (password)"
        assert imap_oauth2.auth_description(False) == "Basic (password)"
