"""
Tests for imap_oauth2.py

Tests cover:
- OAuth2 provider detection
- Microsoft tenant discovery
- Microsoft token acquisition and caching
- Google token acquisition and caching
- Provider dispatch
- Token refresh (caching and silent refresh)
- Thread-safe token refresh
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_oauth2


@pytest.fixture(autouse=True)
def clear_oauth2_caches():
    """Clear module-level OAuth2 caches between tests."""
    imap_oauth2._msal_app_cache.clear()
    imap_oauth2._google_creds_cache.clear()
    yield
    imap_oauth2._msal_app_cache.clear()
    imap_oauth2._google_creds_cache.clear()


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


class TestDiscoverMicrosoftTenant:
    """Tests for discover_microsoft_tenant function."""

    def test_successful_discovery(self):
        """Test successful tenant ID extraction from OpenID config."""
        tenant_id = "12345678-abcd-ef01-2345-67890abcdef0"
        openid_response = json.dumps(
            {
                "issuer": f"https://sts.windows.net/{tenant_id}/",
                "authorization_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
            }
        ).encode("utf-8")

        mock_response = MagicMock()
        mock_response.read.return_value = openid_response
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = imap_oauth2.discover_microsoft_tenant("user@contoso.com")

        assert result == tenant_id

    def test_domain_extraction(self):
        """Test that domain is correctly extracted from email."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"issuer": "https://sts.windows.net/abcdef01-2345-6789-abcd-ef0123456789/"}
        ).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            imap_oauth2.discover_microsoft_tenant("user@example.org")
            call_url = mock_urlopen.call_args[0][0]
            assert "example.org" in call_url

    def test_network_error(self, capsys):
        """Test returns None on network error."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            result = imap_oauth2.discover_microsoft_tenant("user@invalid.example")

        assert result is None
        captured = capsys.readouterr()
        assert "Could not discover" in captured.out

    def test_invalid_json(self, capsys):
        """Test returns None on invalid JSON response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not json"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = imap_oauth2.discover_microsoft_tenant("user@test.com")

        assert result is None

    def test_no_tenant_in_issuer(self, capsys):
        """Test returns None when issuer has no tenant GUID."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"issuer": "https://sts.windows.net/not-a-guid/"}).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = imap_oauth2.discover_microsoft_tenant("user@test.com")

        assert result is None
        captured = capsys.readouterr()
        assert "Could not extract tenant ID" in captured.out


class TestAcquireMicrosoftOauth2Token:
    """Tests for acquire_microsoft_oauth2_token function."""

    def test_successful_token(self):
        """Test successful token acquisition with auto-discovery."""
        with patch.object(imap_oauth2, "discover_microsoft_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC123", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "test_token"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                result = imap_oauth2.acquire_microsoft_oauth2_token("client-id", "user@test.com")

            assert result == "test_token"

    def test_tenant_discovery_failure(self, capsys):
        """Test returns None when tenant discovery fails."""
        with patch.object(imap_oauth2, "discover_microsoft_tenant", return_value=None):
            result = imap_oauth2.acquire_microsoft_oauth2_token("client-id", "user@test.com")

        assert result is None

    def test_cached_token(self):
        """Test returns cached token when available."""
        with patch.object(imap_oauth2, "discover_microsoft_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_account = {"username": "user@test.com"}
            mock_app.get_accounts.return_value = [mock_account]
            mock_app.acquire_token_silent.return_value = {"access_token": "cached_token"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                result = imap_oauth2.acquire_microsoft_oauth2_token("client-id", "user@test.com")

            assert result == "cached_token"


class TestAcquireGoogleOauth2Token:
    """Tests for acquire_google_oauth2_token function."""

    def test_successful_token(self):
        """Test successful Google token acquisition."""
        mock_credentials = MagicMock()
        mock_credentials.token = "google_test_token"

        mock_flow = MagicMock()
        mock_flow.run_local_server.return_value = mock_credentials

        mock_installed_app_flow = MagicMock()
        mock_installed_app_flow.from_client_config.return_value = mock_flow

        mock_module = MagicMock()
        mock_module.InstalledAppFlow = mock_installed_app_flow

        with patch.dict("sys.modules", {"google_auth_oauthlib": MagicMock(), "google_auth_oauthlib.flow": mock_module}):
            result = imap_oauth2.acquire_google_oauth2_token("client-id", "client-secret")

        assert result == "google_test_token"

    def test_missing_library(self):
        """Test exits when google-auth-oauthlib is not installed."""
        with patch.dict("sys.modules", {"google_auth_oauthlib": None, "google_auth_oauthlib.flow": None}):
            with pytest.raises(SystemExit):
                imap_oauth2.acquire_google_oauth2_token("client-id", "client-secret")

    def test_no_token_returned(self):
        """Test returns None when credentials have no token."""
        mock_credentials = MagicMock()
        mock_credentials.token = None

        mock_flow = MagicMock()
        mock_flow.run_local_server.return_value = mock_credentials

        mock_installed_app_flow = MagicMock()
        mock_installed_app_flow.from_client_config.return_value = mock_flow

        mock_module = MagicMock()
        mock_module.InstalledAppFlow = mock_installed_app_flow

        with patch.dict("sys.modules", {"google_auth_oauthlib": MagicMock(), "google_auth_oauthlib.flow": mock_module}):
            result = imap_oauth2.acquire_google_oauth2_token("client-id", "client-secret")

        assert result is None


class TestAcquireOauth2TokenForProvider:
    """Tests for acquire_oauth2_token_for_provider dispatch function."""

    def test_dispatch_to_microsoft(self):
        """Test dispatches to Microsoft when provider is 'microsoft'."""
        with patch.object(imap_oauth2, "acquire_microsoft_oauth2_token", return_value="ms_token") as mock_ms:
            result = imap_oauth2.acquire_oauth2_token_for_provider("microsoft", "cid", "user@test.com")

        assert result == "ms_token"
        mock_ms.assert_called_once_with("cid", "user@test.com")

    def test_dispatch_to_google(self):
        """Test dispatches to Google when provider is 'google'."""
        with patch.object(imap_oauth2, "acquire_google_oauth2_token", return_value="g_token") as mock_g:
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


class TestMicrosoftTokenRefresh:
    """Tests for Microsoft OAuth2 token caching and refresh."""

    def test_msal_app_cached_on_first_call(self):
        """Test MSAL app is cached after first call."""
        with patch.object(imap_oauth2, "discover_microsoft_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token1"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                imap_oauth2.acquire_microsoft_oauth2_token("client-id", "user@test.com")

            assert ("client-id", "tenant-123") in imap_oauth2._msal_app_cache

    def test_cached_app_reused_on_second_call(self):
        """Test second call reuses cached MSAL app instead of creating new one."""
        with patch.object(imap_oauth2, "discover_microsoft_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token1"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                imap_oauth2.acquire_microsoft_oauth2_token("client-id", "user@test.com")

                # Second call — simulate cached token available (refresh token worked)
                mock_account = {"username": "user@test.com"}
                mock_app.get_accounts.return_value = [mock_account]
                mock_app.acquire_token_silent.return_value = {"access_token": "refreshed_token"}

                result = imap_oauth2.acquire_microsoft_oauth2_token("client-id", "user@test.com")

            assert result == "refreshed_token"
            # PublicClientApplication should only have been called once (first call)
            assert mock_msal.PublicClientApplication.call_count == 1


class TestGoogleTokenRefresh:
    """Tests for Google OAuth2 token caching and refresh."""

    def test_credentials_cached_on_first_call(self):
        """Test Google credentials are cached after first call."""
        mock_credentials = MagicMock()
        mock_credentials.token = "google_token"

        mock_flow = MagicMock()
        mock_flow.run_local_server.return_value = mock_credentials

        mock_installed_app_flow = MagicMock()
        mock_installed_app_flow.from_client_config.return_value = mock_flow

        mock_module = MagicMock()
        mock_module.InstalledAppFlow = mock_installed_app_flow

        with patch.dict("sys.modules", {"google_auth_oauthlib": MagicMock(), "google_auth_oauthlib.flow": mock_module}):
            imap_oauth2.acquire_google_oauth2_token("client-id", "client-secret")

        assert ("client-id", "client-secret") in imap_oauth2._google_creds_cache

    def test_cached_credentials_refreshed_on_second_call(self):
        """Test second call refreshes cached credentials without opening browser."""
        # Pre-populate cache with credentials that have a refresh token
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh_tok"
        mock_creds.token = "refreshed_google_token"
        imap_oauth2._google_creds_cache[("client-id", "client-secret")] = mock_creds

        mock_request_module = MagicMock()
        with patch.dict(
            "sys.modules",
            {
                "google": MagicMock(),
                "google.auth": MagicMock(),
                "google.auth.transport": MagicMock(),
                "google.auth.transport.requests": mock_request_module,
            },
        ):
            result = imap_oauth2.acquire_google_oauth2_token("client-id", "client-secret")

        assert result == "refreshed_google_token"
        # Verify refresh was called
        mock_creds.refresh.assert_called_once()

    def test_falls_back_to_browser_if_refresh_fails(self):
        """Test falls back to full auth flow if cached token refresh fails."""
        # Pre-populate cache with credentials whose refresh fails
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh_tok"
        mock_creds.refresh.side_effect = Exception("Refresh failed")
        imap_oauth2._google_creds_cache[("client-id", "client-secret")] = mock_creds

        # Set up the full auth flow
        mock_credentials = MagicMock()
        mock_credentials.token = "new_browser_token"

        mock_flow = MagicMock()
        mock_flow.run_local_server.return_value = mock_credentials

        mock_installed_app_flow = MagicMock()
        mock_installed_app_flow.from_client_config.return_value = mock_flow

        mock_module = MagicMock()
        mock_module.InstalledAppFlow = mock_installed_app_flow

        with patch.dict("sys.modules", {"google_auth_oauthlib": MagicMock(), "google_auth_oauthlib.flow": mock_module}):
            result = imap_oauth2.acquire_google_oauth2_token("client-id", "client-secret")

        assert result == "new_browser_token"


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
