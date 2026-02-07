"""
Tests for oauth2_google.py

Tests cover:
- Token acquisition using installed app flow
- Credentials caching and silent token refresh
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import oauth2_google


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear module-level caches between tests."""
    oauth2_google._creds_cache.clear()
    yield
    oauth2_google._creds_cache.clear()


class TestAcquireToken:
    """Tests for acquire_token function."""

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
            result = oauth2_google.acquire_token("client-id", "client-secret")

        assert result == "google_test_token"

    def test_missing_library(self):
        """Test exits when google-auth-oauthlib is not installed."""
        with patch.dict("sys.modules", {"google_auth_oauthlib": None, "google_auth_oauthlib.flow": None}):
            with pytest.raises(SystemExit):
                oauth2_google.acquire_token("client-id", "client-secret")

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
            result = oauth2_google.acquire_token("client-id", "client-secret")

        assert result is None

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
            oauth2_google.acquire_token("client-id", "client-secret")

        assert ("client-id", "client-secret") in oauth2_google._creds_cache

    def test_cached_credentials_refreshed_on_second_call(self):
        """Test second call refreshes cached credentials without opening browser."""
        # Pre-populate cache with credentials that have a refresh token
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh_tok"
        mock_creds.token = "refreshed_google_token"
        oauth2_google._creds_cache[("client-id", "client-secret")] = mock_creds

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
            result = oauth2_google.acquire_token("client-id", "client-secret")

        assert result == "refreshed_google_token"
        # Verify refresh was called
        mock_creds.refresh.assert_called_once()

    def test_falls_back_to_browser_if_refresh_fails(self):
        """Test falls back to full auth flow if cached token refresh fails."""
        # Pre-populate cache with credentials whose refresh fails
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh_tok"
        mock_creds.refresh.side_effect = Exception("Refresh failed")
        oauth2_google._creds_cache[("client-id", "client-secret")] = mock_creds

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
            result = oauth2_google.acquire_token("client-id", "client-secret")

        assert result == "new_browser_token"

    def test_no_refresh_if_no_refresh_token(self):
        """Test falls back to browser if cached credentials have no refresh token."""
        # Pre-populate cache with credentials that have no refresh token
        mock_creds = MagicMock()
        mock_creds.refresh_token = None
        oauth2_google._creds_cache[("client-id", "client-secret")] = mock_creds

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
            result = oauth2_google.acquire_token("client-id", "client-secret")

        assert result == "new_browser_token"
        # Refresh should not have been called
        mock_creds.refresh.assert_not_called()
