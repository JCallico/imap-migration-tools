"""
Tests for oauth2_google.py

Tests cover:
- Token acquisition using installed app flow
- Credentials caching and silent token refresh
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from auth import oauth2_google
from auth.oauth2_cache import oauth2_cache


@pytest.fixture(autouse=True)
def clear_caches(monkeypatch):
    """Clear module-level caches between tests."""
    monkeypatch.setenv("OAUTH2_CACHE_ENABLED", "false")
    oauth2_cache.clear_memory()
    yield
    oauth2_cache.clear_memory()


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

        assert oauth2_cache.get("google_credentials", ("client-id", "default")) is mock_credentials

    def test_cached_credentials_refreshed_on_second_call(self):
        """Test second call refreshes cached credentials without opening browser."""
        # Pre-populate cache with credentials that have a refresh token
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh_tok"
        mock_creds.token = "refreshed_google_token"
        oauth2_cache.set("google_credentials", ("client-id", "default"), mock_creds)

        with patch("google.auth.transport.requests.Request"):
            result = oauth2_google.acquire_token("client-id", "client-secret")

        assert result == "refreshed_google_token"
        # Verify refresh was called
        mock_creds.refresh.assert_called_once()

    def test_persistent_credentials_are_restored_and_refreshed(self):
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh-token"
        mock_creds.token = "refreshed-token"
        mock_creds.to_json.return_value = '{"updated":true}'
        serialized = json.dumps(
            {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "refresh_token": "refresh-token",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        )

        with (
            patch.object(oauth2_google.oauth2_cache, "load", return_value=serialized),
            patch.object(oauth2_google.oauth2_cache, "save", return_value=True) as save,
            patch("google.oauth2.credentials.Credentials.from_authorized_user_info", return_value=mock_creds),
            patch("google.auth.transport.requests.Request"),
        ):
            result = oauth2_google.acquire_token("client-id", "client-secret", "User@Gmail.com")

        assert result == "refreshed-token"
        assert oauth2_google.oauth2_cache.get("google_credentials", ("client-id", "user@gmail.com")) is mock_creds
        save.assert_called_once_with("google", '{"updated":true}', "client-id", "user@gmail.com")

    def test_invalid_persistent_credentials_fall_back_to_browser(self, capsys):
        mock_credentials = MagicMock()
        mock_credentials.token = "browser-token"
        mock_flow = MagicMock()
        mock_flow.run_local_server.return_value = mock_credentials

        with (
            patch.object(oauth2_google.oauth2_cache, "load", return_value="not-json"),
            patch.object(oauth2_google.oauth2_cache, "save", return_value=True),
            patch("google_auth_oauthlib.flow.InstalledAppFlow.from_client_config", return_value=mock_flow),
        ):
            result = oauth2_google.acquire_token("client-id", "client-secret", "user@gmail.com")

        assert result == "browser-token"
        assert "Could not restore cached Google credentials" in capsys.readouterr().out

    def test_falls_back_to_browser_if_refresh_fails(self):
        """Test falls back to full auth flow if cached token refresh fails."""
        # Pre-populate cache with credentials whose refresh fails
        mock_creds = MagicMock()
        mock_creds.refresh_token = "refresh_tok"
        mock_creds.refresh.side_effect = Exception("Refresh failed")
        oauth2_cache.set("google_credentials", ("client-id", "default"), mock_creds)

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
        oauth2_cache.set("google_credentials", ("client-id", "default"), mock_creds)

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
