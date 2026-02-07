"""
Tests for oauth2_microsoft.py

Tests cover:
- Tenant discovery from email domain
- Token acquisition using MSAL device code flow
- MSAL app caching and silent token refresh
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import oauth2_microsoft


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear module-level caches between tests."""
    oauth2_microsoft._msal_app_cache.clear()
    oauth2_microsoft._tenant_cache.clear()
    yield
    oauth2_microsoft._msal_app_cache.clear()
    oauth2_microsoft._tenant_cache.clear()


class TestDiscoverTenant:
    """Tests for discover_tenant function."""

    def test_successful_discovery(self):
        """Test successful tenant ID extraction from OpenID config."""
        tenant_id = "12345678-abcd-ef01-2345-67890abcdef0"
        data = {
            "issuer": f"https://sts.windows.net/{tenant_id}/",
            "authorization_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        }

        with patch.object(oauth2_microsoft, "_fetch_json_https", return_value=data):
            result = oauth2_microsoft.discover_tenant("user@contoso.com")

        assert result == tenant_id

    def test_domain_extraction(self):
        """Test that domain is correctly extracted from email."""
        data = {"issuer": "https://sts.windows.net/abcdef01-2345-6789-abcd-ef0123456789/"}

        with patch.object(oauth2_microsoft, "_fetch_json_https", return_value=data) as mock_fetch:
            oauth2_microsoft.discover_tenant("user@example.org")
            host, path = mock_fetch.call_args[0][0], mock_fetch.call_args[0][1]
            assert host == "login.microsoftonline.com"
            assert "example.org" in path

    def test_network_error(self, capsys):
        """Test returns None on network error."""
        with patch.object(oauth2_microsoft, "_fetch_json_https", side_effect=OSError("Connection refused")):
            result = oauth2_microsoft.discover_tenant("user@invalid.example")

        assert result is None
        captured = capsys.readouterr()
        assert "Could not discover" in captured.out

    def test_invalid_json(self, capsys):
        """Test returns None on invalid JSON response."""
        with patch.object(
            oauth2_microsoft,
            "_fetch_json_https",
            side_effect=json.JSONDecodeError("Expecting value", "not json", 0),
        ):
            result = oauth2_microsoft.discover_tenant("user@test.com")

        assert result is None

    def test_no_tenant_in_issuer(self, capsys):
        """Test returns None when issuer has no tenant GUID."""
        data = {"issuer": "https://sts.windows.net/not-a-guid/"}

        with patch.object(oauth2_microsoft, "_fetch_json_https", return_value=data):
            result = oauth2_microsoft.discover_tenant("user@test.com")

        assert result is None
        captured = capsys.readouterr()
        assert "Could not extract tenant ID" in captured.out

    def test_tenant_caching(self):
        """Test that discovered tenant IDs are cached."""
        tenant_id = "12345678-abcd-ef01-2345-67890abcdef0"
        data = {"issuer": f"https://sts.windows.net/{tenant_id}/"}

        with patch.object(oauth2_microsoft, "_fetch_json_https", return_value=data) as mock_fetch:
            # First call
            result1 = oauth2_microsoft.discover_tenant("user@example.com")
            # Second call with same domain
            result2 = oauth2_microsoft.discover_tenant("another@example.com")

        assert result1 == tenant_id
        assert result2 == tenant_id
        # Should only fetch once due to caching
        assert mock_fetch.call_count == 1


class TestAcquireToken:
    """Tests for acquire_token function."""

    def test_successful_token(self):
        """Test successful token acquisition with auto-discovery."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC123", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "test_token"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                result = oauth2_microsoft.acquire_token("client-id", "user@test.com")

            assert result == "test_token"

    def test_tenant_discovery_failure(self, capsys):
        """Test returns None when tenant discovery fails."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value=None):
            result = oauth2_microsoft.acquire_token("client-id", "user@test.com")

        assert result is None

    def test_cached_token(self):
        """Test returns cached token when available."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_account = {"username": "user@test.com"}
            mock_app.get_accounts.return_value = [mock_account]
            mock_app.acquire_token_silent.return_value = {"access_token": "cached_token"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                result = oauth2_microsoft.acquire_token("client-id", "user@test.com")

            assert result == "cached_token"

    def test_msal_app_cached_on_first_call(self):
        """Test MSAL app is cached after first call."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token1"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                oauth2_microsoft.acquire_token("client-id", "user@test.com")

            assert ("client-id", "tenant-123") in oauth2_microsoft._msal_app_cache

    def test_cached_app_reused_on_second_call(self):
        """Test second call reuses cached MSAL app instead of creating new one."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token1"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                oauth2_microsoft.acquire_token("client-id", "user@test.com")

                # Second call — simulate cached token available (refresh token worked)
                mock_account = {"username": "user@test.com"}
                mock_app.get_accounts.return_value = [mock_account]
                mock_app.acquire_token_silent.return_value = {"access_token": "refreshed_token"}

                result = oauth2_microsoft.acquire_token("client-id", "user@test.com")

            assert result == "refreshed_token"
            # PublicClientApplication should only have been called once (first call)
            assert mock_msal.PublicClientApplication.call_count == 1

    def test_missing_msal_library(self):
        """Test exits when msal package is not installed."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            with patch.dict("sys.modules", {"msal": None}):
                with pytest.raises(SystemExit):
                    oauth2_microsoft.acquire_token("client-id", "user@test.com")

    def test_no_token_in_response(self):
        """Test returns None when MSAL response has no access_token."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {}  # No access_token
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                result = oauth2_microsoft.acquire_token("client-id", "user@test.com")

            assert result is None
