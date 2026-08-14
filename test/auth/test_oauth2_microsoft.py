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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from auth import oauth2_microsoft
from auth.oauth2_cache import oauth2_cache
from conftest import temp_env
from mock_oauth_server import MOCK_TENANT_ID

EXPECTED_PERSONAL_MICROSOFT_DOMAINS = {
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "hotmail.co.uk",
    "outlook.co.uk",
    "live.co.uk",
    "hotmail.fr",
    "outlook.fr",
    "hotmail.de",
    "outlook.de",
}


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear module-level caches between tests."""
    oauth2_cache.clear_memory()
    oauth2_microsoft._tenant_cache.clear()
    yield
    oauth2_cache.clear_memory()
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

    def test_discovery_env_override(self, mock_oauth_server):
        """Test discovery uses OAUTH2_MICROSOFT_DISCOVERY_URL when set."""
        with temp_env({"OAUTH2_MICROSOFT_DISCOVERY_URL": mock_oauth_server}):
            result = oauth2_microsoft.discover_tenant("user@example.org")

        assert result == MOCK_TENANT_ID

    def test_personal_domain_allowlist_matches_expected_domains(self):
        assert oauth2_microsoft.PERSONAL_MICROSOFT_DOMAINS == EXPECTED_PERSONAL_MICROSOFT_DOMAINS

    @pytest.mark.parametrize("domain", sorted(EXPECTED_PERSONAL_MICROSOFT_DOMAINS))
    def test_auto_recognizes_known_personal_domains(self, domain):
        assert oauth2_microsoft.discover_tenant(f"user@{domain}") == "consumers"

    def test_auto_does_not_classify_unknown_domain_as_personal(self, mock_oauth_server):
        with temp_env({"OAUTH2_MICROSOFT_DISCOVERY_URL": mock_oauth_server}):
            result = oauth2_microsoft.discover_tenant("user@not-personal.example", "auto")

        assert result == MOCK_TENANT_ID

    def test_personal_supports_non_microsoft_email_without_discovery(self):
        with temp_env({"OAUTH2_MICROSOFT_DISCOVERY_URL": "http://127.0.0.1:1"}):
            result = oauth2_microsoft.discover_tenant("user@example.org", "personal")

        assert result == "consumers"

    def test_work_forces_real_discovery_for_known_personal_domain(self, mock_oauth_server):
        with temp_env({"OAUTH2_MICROSOFT_DISCOVERY_URL": mock_oauth_server}):
            result = oauth2_microsoft.discover_tenant("user@hotmail.com", "work")

        assert result == MOCK_TENANT_ID

    def test_work_override_is_not_polluted_by_auto_cache(self, mock_oauth_server):
        assert oauth2_microsoft.discover_tenant("user@hotmail.com", "auto") == "consumers"

        with temp_env({"OAUTH2_MICROSOFT_DISCOVERY_URL": mock_oauth_server}):
            result = oauth2_microsoft.discover_tenant("user@hotmail.com", "work")

        assert result == MOCK_TENANT_ID

    def test_invalid_account_type_is_rejected(self):
        with pytest.raises(ValueError, match="Invalid Microsoft account type"):
            oauth2_microsoft.discover_tenant("user@example.org", "unknown")


class TestImapScopes:
    @pytest.mark.parametrize(
        ("tenant", "expected_scope"),
        [
            ("consumers", "https://outlook.office.com/IMAP.AccessAsUser.All"),
            (
                "9188040d-6c67-4c5b-b112-36a304b66dad",
                "https://outlook.office.com/IMAP.AccessAsUser.All",
            ),
            ("tenant-123", "https://outlook.office365.com/IMAP.AccessAsUser.All"),
        ],
    )
    def test_tenant_selects_expected_scope(self, tenant, expected_scope):
        assert oauth2_microsoft.get_imap_scopes(tenant) == [expected_scope]


class TestAcquireToken:
    """Tests for acquire_token function."""

    @pytest.fixture(autouse=True)
    def disable_persistent_cache(self):
        """Keep mocked acquisition tests isolated from the user's credential store."""
        with temp_env({"OAUTH2_CACHE_ENABLED": "false"}):
            yield

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

    def test_custom_authority_url(self):
        """Test custom authority URL from environment variable."""
        custom_base = "https://custom.login.example.com"
        tenant_id = "tenant-123"
        expected_authority = f"{custom_base}/{tenant_id}"

        with patch.object(oauth2_microsoft, "discover_tenant", return_value=tenant_id):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "msg"}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                with temp_env(
                    {
                        "OAUTH2_MICROSOFT_AUTHORITY_BASE_URL": custom_base,
                        "OAUTH2_CACHE_ENABLED": "false",
                    }
                ):
                    oauth2_microsoft.acquire_token("client-id", "user@test.com")

            mock_msal.PublicClientApplication.assert_called_with("client-id", authority=expected_authority)

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
            mock_app.get_accounts.assert_called_once_with(username="user@test.com")

    def test_persistent_token_cache_is_attached_to_new_application(self, tmp_path):
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token"}
            mock_msal.PublicClientApplication.return_value = mock_app
            persistent_token_cache = object()

            with (
                patch.dict("sys.modules", {"msal": mock_msal}),
                patch.object(
                    oauth2_cache,
                    "create_token_cache",
                    return_value=persistent_token_cache,
                ) as create_token_cache,
            ):
                with temp_env(
                    {
                        "OAUTH2_CACHE_ENABLED": "true",
                        "OAUTH2_CACHE_DIR": str(tmp_path),
                    }
                ):
                    oauth2_microsoft.acquire_token("client-id", "User@Test.com")

            create_token_cache.assert_called_once_with("microsoft", "client-id", "tenant-123", "user@test.com")
            mock_msal.PublicClientApplication.assert_called_once_with(
                "client-id",
                authority="https://login.microsoftonline.com/tenant-123",
                token_cache=persistent_token_cache,
            )

    def test_msal_application_cached_on_first_call(self):
        """Test the MSAL application is cached after the first call."""
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"user_code": "ABC", "message": "Go to..."}
            mock_app.acquire_token_by_device_flow.return_value = {"access_token": "token1"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                oauth2_microsoft.acquire_token("client-id", "user@test.com")

            expected_authority = "https://login.microsoftonline.com/tenant-123"
            application_cache_key = ("client-id", expected_authority, "user@test.com")
            assert oauth2_cache.get("microsoft_application", application_cache_key) is mock_app

    def test_cached_application_reused_on_second_call(self):
        """Test the second call reuses the cached MSAL application."""
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

    def test_device_flow_initialization_failure(self, capsys):
        with patch.object(oauth2_microsoft, "discover_tenant", return_value="tenant-123"):
            mock_msal = MagicMock()
            mock_app = MagicMock()
            mock_app.get_accounts.return_value = []
            mock_app.initiate_device_flow.return_value = {"error_description": "device flow unavailable"}
            mock_msal.PublicClientApplication.return_value = mock_app

            with patch.dict("sys.modules", {"msal": mock_msal}):
                result = oauth2_microsoft.acquire_token("client-id", "user@test.com")

        assert result is None
        assert "device flow unavailable" in capsys.readouterr().out


class TestFetchJsonHttps:
    """Tests for internal _fetch_json_https function."""

    def test_invalid_host_raises_value_error(self):
        """Test invalid host raises ValueError."""
        # Test empty host
        with pytest.raises(ValueError, match="Invalid host"):
            oauth2_microsoft._fetch_json_https("", "/path")

        # Test None host
        with pytest.raises(ValueError, match="Invalid host"):
            oauth2_microsoft._fetch_json_https(None, "/path")

        # Test host with newline
        with pytest.raises(ValueError, match="Invalid host"):
            oauth2_microsoft._fetch_json_https("api.example.com\n", "/path")

    def test_path_normalization(self):
        """Test path missing leading slash is corrected."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"key": "value"}'

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            # Pass path without '/'
            result = oauth2_microsoft._fetch_json_https("api.example.com", "my/resource")

            # Check request called with normalized path
            mock_conn.request.assert_called_with("GET", "/my/resource", headers={"Accept": "application/json"})
            assert result == {"key": "value"}

    def test_https_ssl_context(self):
        """Test SSL context is created and passed to HTTPSConnection."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"{}"

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        mock_context = MagicMock()

        with patch("ssl.create_default_context", return_value=mock_context) as mock_create_context:
            with patch("http.client.HTTPSConnection", return_value=mock_conn) as mock_https:
                oauth2_microsoft._fetch_json_https("example.com", "/")

                # Verify SSL context creation
                mock_create_context.assert_called_once()

                # Verify context passed to connection
                mock_https.assert_called_with("example.com", timeout=10, context=mock_context)
