"""Tests for the provider-neutral OAuth2 cache."""

import os
import sys
from unittest.mock import patch

import pytest
from msal import TokenCache
from msal_extensions import FilePersistence, PersistedTokenCache

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from auth.oauth2_cache import MsalExtensionsOAuth2CacheProvider
from conftest import temp_env


class TestMemoryCache:
    def test_objects_are_partitioned_by_namespace_and_key(self):
        provider = MsalExtensionsOAuth2CacheProvider()
        provider.set("google", ("client", "user"), "google-value")
        provider.set("microsoft", ("client", "user"), "microsoft-value")

        assert provider.get("google", ("client", "user")) == "google-value"
        assert provider.get("microsoft", ("client", "user")) == "microsoft-value"

        provider.clear_memory()
        assert provider.get("google", ("client", "user")) is None


class TestPersistentCache:
    @pytest.mark.parametrize(
        ("platform", "environment", "suffix"),
        [
            ("win32", {"LOCALAPPDATA": "/local"}, "/local/imap-migration-tools"),
            ("linux", {"XDG_CACHE_HOME": "/cache"}, "/cache/imap-migration-tools"),
        ],
    )
    def test_default_directory_uses_platform_convention(self, platform, environment, suffix):
        provider = MsalExtensionsOAuth2CacheProvider()
        with pytest.MonkeyPatch.context() as monkeypatch, temp_env(environment):
            monkeypatch.setattr(sys, "platform", platform)
            assert provider._cache_dir() == suffix

    def test_default_directory_uses_macos_cache(self):
        provider = MsalExtensionsOAuth2CacheProvider()
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(sys, "platform", "darwin")
            assert provider._cache_dir().endswith("/Library/Caches/imap-migration-tools")

    def test_paths_are_normalized_partitioned_and_non_identifying(self, tmp_path):
        provider = MsalExtensionsOAuth2CacheProvider()
        with temp_env({"OAUTH2_CACHE_DIR": str(tmp_path)}):
            first = provider.cache_path("google", "Client-A", " User@Example.com ")
            same_identity = provider.cache_path("google", "client-a", "user@example.com")
            other_provider = provider.cache_path("microsoft", "client-a", "user@example.com")

        assert first == same_identity
        assert first != other_provider
        assert "user@example.com" not in first

    @pytest.mark.parametrize(("value", "enabled"), [("true", True), ("OFF", False)])
    def test_enable_switch(self, value, enabled):
        provider = MsalExtensionsOAuth2CacheProvider()
        with temp_env({"OAUTH2_CACHE_ENABLED": value}):
            assert provider.persistent_cache_enabled() is enabled

    def test_generic_values_round_trip_through_real_persistence(self, tmp_path):
        provider = MsalExtensionsOAuth2CacheProvider(encrypted_persistence_builder=FilePersistence)
        cache_dir = tmp_path / "private-cache"
        with temp_env({"OAUTH2_CACHE_DIR": str(cache_dir)}):
            assert provider.load("google", "client", "user@example.com") is None
            assert provider.save("google", '{"refresh_token":"synthetic"}', "client", "user@example.com")
            assert provider.load("google", "client", "user@example.com") == '{"refresh_token":"synthetic"}'

        assert cache_dir.stat().st_mode & 0o077 == 0

    def test_msal_token_cache_round_trips_through_real_persistence(self, tmp_path):
        provider = MsalExtensionsOAuth2CacheProvider(encrypted_persistence_builder=FilePersistence)
        with temp_env({"OAUTH2_CACHE_DIR": str(tmp_path)}):
            first_cache = provider.create_token_cache("microsoft", "client", "tenant", "user@example.com")
            entry = {
                "home_account_id": "account-id",
                "environment": "login.microsoftonline.com",
                "client_id": "client-id",
                "secret": "synthetic-token",
                "target": "imap-scope",
                "realm": "tenant-id",
                "token_type": "Bearer",
                "expires_on": "9999999999",
            }
            first_cache.modify(TokenCache.CredentialType.ACCESS_TOKEN, entry, entry)
            cache_path = provider.cache_path("microsoft", "client", "tenant", "user@example.com")

        second_cache = PersistedTokenCache(FilePersistence(cache_path))
        assert list(second_cache.search(TokenCache.CredentialType.ACCESS_TOKEN)) == [entry]

    def test_encryption_failure_disables_persistence(self, tmp_path, capsys):
        def unavailable(_path):
            raise RuntimeError("credential store unavailable")

        provider = MsalExtensionsOAuth2CacheProvider(encrypted_persistence_builder=unavailable)
        with temp_env({"OAUTH2_CACHE_DIR": str(tmp_path)}):
            assert provider.load("google", "client", "user") is None
            assert provider.save("google", "value", "client", "user") is False
            assert provider.create_token_cache("microsoft", "client", "tenant", "user") is None

        output = capsys.readouterr().out
        assert "Continuing without persistent token caching" in output
        assert not list(tmp_path.glob("*.cache"))

    def test_unavailable_directory_disables_persistence(self, tmp_path, capsys):
        parent_file = tmp_path / "not-a-directory"
        parent_file.write_text("occupied", encoding="utf-8")
        provider = MsalExtensionsOAuth2CacheProvider(encrypted_persistence_builder=FilePersistence)

        with temp_env({"OAUTH2_CACHE_DIR": str(parent_file)}):
            assert provider.load("google", "client", "user") is None

        assert "Persistent token caching is disabled" in capsys.readouterr().out

    def test_missing_cache_library_disables_only_persistence(self, tmp_path, capsys):
        provider = MsalExtensionsOAuth2CacheProvider()
        with temp_env({"OAUTH2_CACHE_DIR": str(tmp_path)}), patch.dict("sys.modules", {"msal_extensions": None}):
            assert provider.load("google", "client", "user") is None

        assert "pip install msal-extensions" in capsys.readouterr().out

    def test_storage_errors_do_not_escape_provider(self, tmp_path, capsys):
        class FailingPersistence:
            def __init__(self, location):
                self.location = location

            def get_location(self):
                return self.location

            def load(self):
                raise RuntimeError("load failed")

            def save(self, _value):
                raise RuntimeError("save failed")

        provider = MsalExtensionsOAuth2CacheProvider(encrypted_persistence_builder=FailingPersistence)
        with temp_env({"OAUTH2_CACHE_DIR": str(tmp_path)}):
            assert provider.load("google", "client", "user") is None
            assert provider.save("google", "value", "client", "user") is False

        output = capsys.readouterr().out
        assert "Could not load the google persistent token cache" in output
        assert "Could not save the google persistent token cache" in output
