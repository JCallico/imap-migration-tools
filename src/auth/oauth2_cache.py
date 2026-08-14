"""Provider-neutral OAuth2 caching backed by encrypted MSAL Extensions storage."""

import hashlib
import os
import sys


class MsalExtensionsOAuth2CacheProvider:
    """Provide process-local and encrypted persistent caches for OAuth2 providers."""

    def __init__(self, encrypted_persistence_builder=None):
        self._memory = {}
        self._encrypted_persistence_builder = encrypted_persistence_builder

    def get(self, namespace, key):
        """Return a process-local cached object."""
        return self._memory.get((namespace, key))

    def set(self, namespace, key, value):
        """Store an object in the process-local cache."""
        self._memory[(namespace, key)] = value

    def clear_memory(self):
        """Clear process-local cached objects."""
        self._memory.clear()

    def persistent_cache_enabled(self):
        """Return whether encrypted persistent caching is enabled."""
        value = os.getenv("OAUTH2_CACHE_ENABLED", "true")
        return value.strip().lower() not in {"0", "false", "no", "off"}

    def cache_path(self, namespace, *identity_parts):
        """Return a collision-resistant, non-identifying cache path."""
        identity = "\0".join(str(part).strip().casefold() for part in identity_parts)
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return os.path.join(self._cache_dir(), f"{namespace}-{digest}.cache")

    def create_token_cache(self, namespace, *identity_parts):
        """Create an MSAL-compatible encrypted persistent token cache."""
        persistence = self._create_encrypted_persistence(namespace, *identity_parts)
        if persistence is None:
            return None
        from msal_extensions import PersistedTokenCache

        return PersistedTokenCache(persistence)

    def load(self, namespace, *identity_parts):
        """Load a string from encrypted persistent storage."""
        persistence = self._create_encrypted_persistence(namespace, *identity_parts)
        if persistence is None:
            return None
        from msal_extensions import CrossPlatLock
        from msal_extensions.persistence import PersistenceNotFound

        try:
            with CrossPlatLock(f"{persistence.get_location()}.lockfile"):
                return persistence.load()
        except PersistenceNotFound:
            return None
        except Exception as e:
            print(f"Warning: Could not load the {namespace} persistent token cache: {e}")
            return None

    def save(self, namespace, value, *identity_parts):
        """Save a string to encrypted persistent storage."""
        persistence = self._create_encrypted_persistence(namespace, *identity_parts)
        if persistence is None:
            return False
        from msal_extensions import CrossPlatLock

        try:
            with CrossPlatLock(f"{persistence.get_location()}.lockfile"):
                persistence.save(value)
            return True
        except Exception as e:
            print(f"Warning: Could not save the {namespace} persistent token cache: {e}")
            return False

    def _cache_dir(self):
        configured = os.getenv("OAUTH2_CACHE_DIR")
        if configured:
            return configured
        if sys.platform == "win32":
            root = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
        elif sys.platform == "darwin":
            root = os.path.expanduser("~/Library/Caches")
        else:
            root = os.getenv("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
        return os.path.join(root, "imap-migration-tools")

    def _create_encrypted_persistence(self, namespace, *identity_parts):
        if not self.persistent_cache_enabled():
            return None

        try:
            from msal_extensions import build_encrypted_persistence
        except ImportError:
            print("Warning: Persistent OAuth2 caching requires: pip install msal-extensions")
            return None

        cache_path = self.cache_path(namespace, *identity_parts)
        cache_dir = os.path.dirname(cache_path)
        cache_dir_existed = os.path.isdir(cache_dir)
        try:
            os.makedirs(cache_dir, mode=0o700, exist_ok=True)
            if os.name == "posix" and not cache_dir_existed:
                os.chmod(cache_dir, 0o700)
        except OSError as e:
            print(f"Warning: Persistent token caching is disabled because {cache_dir} is unavailable: {e}")
            return None

        builder = self._encrypted_persistence_builder or build_encrypted_persistence
        try:
            return builder(cache_path)
        except Exception as e:
            print(
                f"Warning: Encrypted token caching is unavailable ({e}). Continuing without persistent token caching."
            )
            return None


oauth2_cache = MsalExtensionsOAuth2CacheProvider()
