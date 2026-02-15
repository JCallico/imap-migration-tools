"""
IMAP OAuth2 Authentication

OAuth2 token acquisition and refresh for Microsoft and Google IMAP providers.
Dispatches to provider-specific modules (oauth2_microsoft, oauth2_google).

Provider is auto-detected from the IMAP host string.
"""

import sys
import threading

from auth import oauth2_google, oauth2_microsoft

# Re-export caches for test access
_msal_app_cache = oauth2_microsoft._msal_app_cache
_google_creds_cache = oauth2_google._creds_cache
_tenant_cache = oauth2_microsoft._tenant_cache

# Thread-safe token refresh
_token_refresh_lock = threading.Lock()


def is_token_expired_error(error):
    """
    Check if an exception indicates OAuth2 token expiration.

    Args:
        error: The exception to check

    Returns:
        True if the error indicates token expiration, False otherwise
    """
    error_str = str(error).lower()
    return "accesstokenexpired" in error_str or "session invalidated" in error_str


def is_auth_error(error):
    """
    Check if an exception indicates an authentication failure that may be recoverable
    by reconnecting (token expiration, session loss, etc.).

    Args:
        error: The exception to check

    Returns:
        True if the error indicates an auth failure, False otherwise
    """
    error_str = str(error).lower()
    return is_token_expired_error(error) or "not authenticated" in error_str or "authentication failed" in error_str


def detect_oauth2_provider(host):
    """
    Detects the OAuth2 provider from the IMAP host.
    Returns "microsoft", "google", or None if unrecognized.
    """
    host_lower = host.lower()
    if "outlook" in host_lower or "office365" in host_lower or "microsoft" in host_lower:
        return "microsoft"
    if "gmail" in host_lower or "google" in host_lower:
        return "google"
    return None


def discover_microsoft_tenant(email):
    """
    Auto-discovers the Microsoft tenant ID from an email address domain.
    Delegates to oauth2_microsoft module.
    """
    return oauth2_microsoft.discover_tenant(email)


def acquire_microsoft_oauth2_token(client_id, email):
    """
    Acquires a Microsoft OAuth2 access token using the MSAL device code flow.
    Delegates to oauth2_microsoft module.
    """
    return oauth2_microsoft.acquire_token(client_id, email)


def acquire_google_oauth2_token(client_id, client_secret):
    """
    Acquires a Google OAuth2 access token using the installed app flow.
    Delegates to oauth2_google module.
    """
    return oauth2_google.acquire_token(client_id, client_secret)


def acquire_oauth2_token_for_provider(provider, client_id, email, client_secret=None):
    """
    Acquires an OAuth2 token for the specified provider.

    Args:
        provider: "microsoft" or "google"
        client_id: OAuth2 client ID
        email: User's email address (used for Microsoft tenant discovery)
        client_secret: Required for Google, not needed for Microsoft
    """
    if provider == "microsoft":
        return oauth2_microsoft.acquire_token(client_id, email)
    elif provider == "google":
        if not client_secret:
            print(
                "Error: OAuth2 client secret is required for Google OAuth2. "
                "Provide --oauth2-client-secret (or --src-oauth2-client-secret / --dest-oauth2-client-secret), "
                "or set OAUTH2_CLIENT_SECRET / SRC_OAUTH2_CLIENT_SECRET / DEST_OAUTH2_CLIENT_SECRET."
            )
            return None
        return oauth2_google.acquire_token(client_id, client_secret)
    else:
        print(f"Error: Unknown OAuth2 provider: {provider}")
        return None


def acquire_token(host, client_id, email, client_secret=None, label=None):
    """
    Detect the OAuth2 provider from the host and acquire a token.

    Prints status messages and calls sys.exit(1) on failure.

    Args:
        host: IMAP host string (used to detect provider)
        client_id: OAuth2 client ID
        email: User's email address
        client_secret: OAuth2 client secret (required for Google)
        label: Optional context label for messages (e.g. "source", "destination")

    Returns:
        (token, provider) tuple on success.
    """
    provider = detect_oauth2_provider(host)
    if not provider:
        print(f"Error: Could not detect OAuth2 provider from host '{host}'.")
        sys.exit(1)
    if label:
        print(f"Acquiring OAuth2 token for {label} ({provider})...")
    else:
        print(f"Acquiring OAuth2 token ({provider})...")
    token = acquire_oauth2_token_for_provider(provider, client_id, email, client_secret)
    if not token:
        if label:
            print(f"Error: Failed to acquire OAuth2 token for {label}.")
        else:
            print("Error: Failed to acquire OAuth2 token.")
        sys.exit(1)
    if label:
        print(f"{label.capitalize()} OAuth2 token acquired successfully.\n")
    else:
        print("OAuth2 token acquired successfully.\n")
    return token, provider


def auth_description(provider):
    """
    Return a human-readable auth description for config summaries.

    Args:
        provider: OAuth2 provider string (e.g. "microsoft", "google") or None for password auth.

    Returns:
        "OAuth2/{provider} (XOAUTH2)" or "Basic (password)".
    """
    if provider:
        return f"OAuth2/{provider} (XOAUTH2)"
    return "Basic (password)"


def refresh_oauth2_token(conf, old_token):
    """
    Thread-safe OAuth2 token refresh using double-checked locking.

    Multiple threads may detect an expired token simultaneously. This function
    ensures only one thread performs the actual refresh. Other threads waiting
    on the lock will see that conf["oauth2_token"] has already been updated and
    skip the redundant refresh.

    Args:
        conf: Mutable dict with keys:
            - host, user, password, oauth2_token: connection credentials
            - oauth2: dict with provider, client_id, email, client_secret
        old_token: The expired token that triggered this refresh (for comparison)

    Returns:
        The new token string, or None if refresh failed.
    """
    oauth2 = conf.get("oauth2")
    if not oauth2:
        return None

    with _token_refresh_lock:
        # Another thread may have already refreshed while we were waiting
        if conf["oauth2_token"] != old_token:
            return conf["oauth2_token"]

        new_token = acquire_oauth2_token_for_provider(
            oauth2["provider"], oauth2["client_id"], oauth2["email"], oauth2.get("client_secret")
        )
        if new_token:
            conf["oauth2_token"] = new_token
        return new_token
