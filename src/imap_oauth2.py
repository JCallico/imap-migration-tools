"""
IMAP OAuth2 Authentication

OAuth2 token acquisition and refresh for Microsoft and Google IMAP providers.
Supports device code flow (Microsoft) and installed app flow (Google),
with in-memory caching for silent token refresh.

Notes:
- Microsoft OAuth2 requires the `msal` package and uses device code flow.
- Google OAuth2 requires the `google-auth-oauthlib` package and uses an installed-app flow
    (opens a browser and listens on a local HTTP redirect).
- Provider is auto-detected from the IMAP host string.
"""

import http.client
import json
import re
import ssl
import sys
import threading
import urllib.parse

# Module-level caches for OAuth2 token refresh
_msal_app_cache = {}  # (client_id, tenant_id) -> PublicClientApplication
_google_creds_cache = {}  # (client_id, client_secret) -> credentials
_token_refresh_lock = threading.Lock()


def _fetch_json_https(host, path, timeout=10):
    if not host or any(ch in host for ch in "\r\n"):
        raise ValueError("Invalid host")
    if not path.startswith("/"):
        path = f"/{path}"

    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, timeout=timeout, context=context)
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        response = conn.getresponse()
        body = response.read()
    finally:
        conn.close()

    if response.status != 200:
        raise RuntimeError(f"Unexpected HTTP status {response.status}")
    return json.loads(body.decode("utf-8"))


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
    Uses the OpenID Connect discovery endpoint (no authentication required).
    Returns the tenant ID string or None if discovery fails.
    """
    domain = email.split("@")[-1].strip()
    if not domain:
        print("Error: Could not discover Microsoft tenant: missing email domain")
        return None

    domain_quoted = urllib.parse.quote(domain, safe=".-")
    path = f"/{domain_quoted}/.well-known/openid-configuration"

    try:
        data = _fetch_json_https("login.microsoftonline.com", path, timeout=10)
    except (OSError, http.client.HTTPException, json.JSONDecodeError, RuntimeError, ValueError) as e:
        print(f"Error: Could not discover Microsoft tenant for domain '{domain}': {e}")
        return None

    issuer = data.get("issuer", "")
    match = re.search(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", issuer)
    if match:
        return match.group(1)

    print(f"Error: Could not extract tenant ID from issuer: {issuer}")
    return None


def acquire_microsoft_oauth2_token(client_id, email):
    """
    Acquires a Microsoft OAuth2 access token using the MSAL device code flow.
    Auto-discovers tenant ID from the email domain.
    Requires the 'msal' package: pip install msal

    On subsequent calls, silently refreshes the token using the cached MSAL app
    (which holds the refresh token in its in-memory cache).
    """
    tenant_id = discover_microsoft_tenant(email)
    if not tenant_id:
        return None

    try:
        import msal
    except ImportError:
        print("Error: 'msal' package is required for Microsoft OAuth2. Install it with: pip install msal")
        sys.exit(1)

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["https://outlook.office365.com/IMAP.AccessAsUser.All"]

    # Reuse cached MSAL app so acquire_token_silent can access refresh tokens
    cache_key = (client_id, tenant_id)
    if cache_key in _msal_app_cache:
        app = _msal_app_cache[cache_key]
    else:
        print(f"Discovered Microsoft tenant: {tenant_id}")
        app = msal.PublicClientApplication(client_id, authority=authority)
        _msal_app_cache[cache_key] = app

    # Try cached/refreshed token first (handles refresh tokens automatically)
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            return result["access_token"]

    # Fall back to device code flow (first call or if refresh fails)
    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        print(f"Error: Could not initiate device flow: {flow.get('error_description', 'Unknown error')}")
        return None

    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)

    if "access_token" in result:
        return result["access_token"]

    print(f"Error: Could not acquire token: {result.get('error_description', 'Unknown error')}")
    return None


def acquire_google_oauth2_token(client_id, client_secret):
    """
    Acquires a Google OAuth2 access token using the installed app flow.
    Opens a browser for user consent and runs a local HTTP server for the redirect.
    Requires the 'google-auth-oauthlib' package: pip install google-auth-oauthlib

    On subsequent calls, silently refreshes the token using the cached credentials
    object (which holds the refresh token). No browser interaction needed for refresh.
    """
    # Try refreshing cached credentials first (no browser needed)
    cache_key = (client_id, client_secret)
    if cache_key in _google_creds_cache:
        creds = _google_creds_cache[cache_key]
        if creds and creds.refresh_token:
            try:
                import google.auth.transport.requests

                creds.refresh(google.auth.transport.requests.Request())
                if creds.token:
                    return creds.token
            except Exception:
                pass  # Fall through to full auth flow

    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("Error: 'google-auth-oauthlib' package is required for Google OAuth2.")
        print("Install it with: pip install google-auth-oauthlib")
        sys.exit(1)

    client_config = {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, scopes=["https://mail.google.com/"])

    print("Opening browser for Google authentication...")
    print("If the browser does not open, check the terminal for a URL to visit.")

    credentials = flow.run_local_server(port=0)

    if credentials and credentials.token:
        _google_creds_cache[cache_key] = credentials
        return credentials.token

    print("Error: Could not acquire Google OAuth2 token.")
    return None


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
        return acquire_microsoft_oauth2_token(client_id, email)
    elif provider == "google":
        if not client_secret:
            print(
                "Error: OAuth2 client secret is required for Google OAuth2. "
                "Provide --oauth2-client-secret (or --src-oauth2-client-secret / --dest-oauth2-client-secret), "
                "or set OAUTH2_CLIENT_SECRET / SRC_OAUTH2_CLIENT_SECRET / DEST_OAUTH2_CLIENT_SECRET."
            )
            return None
        return acquire_google_oauth2_token(client_id, client_secret)
    else:
        print(f"Error: Unknown OAuth2 provider: {provider}")
        return None


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
