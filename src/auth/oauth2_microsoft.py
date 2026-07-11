"""
Microsoft OAuth2 Token Acquisition

OAuth2 token acquisition for Microsoft/Outlook IMAP using MSAL device code flow.
Supports auto-discovery of tenant ID from email domain.

Requires the 'msal' package: pip install msal
"""

import http.client
import json
import os
import re
import ssl
import sys
import urllib.parse

# Module-level caches
_msal_app_cache = {}  # (client_id, tenant_id) -> PublicClientApplication
_tenant_cache = {}  # domain -> tenant_id


def _fetch_json_https(host, path, timeout=10):
    """Fetch JSON from an HTTP(S) endpoint."""
    if not host or any(ch in host for ch in "\r\n"):
        raise ValueError("Invalid host")
    if not path.startswith("/"):
        path = f"/{path}"

    if host.startswith("http://") or host.startswith("https://"):
        parsed = urllib.parse.urlparse(host)
        if not parsed.hostname:
            raise ValueError("Invalid host")
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        base_path = parsed.path.rstrip("/")
        if base_path:
            path = f"{base_path}{path}"

        use_https = parsed.scheme == "https"
    else:
        use_https = True

    if use_https:
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        response = conn.getresponse()
        body = response.read()
    finally:
        conn.close()

    if response.status != 200:
        raise RuntimeError(f"Unexpected HTTP status {response.status}")
    return json.loads(body.decode("utf-8"))


def discover_tenant(email):
    """
    Auto-discovers the Microsoft tenant ID from an email address domain.
    Uses the OpenID Connect discovery endpoint (no authentication required).
    Results are cached per domain to avoid repeated network requests.
    Returns the tenant ID string or None if discovery fails.
    """
    domain = email.split("@")[-1].strip().lower()
    if not domain:
        print("Error: Could not discover Microsoft tenant: missing email domain")
        return None

    # Return cached tenant if available
    if domain in _tenant_cache:
        return _tenant_cache[domain]

    domain_quoted = urllib.parse.quote(domain, safe=".-")
    path = f"/{domain_quoted}/.well-known/openid-configuration"

    discovery_host = os.getenv("OAUTH2_MICROSOFT_DISCOVERY_URL") or "login.microsoftonline.com"
    try:
        data = _fetch_json_https(discovery_host, path, timeout=10)
    except (OSError, http.client.HTTPException, RuntimeError, ValueError) as e:
        print(f"Error: Could not discover Microsoft tenant for domain '{domain}': {e}")
        return None

    issuer = data.get("issuer", "")
    match = re.search(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", issuer)
    if match:
        tenant_id = match.group(1)
        _tenant_cache[domain] = tenant_id
        return tenant_id

    print(f"Error: Could not extract tenant ID from issuer: {issuer}")
    return None


def _msal_cache_path_for(email):
    """
    Per-account MSAL token cache path.
    Contains refresh tokens — permissions restricted to owner (POSIX).
    Environment override: OAUTH2_MICROSOFT_CACHE_DIR.
    """
    cache_dir = os.getenv("OAUTH2_MICROSOFT_CACHE_DIR") or os.path.expanduser("~")
    safe = re.sub(r"[^a-zA-Z0-9]", "_", email.lower())
    return os.path.join(cache_dir, f".msal-imap-migrate-{safe}.json")


def _load_cache(cache_path, msal_module):
    """Load a SerializableTokenCache from disk, if it exists."""
    cache = msal_module.SerializableTokenCache()
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache.deserialize(f.read())
        except (OSError, ValueError) as e:
            print(f"Warning: Could not load MSAL token cache from {cache_path}: {e}")
    return cache


def _save_cache(cache, cache_path):
    """Persist the cache to disk if it changed, with restrictive permissions.

    On POSIX, the file is created with mode 0600 atomically (via os.open with
    the O_CREAT flag + mode arg), so refresh-token bytes never touch a
    world-readable inode. Windows ignores the mode arg — its ACL model is
    handled separately and defaults to inheriting the parent directory ACL,
    which is typically the user's profile directory.
    """
    if not cache.has_state_changed:
        return
    try:
        # os.open with O_CREAT|O_WRONLY|O_TRUNC and mode 0o600 ensures POSIX
        # never sees a world-readable moment between file creation and chmod.
        fd = os.open(
            cache_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(cache.serialize())
    except OSError as e:
        print(f"Warning: Could not save MSAL token cache to {cache_path}: {e}")


def acquire_token(client_id, email):
    """
    Acquires a Microsoft OAuth2 access token using the MSAL device code flow.
    Auto-discovers tenant ID from the email domain.
    Requires the 'msal' package: pip install msal

    The token cache is persisted to disk (per email, in the user's home dir
    by default; override with OAUTH2_MICROSOFT_CACHE_DIR). After the first
    interactive device-code approval, subsequent process invocations reuse
    the refresh token silently — enabling cron use. Cache files contain
    refresh tokens (secrets) and are written with mode 0600 on POSIX.
    """
    tenant_id = discover_tenant(email)
    if not tenant_id:
        return None

    try:
        import msal
    except ImportError:
        print("Error: 'msal' package is required for Microsoft OAuth2. Install it with: pip install msal")
        sys.exit(1)

    authority_base = os.getenv("OAUTH2_MICROSOFT_AUTHORITY_BASE_URL")
    if authority_base:
        authority = f"{authority_base.rstrip('/')}/{tenant_id}"
    else:
        authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["https://outlook.office365.com/IMAP.AccessAsUser.All"]

    # Load persistent cache — enables non-interactive cron use.
    cache_path = _msal_cache_path_for(email)
    cache = _load_cache(cache_path, msal)

    # Reuse cached MSAL app so acquire_token_silent can access refresh tokens.
    # Include email in the key so different accounts don't share app state.
    cache_key = (client_id, tenant_id, email)
    if cache_key in _msal_app_cache:
        app = _msal_app_cache[cache_key]
    else:
        print(f"Discovered Microsoft tenant: {tenant_id}")
        app = msal.PublicClientApplication(client_id, authority=authority, token_cache=cache)
        _msal_app_cache[cache_key] = app

    # Try cached/refreshed token first (handles refresh tokens automatically)
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            _save_cache(cache, cache_path)  # persist any refresh-token rotation
            return result["access_token"]

    # Fall back to device code flow (first call or if refresh fails)
    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        print(f"Error: Could not initiate device flow: {flow.get('error_description', 'Unknown error')}")
        return None

    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)

    if "access_token" in result:
        _save_cache(cache, cache_path)  # persist newly-acquired refresh token
        return result["access_token"]

    print(f"Error: Could not acquire token: {result.get('error_description', 'Unknown error')}")
    return None
