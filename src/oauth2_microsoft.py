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


def acquire_token(client_id, email):
    """
    Acquires a Microsoft OAuth2 access token using the MSAL device code flow.
    Auto-discovers tenant ID from the email domain.
    Requires the 'msal' package: pip install msal

    On subsequent calls, silently refreshes the token using the cached MSAL app
    (which holds the refresh token in its in-memory cache).
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
