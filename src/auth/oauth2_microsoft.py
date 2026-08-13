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
_tenant_cache = {}  # (domain, account_type) -> tenant_id

MICROSOFT_ACCOUNT_TYPES = ("auto", "personal", "work")
PERSONAL_MICROSOFT_DOMAINS = frozenset(
    {
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
)
CONSUMER_TENANTS = frozenset({"consumers", "9188040d-6c67-4c5b-b112-36a304b66dad"})


def get_imap_scopes(tenant_id):
    """Return the delegated IMAP scope appropriate for a Microsoft tenant."""
    resource_host = "outlook.office.com" if tenant_id.lower() in CONSUMER_TENANTS else "outlook.office365.com"
    return [f"https://{resource_host}/IMAP.AccessAsUser.All"]


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


def discover_tenant(email, account_type="auto"):
    """
    Auto-discovers the Microsoft tenant ID from an email address domain.
    Uses the OpenID Connect discovery endpoint (no authentication required).
    Results are cached per domain to avoid repeated network requests.
    Returns the tenant ID string or None if discovery fails.
    """
    account_type = account_type.strip().lower()
    if account_type not in MICROSOFT_ACCOUNT_TYPES:
        choices = ", ".join(MICROSOFT_ACCOUNT_TYPES)
        raise ValueError(f"Invalid Microsoft account type '{account_type}'; expected one of: {choices}")

    if account_type == "personal":
        return "consumers"

    domain = email.split("@")[-1].strip().lower()
    if not domain:
        print("Error: Could not discover Microsoft tenant: missing email domain")
        return None

    cache_key = (domain, account_type)
    if cache_key in _tenant_cache:
        return _tenant_cache[cache_key]

    # Personal Microsoft accounts (live.com identity provider) live in the
    # "consumers" tenant. Auto-discovery via login.microsoftonline.com for
    # these domains returns a Microsoft-internal work/school tenant that
    # rejects personal accounts with AADSTS50020. Short-circuit here.
    if account_type == "auto" and domain in PERSONAL_MICROSOFT_DOMAINS:
        _tenant_cache[cache_key] = "consumers"
        return "consumers"

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
        _tenant_cache[cache_key] = tenant_id
        return tenant_id

    print(f"Error: Could not extract tenant ID from issuer: {issuer}")
    return None


def acquire_token(client_id, email, account_type="auto"):
    """
    Acquires a Microsoft OAuth2 access token using the MSAL device code flow.
    Auto-discovers tenant ID from the email domain.
    Requires the 'msal' package: pip install msal

    On subsequent calls, silently refreshes the token using the cached MSAL app
    (which holds the refresh token in its in-memory cache).
    """
    tenant_id = discover_tenant(email, account_type)
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
    # Personal accounts (consumers tenant) require the outlook.office.com
    # resource URL, not outlook.office365.com, or AADSTS70011 fires.
    scopes = get_imap_scopes(tenant_id)

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
