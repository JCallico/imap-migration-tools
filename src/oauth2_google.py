"""
Google OAuth2 Token Acquisition

OAuth2 token acquisition for Google/Gmail IMAP using installed app flow.
Opens a browser for user consent and runs a local HTTP server for the redirect.

Requires the 'google-auth-oauthlib' package: pip install google-auth-oauthlib
"""

import os
import sys

# Module-level cache for credentials (holds refresh token)
_creds_cache = {}  # (client_id, client_secret) -> credentials


def acquire_token(client_id, client_secret):
    """
    Acquires a Google OAuth2 access token using the installed app flow.
    Opens a browser for user consent and runs a local HTTP server for the redirect.
    Requires the 'google-auth-oauthlib' package: pip install google-auth-oauthlib

    On subsequent calls, silently refreshes the token using the cached credentials
    object (which holds the refresh token). No browser interaction needed for refresh.
    """
    # Try refreshing cached credentials first (no browser needed)
    cache_key = (client_id, client_secret)
    if cache_key in _creds_cache:
        creds = _creds_cache[cache_key]
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

    auth_uri = os.getenv("OAUTH2_GOOGLE_AUTH_URL") or "https://accounts.google.com/o/oauth2/auth"
    token_uri = os.getenv("OAUTH2_GOOGLE_TOKEN_URL") or "https://oauth2.googleapis.com/token"

    client_config = {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": auth_uri,
            "token_uri": token_uri,
            "redirect_uris": ["http://localhost"],
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, scopes=["https://mail.google.com/"])

    print("Opening browser for Google authentication...")
    print("If the browser does not open, check the terminal for a URL to visit.")

    credentials = flow.run_local_server(port=0)

    if credentials and credentials.token:
        _creds_cache[cache_key] = credentials
        return credentials.token

    print("Error: Could not acquire Google OAuth2 token.")
    return None
