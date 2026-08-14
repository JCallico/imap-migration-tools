"""
Google OAuth2 Token Acquisition

OAuth2 token acquisition for Google/Gmail IMAP using installed app flow.
Opens a browser for user consent and runs a local HTTP server for the redirect.

Requires the 'google-auth-oauthlib' package: pip install google-auth-oauthlib
"""

import json
import os
import sys

from auth.oauth2_cache import oauth2_cache

GOOGLE_IMAP_SCOPES = ["https://mail.google.com/"]


def acquire_token(client_id, client_secret, email=None):
    """
    Acquires a Google OAuth2 access token using the installed app flow.
    Opens a browser for user consent and runs a local HTTP server for the redirect.
    Requires the 'google-auth-oauthlib' package: pip install google-auth-oauthlib

    On subsequent calls, silently refreshes the token using the cached credentials
    object (which holds the refresh token). No browser interaction needed for refresh.
    """
    try:
        import google.auth.transport.requests
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("Error: 'google-auth-oauthlib' package is required for Google OAuth2.")
        print("Install it with: pip install google-auth-oauthlib")
        sys.exit(1)

    normalized_email = email.strip().casefold() if email else "default"
    credentials_cache_key = (client_id, normalized_email)
    credentials = oauth2_cache.get("google_credentials", credentials_cache_key)

    if credentials is None:
        serialized_credentials = oauth2_cache.load("google", client_id, normalized_email)
        if serialized_credentials:
            try:
                credentials = Credentials.from_authorized_user_info(
                    json.loads(serialized_credentials), scopes=GOOGLE_IMAP_SCOPES
                )
                oauth2_cache.set("google_credentials", credentials_cache_key, credentials)
            except (TypeError, ValueError) as e:
                print(f"Warning: Could not restore cached Google credentials: {e}")

    if credentials and credentials.refresh_token:
        try:
            credentials.refresh(google.auth.transport.requests.Request())
            if credentials.token:
                oauth2_cache.save("google", credentials.to_json(), client_id, normalized_email)
                return credentials.token
        except Exception:
            pass  # Fall through to full auth flow

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

    flow = InstalledAppFlow.from_client_config(client_config, scopes=GOOGLE_IMAP_SCOPES)

    print("Opening browser for Google authentication...")
    print("If the browser does not open, check the terminal for a URL to visit.")

    credentials = flow.run_local_server(port=0)

    if credentials and credentials.token:
        oauth2_cache.set("google_credentials", credentials_cache_key, credentials)
        oauth2_cache.save("google", credentials.to_json(), client_id, normalized_email)
        return credentials.token

    print("Error: Could not acquire Google OAuth2 token.")
    return None
