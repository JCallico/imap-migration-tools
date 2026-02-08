"""
IMAP Session Management

Connection and session management for IMAP operations with OAuth2 support.
Combines imap_common (low-level IMAP) with imap_oauth2 (token refresh).
"""

import imap_common
import imap_oauth2


def build_imap_conf(host, user, password, client_id=None, client_secret=None, label=None):
    """
    Build a standard IMAP connection config dict.

    If client_id is provided, acquires an OAuth2 token (with error handling and
    sys.exit(1) on failure). Otherwise, builds a password-auth config.

    Args:
        host: IMAP host
        user: IMAP username / email
        password: IMAP password (used for password auth or as fallback)
        client_id: OAuth2 client ID (triggers OAuth2 flow if provided)
        client_secret: OAuth2 client secret (required for Google)
        label: Optional context label for status messages (e.g. "source", "destination")

    Returns:
        Dict with keys: host, user, password, oauth2_token, oauth2
    """
    oauth2_token = None
    oauth2_provider = None
    oauth2_info = None

    if client_id:
        oauth2_token, oauth2_provider = imap_oauth2.acquire_token(host, client_id, user, client_secret, label)
        oauth2_info = {
            "provider": oauth2_provider,
            "client_id": client_id,
            "email": user,
            "client_secret": client_secret,
        }

    return {
        "host": host,
        "user": user,
        "password": password,
        "oauth2_token": oauth2_token,
        "oauth2": oauth2_info,
    }


def ensure_connection(conn, conf):
    """
    Refresh OAuth2 token if needed and ensure connection is healthy.

    Args:
        conn: Existing IMAP connection or None
        conf: Connection config dict with keys:
            - host, user, password, oauth2_token: connection credentials
            - oauth2: dict with provider, client_id, email, client_secret (optional)

    Returns:
        Healthy IMAP connection, or None if connection failed.
        May return a different connection object if reconnection was needed.
    """
    # The OAuth2 provider implementations (MSAL for Microsoft, google-auth for Google)
    # use internal caching and will only contact the server if the token needs refresh.
    if conf.get("oauth2"):
        imap_oauth2.refresh_oauth2_token(conf, conf.get("oauth2_token"))
    return imap_common.ensure_connection_from_conf(conn, conf)


def ensure_folder_session(conn, conf, folder_name, readonly=True):
    """
    Ensure connection is healthy and folder is selected.

    Proactively refreshes OAuth2 token if needed. If the connection was
    refreshed (new connection object), reselects the folder.

    Args:
        conn: Existing IMAP connection or None
        conf: Connection config dict (see ensure_connection)
        folder_name: IMAP folder to select
        readonly: Whether to select folder as readonly (default True)

    Returns:
        Tuple of (connection, success: bool)
        - On success: (connection, True) - folder is selected
        - On failure: (connection or None, False)
    """
    old_conn = conn
    new_conn = ensure_connection(conn, conf)

    if not new_conn:
        return None, False

    # If connection changed (token refreshed), need to reselect folder
    if new_conn is not old_conn:
        try:
            new_conn.select(f'"{folder_name}"', readonly=readonly)
        except Exception:
            return new_conn, False

    return new_conn, True
