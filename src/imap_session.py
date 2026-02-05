"""
IMAP Session Management

Connection and session management for IMAP operations with OAuth2 support.
Combines imap_common (low-level IMAP) with imap_oauth2 (token refresh).
"""

import imap_common
import imap_oauth2


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
