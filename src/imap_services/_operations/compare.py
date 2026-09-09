"""Compatibility helpers for callers using the original comparison API."""


def get_email_count(connection, folder_name):
    """Return an IMAP folder's message count, or ``None`` on error."""
    try:
        status, data = connection.select(f'"{folder_name}"', readonly=True)
        if status != "OK":
            return None
        return int(data[0]) if data and data[0] else 0
    except Exception:
        return None
