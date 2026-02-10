"""
IMAP Retry Logic

Transparent retry wrapper for IMAP connections that handles transient
server errors (e.g. Microsoft 365 "Server Busy") with exponential backoff.
"""

from __future__ import annotations

import time


class ConnectionProxy:
    """Transparent proxy that retries IMAP commands on transient server errors.

    Wraps an imaplib.IMAP4 or IMAP4_SSL connection. For methods in
    RETRYABLE_METHODS that return (typ, data) tuples, retries on transient
    errors with exponential backoff.
    """

    TRANSIENT_PATTERNS = [b"UNAVAILABLE", b"Server Busy", b"try again", b"THROTTLED"]

    # Methods that are safe to retry and return (typ, data)
    RETRYABLE_METHODS = frozenset(
        {
            "uid",
            "select",
            "search",
            "fetch",
            "append",
            "store",
            "list",
            "create",
            "expunge",
            "noop",
        }
    )

    def __init__(self, conn, max_retries=3, initial_wait=5, log_fn=print):
        if max_retries < 1:
            raise ValueError(f"max_retries must be >= 1, got {max_retries}")
        if initial_wait < 0:
            raise ValueError(f"initial_wait must be >= 0, got {initial_wait}")
        self._conn = conn
        self._max_retries = max_retries
        self._initial_wait = initial_wait
        self._log_fn = log_fn

    @classmethod
    def _is_transient_error(cls, data):
        """Check if IMAP response data contains transient error patterns."""
        for item in data:
            if isinstance(item, bytes):
                for pattern in cls.TRANSIENT_PATTERNS:
                    if pattern in item:
                        return True
        return False

    def __getattr__(self, name):
        attr = getattr(self._conn, name)
        if name not in self.RETRYABLE_METHODS or not callable(attr):
            return attr

        def wrapper(*args, **kwargs):
            last_result = None
            for attempt in range(self._max_retries):
                result = attr(*args, **kwargs)
                if not isinstance(result, tuple) or len(result) < 2:
                    return result
                typ, data = result[0], result[1]
                if typ == "OK" or not self._is_transient_error(data):
                    return result
                last_result = result
                if attempt + 1 < self._max_retries:
                    wait = self._initial_wait * (2**attempt)  # 5s, 10s, 20s
                    self._log_fn(f"Server busy, retrying in {wait}s... (attempt {attempt + 1}/{self._max_retries})")
                    time.sleep(wait)
            return last_result

        return wrapper
