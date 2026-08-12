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

    FOLDER_ARG_INDEXES = {
        "append": (0,),
        "copy": (1,),
        "create": (0,),
        "delete": (0,),
        "examine": (0,),
        "rename": (0, 1),
        "select": (0,),
        "status": (0,),
        "subscribe": (0,),
        "unsubscribe": (0,),
    }

    def __init__(self, conn, max_retries=3, initial_wait=5, log_fn=print, folder_prefix="", folder_sep="/"):
        if max_retries < 1:
            raise ValueError(f"max_retries must be >= 1, got {max_retries}")
        if initial_wait < 0:
            raise ValueError(f"initial_wait must be >= 0, got {initial_wait}")
        self._conn = conn
        self._max_retries = max_retries
        self._initial_wait = initial_wait
        self._log_fn = log_fn
        self.configure_folder_mapping(folder_prefix, folder_sep)

    def configure_folder_mapping(self, folder_prefix="", folder_sep="/"):
        """Configure destination mailbox prefix and hierarchy separator mapping."""
        self._folder_prefix = folder_prefix or ""
        self._folder_sep = folder_sep or "/"

    def _map_folder(self, folder):
        if not isinstance(folder, (str, bytes)):
            return folder

        was_bytes = isinstance(folder, bytes)
        value = folder.decode("utf-8") if was_bytes else folder
        quoted = len(value) >= 2 and value.startswith('"') and value.endswith('"')
        name = value[1:-1] if quoted else value

        if name.upper() != "INBOX" and not (self._folder_prefix and name.startswith(self._folder_prefix)):
            if self._folder_sep != "/":
                name = name.replace("/", self._folder_sep)
            name = f"{self._folder_prefix}{name}"

        mapped = f'"{name}"' if quoted else name
        return mapped.encode("utf-8") if was_bytes else mapped

    def _map_folder_args(self, name, args):
        indexes = self.FOLDER_ARG_INDEXES.get(name, ())
        uid_command = (
            args[0].decode("ascii", errors="ignore") if args and isinstance(args[0], bytes) else args[0] if args else ""
        )
        if name == "uid" and str(uid_command).lower() == "copy":
            indexes = (2,)
        if not indexes:
            return args

        mapped = list(args)
        for index in indexes:
            if index < len(mapped) and mapped[index] is not None:
                mapped[index] = self._map_folder(mapped[index])
        return tuple(mapped)

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
        maps_folders = name in self.FOLDER_ARG_INDEXES or name == "uid"
        if (name not in self.RETRYABLE_METHODS and not maps_folders) or not callable(attr):
            return attr

        def wrapper(*args, **kwargs):
            args = self._map_folder_args(name, args)
            if name not in self.RETRYABLE_METHODS:
                return attr(*args, **kwargs)
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
