"""
IMAP Common Utilities

Shared functionality for IMAP migration, counting, and comparison scripts.
"""

from __future__ import annotations

import imaplib
import json
import os
import re
import sys
import threading
import urllib.parse
from email import policy
from email.header import decode_header
from email.parser import BytesParser

import imap_oauth2
import restore_cache

# Standard IMAP flags
FLAG_SEEN = "\\Seen"
FLAG_ANSWERED = "\\Answered"
FLAG_FLAGGED = "\\Flagged"
FLAG_DRAFT = "\\Draft"
FLAG_DELETED = "\\Deleted"
FLAG_DELETED_LITERAL = "(\\Deleted)"

# Standard IMAP flags that can be preserved during migration
# \Recent is session-specific and cannot be set by clients
# \Deleted should not be preserved as it marks messages for removal
PRESERVABLE_FLAGS = {FLAG_SEEN, FLAG_ANSWERED, FLAG_FLAGGED, FLAG_DRAFT}

# IMAP Folder Constants
FOLDER_INBOX = "INBOX"

# Gmail-mode restore/migrate fallback folder for messages with no usable labels.
# Keeping this as a normal folder (not [Gmail]/Drafts) avoids populating Drafts with non-drafts.
FOLDER_RESTORED_UNLABELED = "Restored/Unlabeled"

# IMAP Commands
CMD_STORE = "store"
CMD_SEARCH = "search"
CMD_FETCH = "fetch"
OP_ADD_FLAGS = "+FLAGS"

_print_lock = threading.Lock()


def safe_print(message: str) -> None:
    """Thread-safe print with short thread names for logs."""
    t_name = threading.current_thread().name
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with _print_lock:
        print(f"[{short_name}] {message}")


def _is_ignored_local_dir(dirname: str) -> bool:
    return dirname.startswith(".") or dirname == "__pycache__"


def list_local_folders(local_root: str) -> list[str]:
    """List all folders under a local backup root in IMAP-style names."""
    folders: set[str] = set()

    for dirpath, dirnames, _filenames in os.walk(local_root):
        dirnames[:] = [d for d in dirnames if not _is_ignored_local_dir(d)]

        if os.path.abspath(dirpath) == os.path.abspath(local_root):
            continue

        rel = os.path.relpath(dirpath, local_root)
        if rel == ".":
            continue

        parts = [p for p in rel.split(os.sep) if p and not _is_ignored_local_dir(p)]
        if not parts:
            continue

        folders.add("/".join(parts))

    return sorted(folders)


def get_local_email_count(local_root: str, folder_name: str) -> int | None:
    """Return the count of .eml files in a local folder, or None if missing/unreadable."""
    folder_path = os.path.join(local_root, *folder_name.split("/"))
    if not os.path.isdir(folder_path):
        return None

    try:
        count = 0
        for filename in os.listdir(folder_path):
            if not filename.endswith(".eml"):
                continue
            full_path = os.path.join(folder_path, filename)
            if os.path.isfile(full_path):
                count += 1
        return count
    except OSError:
        return None


def get_backup_folders(local_path: str) -> list[tuple[str, str]]:
    """Scan the backup directory and return list of (folder_name, folder_path) tuples."""
    folders: list[tuple[str, str]] = []

    def scan_dir(path: str, prefix: str = "") -> None:
        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    # Check if this directory contains .eml files
                    has_eml = any(
                        f.endswith(".eml") for f in os.listdir(item_path) if os.path.isfile(os.path.join(item_path, f))
                    )
                    folder_name = f"{prefix}{item}" if prefix else item

                    if has_eml:
                        folders.append((folder_name, item_path))

                    # Recurse into subdirectories
                    scan_dir(item_path, f"{folder_name}/")
        except Exception:
            pass

    scan_dir(local_path)
    return folders


def extract_message_id_from_eml(file_path: str, read_limit: int = 65536) -> str | None:
    """Extract just the Message-ID from an .eml file efficiently."""
    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(read_limit)

        return extract_message_id(header_bytes)
    except Exception:
        return None


def is_progress_cache_ready(cache_data: dict | None, cache_lock: threading.Lock | None) -> bool:
    """Return True when cache data and lock are initialized."""
    return cache_data is not None and cache_lock is not None


def load_progress_cache(
    cache_root: str,
    dest_host: str,
    dest_user: str,
    *,
    log_fn=None,
) -> tuple[str, dict, threading.Lock]:
    """Load or initialize a progress cache file for a destination."""
    try:
        os.makedirs(cache_root, exist_ok=True)
    except Exception as exc:
        if log_fn is not None:
            log_fn(f"Warning: unable to create cache directory '{cache_root}': {exc}")

    cache_path = restore_cache.get_dest_index_cache_path(cache_root, dest_host, dest_user)
    cache_data = restore_cache.load_dest_index_cache(cache_path)
    cache_lock = threading.Lock()
    if log_fn is not None:
        log_fn(f"Using progress cache: {cache_path}")
    return cache_path, cache_data, cache_lock


def ensure_folder_exists(imap_conn, folder_name: str) -> None:
    """Best-effort create of a folder if it doesn't already exist.

    IMAP servers typically return an error if the mailbox exists; this helper
    intentionally ignores those errors.
    """
    try:
        if folder_name and folder_name.upper() != FOLDER_INBOX:
            imap_conn.create(f'"{folder_name}"')
    except Exception:
        # Folder may already exist, or server may restrict creation.
        pass


def append_email(
    imap_conn,
    folder_name: str,
    raw_content: bytes,
    date_str: str,
    flags: str | None = None,
    *,
    ensure_folder: bool = True,
) -> bool:
    """Append an email message to a folder.

    This is intentionally a thin wrapper around IMAP APPEND; callers can
    perform duplicate checks or folder selection separately.

    Args:
        flags: Optional IMAP flags. If provided, they are normalized to a
            parenthesized list before being passed to `imaplib.IMAP4.append`.
        ensure_folder: If True, attempts to create the folder first (best-effort).
    """
    if ensure_folder:
        ensure_folder_exists(imap_conn, folder_name)

    normalized_flags = None
    if flags:
        stripped = str(flags).strip()
        if stripped:
            if stripped.startswith("(") and stripped.endswith(")"):
                normalized_flags = stripped
            else:
                normalized_flags = f"({stripped})"

    resp, data = imap_conn.append(f'"{folder_name}"', normalized_flags, date_str, raw_content)
    if resp != "OK":
        safe_print(f"APPEND failed for {folder_name}: {resp} {data}")
    return resp == "OK"


def verify_env_vars(vars_list):
    """
    Checks if all environment variables in the list are set.
    Returns True if all are present, False otherwise.
    Prints missing variables to stderr.
    """
    missing = [v for v in vars_list if not os.getenv(v)]
    if missing:
        print(f"Error: Missing environment variables: {', '.join(missing)}", file=sys.stderr)
        return False
    return True


def get_imap_connection_from_conf(conf):
    """
    Establishes an IMAP connection using a conf dict.

    conf dict structure:
        {
            "host": str,
            "user": str,
            "password": str or None,
            "oauth2_token": str or None,
            "oauth2": dict or None  # Contains provider, client_id, email, client_secret
        }
    """
    return get_imap_connection(conf["host"], conf["user"], conf.get("password"), conf.get("oauth2_token"))


def get_imap_connection(host, user, password=None, oauth2_token=None):
    """
    Establishes an SSL connection to the IMAP server and logs in.
    Supports both basic auth (password) and OAuth 2.0 (XOAUTH2).
    Returns the connection object or None if failed.
    """
    if not host or not user:
        print(f"Error: Invalid credentials for {host}")
        return None

    if not password and not oauth2_token:
        print(f"Error: Either password or oauth2_token is required for {host}")
        return None

    try:
        use_ssl = True
        resolved_host = host
        port = None
        if "://" in host:
            parsed = urllib.parse.urlparse(host)
            scheme = parsed.scheme.lower()
            if not scheme or not parsed.hostname:
                raise ValueError("Invalid IMAP host")
            if scheme in {"imap", "tcp"}:
                use_ssl = False
            elif scheme in {"imaps", "imap+ssl", "imapssl", "ssl"}:
                use_ssl = True
            else:
                raise ValueError(f"Unsupported IMAP scheme: {scheme}")
            resolved_host = parsed.hostname
            port = parsed.port

        if use_ssl:
            conn = imaplib.IMAP4_SSL(resolved_host, port) if port else imaplib.IMAP4_SSL(resolved_host)
        else:
            conn = imaplib.IMAP4(resolved_host, port) if port else imaplib.IMAP4(resolved_host)
        if oauth2_token:
            auth_string = f"user={user}\x01auth=Bearer {oauth2_token}\x01\x01"
            conn.authenticate("XOAUTH2", lambda _: auth_string.encode())
        else:
            conn.login(user, password)
        return conn
    except Exception as e:
        print(f"Connection error to {host}: {e}")
        return None


def ensure_connection(conn, host, user, password=None, oauth2_token=None):
    """
    Verifies an IMAP connection is still alive, reconnecting if necessary.
    Returns the existing connection if healthy, or a new connection if it was broken.
    Returns None if reconnection fails.
    """
    try:
        if conn:
            conn.noop()
            return conn
    except Exception:
        # Connection is broken (network error, timeout, etc.) - fall through to reconnect
        pass
    return get_imap_connection(host, user, password, oauth2_token)


def ensure_connection_from_conf(conn, conf):
    """
    Verifies an IMAP connection is still alive, reconnecting if necessary.
    Uses a conf dict for connection parameters.
    Returns the existing connection if healthy, or a new connection if it was broken.
    Returns None if reconnection fails.
    """
    try:
        if conn:
            conn.noop()
            return conn
    except Exception:
        # Connection is broken (network error, timeout, etc.) - fall through to reconnect
        pass
    return get_imap_connection_from_conf(conf)


def normalize_folder_name(folder_info_str):
    """
    Parses the IMAP list response to extract the clean folder name.
    Handles quoted names and flags.
    """
    if isinstance(folder_info_str, bytes):
        folder_info_str = folder_info_str.decode("utf-8", errors="ignore")

    # Regex to extract folder name: (flags) "delimiter" name
    # Matches: (\HasNoChildren) "/" "INBOX"  OR  (\HasNoChildren) "/" Drafts
    list_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" "?(?P<name>.*)"?')
    match = list_pattern.search(folder_info_str)
    if match:
        name = match.group("name")
        # If the regex grabbed a trailing quote, strip it (though the regex tries to handle it)
        return name.rstrip('"').strip()

    # Fallback: take the last part
    return folder_info_str.split()[-1].strip('"')


def list_selectable_folders(imap_conn):
    """
    Lists all selectable folders (excluding \\Noselect) on the IMAP connection.
    Returns a list of normalized folder name strings, or an empty list on failure.
    """
    try:
        status, folders = imap_conn.list()
        if status != "OK" or not folders:
            return []
    except Exception:
        return []

    result = []
    for f in folders:
        f_str = f.decode("utf-8", errors="ignore") if isinstance(f, bytes) else str(f)
        if "\\Noselect" in f_str:
            continue
        result.append(normalize_folder_name(f))
    return result


def decode_mime_header(header_value):
    """
    Decodes MIME encoded headers (Subject, etc.) to a unicode string.
    """
    if not header_value:
        return "(No Subject)"
    try:
        decoded_list = decode_header(header_value)
        text_parts = []
        for data, encoding in decoded_list:
            if isinstance(data, bytes):
                charset = encoding or "utf-8"
                try:
                    text_parts.append(data.decode(charset, errors="ignore"))
                except LookupError:
                    text_parts.append(data.decode("utf-8", errors="ignore"))
            else:
                text_parts.append(str(data))
        return "".join(text_parts)
    except Exception:
        return str(header_value)


def decode_message_id(msg_id):
    """
    Decodes a Message-ID header value by unfolding continuation lines.
    Returns the stripped Message-ID string or None if empty.
    """
    if not msg_id:
        return None
    # Unfold any header continuation lines (CRLF/LF + whitespace)
    return re.sub(r"\r?\n[ \t]+", " ", str(msg_id)).strip() or None


def extract_message_id(header_data):
    """
    Extracts the Message-ID from header bytes or string using BytesParser.
    Returns the stripped Message-ID string or None if not found.
    """
    if not header_data:
        return None

    try:
        # Use compat32 to preserve raw header with continuation lines
        # (policy.default's _MessageIDHeader parser truncates at newlines)
        parser = BytesParser(policy=policy.compat32)
        if isinstance(header_data, str):
            header_data = header_data.encode("utf-8", errors="ignore")

        msg = parser.parsebytes(header_data, headersonly=True)
        return decode_message_id(msg.get("Message-ID"))
    except Exception:
        pass
    return None


def parse_message_id_from_bytes(raw_message):
    """Parse Message-ID from RFC822 bytes.

    Parses the full message bytes to extract the Message-ID header.
    """
    if not raw_message:
        return None
    try:
        parser = BytesParser()
        msg = parser.parsebytes(raw_message)
        return decode_message_id(msg.get("Message-ID"))
    except Exception:
        return None


def parse_message_id_and_subject_from_bytes(raw_message):
    """Parse Message-ID and decoded Subject from RFC822 bytes.

    Uses header-only parsing to avoid walking large message bodies.
    Returns a tuple: (message_id, subject).
    """
    if not raw_message:
        return None, "(No Subject)"

    try:
        # Use compat32 to preserve raw headers with continuation lines
        parser = BytesParser(policy=policy.compat32)
        email_obj = parser.parsebytes(raw_message, headersonly=True)
        msg_id = decode_message_id(email_obj.get("Message-ID"))
        raw_subject = email_obj.get("Subject")
        subject = decode_mime_header(raw_subject) if raw_subject else "(No Subject)"
        return msg_id, subject
    except Exception:
        return None, "(No Subject)"


def message_exists_in_folder(dest_conn, msg_id):
    """
    Checks if a message with the given Message-ID exists in the CURRENTLY SELECTED folder of dest_conn.
    Only considers non-deleted messages (UNDELETED) so that messages pending expunge
    don't block uploads of fresh copies.
    Returns True if found, False otherwise.
    """
    if not msg_id:
        return False

    clean_id = msg_id.replace('"', '\\"')
    try:
        typ, data = dest_conn.search(None, f'UNDELETED (HEADER Message-ID "{clean_id}")')
        if typ != "OK":
            return False

        dest_ids = data[0].split()
        return len(dest_ids) > 0
    except Exception:
        return False


def get_message_ids_in_folder(imap_conn):
    """
    Fetches all Message-IDs from the currently selected folder.
    Returns a dict mapping UID (bytes) -> Message-ID (str).
    UIDs without a Message-ID are not included in the result.
    Use set(result.values()) to get just the Message-ID set.
    """
    try:
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data[0].strip():
            return {}
    except Exception as e:
        # Re-raise token expiration errors so callers can handle reconnection
        if imap_oauth2.is_auth_error(e):
            raise
        return {}

    uids = data[0].split()
    return get_uid_to_message_id_map(imap_conn, uids)


def get_uid_to_message_id_map(imap_conn, uids):
    """
    Fetches Message-IDs for a list of UIDs from the currently selected folder.
    Returns a dict mapping UID (bytes) -> Message-ID (str).
    UIDs without a Message-ID are not included in the result.
    """
    uid_to_msgid = {}
    if not uids:
        return uid_to_msgid

    FETCH_BATCH = 500
    for i in range(0, len(uids), FETCH_BATCH):
        batch = uids[i : i + FETCH_BATCH]
        uid_range = b",".join(batch)
        try:
            resp, fetch_data = imap_conn.uid("fetch", uid_range, "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
            if resp != "OK":
                continue
            for item in fetch_data:
                if isinstance(item, tuple) and len(item) >= 2:
                    # Extract UID from response like b'1 (UID 12345 BODY[HEADER.FIELDS ...]'
                    meta = item[0]
                    if isinstance(meta, bytes):
                        meta = meta.decode("utf-8", errors="ignore")
                    uid_match = re.search(r"UID\s+(\d+)", meta)
                    if not uid_match:
                        continue
                    uid = uid_match.group(1).encode()

                    # Extract Message-ID
                    mid = extract_message_id(item[1])
                    if mid:
                        uid_to_msgid[uid] = mid
        except Exception as e:
            # Re-raise token expiration errors so callers can handle reconnection
            if imap_oauth2.is_auth_error(e):
                raise
            continue

    return uid_to_msgid


def sanitize_filename(filename):
    """
    Sanitizes a string to be safe for use as a filename.
    Removes/replaces characters that are illegal in file systems.
    Truncates to 250 chars.
    """
    if not filename:
        return "untitled"
    # Replace invalid characters with underscore
    # Invalid: < > : " / \ | ? * and control chars
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)
    # Strip leading/trailing whitespaces/dots
    s = s.strip().strip(".")
    # Ensure not empty and not too long
    return s[:250] if s else "untitled"


def detect_trash_folder(imap_conn):
    """
    Attempts to identify the Trash folder in the account.
    Returns the folder name (str) or None if not found.
    Checks for common names and SPECIAL-USE attributes.
    """
    try:
        status, folders = imap_conn.list()
        if status != "OK":
            return None
    except Exception:
        return None

    trash_candidates = ["[Gmail]/Trash", "Trash", "Deleted Items", "Bin", "[Gmail]/Bin"]
    detected_by_flag = None
    all_folder_names = []

    for f in folders:
        if isinstance(f, bytes):
            f_str = f.decode("utf-8", errors="ignore")
        else:
            f_str = str(f)

        name = normalize_folder_name(f_str)
        all_folder_names.append(name)

        # Check for SPECIAL-USE flag \Trash
        # The flag is usually inside parentheses like (\HasNoChildren \Trash)
        if "\\Trash" in f_str or "\\Bin" in f_str:
            detected_by_flag = name

    if detected_by_flag:
        return detected_by_flag

    # Check candidates
    for candidate in trash_candidates:
        if candidate in all_folder_names:
            return candidate

    return None


def sync_flags_on_existing(imap_conn, folder_name, message_id, flags, size):
    """Sync flags on an existing email in the given folder.

    Finds the email by Message-ID and adds any missing flags.

    Args:
        imap_conn: IMAP connection
        folder_name: Folder containing the email
        message_id: Message-ID header value
        flags: Space-separated flags string like "\\Seen \\Flagged"
        size: Email size for verification
    """
    if not flags or not message_id:
        return

    try:
        imap_conn.select(f'"{folder_name}"')

        clean_id = message_id.strip("<>").replace('"', '\\"')
        typ, data = imap_conn.search(None, f'HEADER Message-ID "{clean_id}"')
        if typ != "OK" or not data or not data[0]:
            return

        msg_num = data[0].split()[0]

        flag_list = flags.split()
        if not flag_list:
            return

        typ, flag_data = imap_conn.fetch(msg_num, "(FLAGS)")
        if typ != "OK" or not flag_data:
            return

        current_flags = set()
        for item in flag_data:
            if isinstance(item, tuple) and item[0]:
                resp_str = item[0].decode("utf-8", errors="ignore")
                match = re.search(r"FLAGS\s+\((.*?)\)", resp_str)
                if match:
                    current_flags.update(match.group(1).split())

        current_flags_lower = {f.lower() for f in current_flags}
        flags_to_add = [f for f in flag_list if f.lower() not in current_flags_lower]

        if flags_to_add:
            flags_str = " ".join(flags_to_add)
            typ, data = imap_conn.store(msg_num, "+FLAGS", f"({flags_str})")
            if typ == "OK":
                for flag in flags_to_add:
                    safe_print(f"  -> Synced flag: {flag}")
            else:
                safe_print(f"STORE +FLAGS failed for {message_id} in {folder_name}: {typ} {data}")

    except Exception as e:
        safe_print(f"Error syncing flags for {message_id} in {folder_name}: {e}")


def delete_orphan_emails(imap_conn, folder_name, source_msg_ids, dest_uid_to_msgid=None):
    """Delete emails from a folder that don't exist in the source set.

    Returns count of deleted emails.

    Args:
        imap_conn: IMAP connection
        folder_name: Folder to delete orphans from
        source_msg_ids: Set of Message-IDs that should be kept
        dest_uid_to_msgid: Optional pre-fetched dict of UID -> Message-ID.
            If None, fetches from the server.
    """
    deleted_count = 0
    try:
        imap_conn.select(f'"{folder_name}"', readonly=False)

        if dest_uid_to_msgid is None:
            dest_uid_to_msgid = get_message_ids_in_folder(imap_conn)

        uids_to_delete = []
        for uid, msg_id in dest_uid_to_msgid.items():
            if msg_id not in source_msg_ids:
                uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                uids_to_delete.append(uid_str)

        for uid in uids_to_delete:
            try:
                imap_conn.uid(CMD_STORE, uid, OP_ADD_FLAGS, FLAG_DELETED_LITERAL)
                deleted_count += 1
            except Exception as e:
                safe_print(f"Warning: Failed to mark UID {uid} as deleted in folder {folder_name}: {e}")

        if deleted_count > 0:
            imap_conn.expunge()
            safe_print(f"[{folder_name}] Deleted {deleted_count} orphan emails from destination")

    except Exception as e:
        safe_print(f"Error deleting orphans from {folder_name}: {e}")

    return deleted_count


def load_folder_msg_ids(
    imap_conn,
    folder_name,
    msg_ids_by_folder,
    msg_ids_lock,
    progress_cache_data=None,
    progress_cache_lock=None,
    dest_host=None,
    dest_user=None,
):
    """Load Message-IDs for a folder, fetching from server if not yet cached.

    On first call for a folder, SELECTs the folder and fetches all Message-IDs
    from the server (merged with progress cache). Subsequent calls return the
    cached set without any IMAP operations.

    Returns the set of Message-IDs, or None if tracking is disabled.
    """
    if msg_ids_by_folder is None or msg_ids_lock is None:
        return None

    with msg_ids_lock:
        existing = msg_ids_by_folder.get(folder_name)

    if existing is not None:
        return existing

    # Build from progress cache
    built: set[str] = set()
    if is_progress_cache_ready(progress_cache_data, progress_cache_lock) and dest_host and dest_user:
        built = restore_cache.get_cached_message_ids(
            progress_cache_data,
            progress_cache_lock,
            dest_host,
            dest_user,
            folder_name,
        )

    # Fetch from server for a comprehensive set (one-time cost per folder)
    try:
        ensure_folder_exists(imap_conn, folder_name)
        imap_conn.select(f'"{folder_name}"')
        server_ids = set(get_message_ids_in_folder(imap_conn).values())
        built.update(server_ids)
    except Exception:
        pass

    with msg_ids_lock:
        msg_ids_by_folder.setdefault(folder_name, built)
        return msg_ids_by_folder[folder_name]


def load_manifest(local_path, filename):
    """Load a manifest JSON file from a backup directory.

    Args:
        local_path: Directory containing the manifest file
        filename: Manifest filename (e.g. "labels_manifest.json")

    Returns:
        Parsed manifest dict, or empty dict if not found or invalid.
    """
    manifest_path = os.path.join(local_path, filename)
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
                safe_print(f"Loaded {filename} with {len(manifest)} entries.")
                return manifest
        except Exception as e:
            safe_print(f"Warning: Could not load {filename}: {e}")
    return {}
