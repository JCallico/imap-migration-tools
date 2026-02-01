"""
IMAP Common Utilities

Shared functionality for IMAP migration, counting, and comparison scripts.
"""

import imaplib
import os
import re
import sys
from email import policy
from email.header import decode_header
from email.parser import BytesParser

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

# Gmail constants
GMAIL_ALL_MAIL = "[Gmail]/All Mail"
GMAIL_TRASH = "[Gmail]/Trash"
GMAIL_SPAM = "[Gmail]/Spam"
GMAIL_DRAFTS = "[Gmail]/Drafts"
GMAIL_BIN = "[Gmail]/Bin"
GMAIL_IMPORTANT = "[Gmail]/Important"
GMAIL_SENT = "[Gmail]/Sent Mail"
GMAIL_STARRED = "[Gmail]/Starred"

GMAIL_SYSTEM_FOLDERS = {
    GMAIL_ALL_MAIL,
    GMAIL_SPAM,
    GMAIL_TRASH,
    GMAIL_DRAFTS,
    GMAIL_BIN,
    GMAIL_IMPORTANT,
}

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
        conn = imaplib.IMAP4_SSL(host)
        if oauth2_token:
            auth_string = f"user={user}\x01auth=Bearer {oauth2_token}\x01\x01"
            conn.authenticate("XOAUTH2", lambda _: auth_string.encode())
        else:
            conn.login(user, password)
        return conn
    except Exception as e:
        print(f"Connection error to {host}: {e}")
        return None


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


def get_msg_details(imap_conn, uid):
    """
    Fetches simplified message details (Message-ID, Size, Subject) for a given UID.
    Returns (msg_id, size, subject) tuple.
    """
    try:
        resp, data = imap_conn.uid("fetch", uid, "(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)])")
    except Exception:
        return None, None, None

    if resp != "OK":
        return None, None, None

    msg_id = None
    subject = "(No Subject)"
    size = 0

    for item in data:
        if isinstance(item, tuple):
            content = item[0].decode("utf-8", errors="ignore")

            # Parse Size
            size_match = re.search(r"RFC822\.SIZE\s+(\d+)", content)
            if size_match:
                size = int(size_match.group(1))

            # Parse Headers
            msg_bytes = item[1]
            # Use compat32 to preserve raw headers with continuation lines
            parser = BytesParser(policy=policy.compat32)
            email_obj = parser.parsebytes(msg_bytes, headersonly=True)
            msg_id = decode_message_id(email_obj.get("Message-ID"))
            raw_subject = email_obj.get("Subject")
            if raw_subject:
                subject = decode_mime_header(raw_subject)

    return msg_id, size, subject


def message_exists_in_folder(dest_conn, msg_id):
    """
    Checks if a message with the given Message-ID exists in the CURRENTLY SELECTED folder of dest_conn.
    Returns True if found, False otherwise.
    """
    if not msg_id:
        return False

    clean_id = msg_id.replace('"', '\\"')
    try:
        typ, data = dest_conn.search(None, f'(HEADER Message-ID "{clean_id}")')
        if typ != "OK":
            return False

        dest_ids = data[0].split()
        return len(dest_ids) > 0
    except Exception:
        return False


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
