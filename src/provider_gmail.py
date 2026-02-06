"""
Gmail-Specific IMAP Utilities

Constants and functions specific to Gmail/Google Workspace IMAP implementation.
"""

import imap_common

# Gmail system folders
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


def is_label_folder(folder_name):
    """
    Determines if a folder represents a Gmail label (user-created or system label
    that should be preserved).
    Excludes system folders like All Mail, Spam, Trash, Drafts.
    """
    # Exclude system folders that aren't really "labels"
    if folder_name in GMAIL_SYSTEM_FOLDERS:
        return False

    # INBOX is a special case - it's a label in Gmail
    if folder_name == imap_common.FOLDER_INBOX:
        return True

    # [Gmail]/Sent Mail and [Gmail]/Starred are labels worth preserving
    if folder_name in (GMAIL_SENT, GMAIL_STARRED):
        return True

    # Any folder NOT under [Gmail]/ is a user label
    if not folder_name.startswith("[Gmail]/"):
        return True

    return False


def folder_to_label(folder_name):
    """Convert an IMAP folder name to a Gmail label name (backup/restore compatible)."""
    if folder_name == imap_common.FOLDER_INBOX:
        return imap_common.FOLDER_INBOX
    if folder_name.startswith("[Gmail]/"):
        return folder_name.split("/", 1)[1]
    return folder_name


def label_to_folder(label):
    """Convert a Gmail label name to an IMAP folder path (restore compatible)."""
    if label == imap_common.FOLDER_INBOX:
        return imap_common.FOLDER_INBOX
    if label in ("Sent Mail", "Starred", "Drafts", "Important"):
        return f"[Gmail]/{label}"
    return label


def build_gmail_label_index(src_conn, safe_print_func):
    """
    Build a mapping of Message-ID -> set(labels) by scanning label folders.

    Args:
        src_conn: IMAP connection to source account
        safe_print_func: Function to use for printing (e.g., safe_print from the calling script)

    Returns:
        dict: Mapping of Message-ID -> set(label names)
    """
    folders = imap_common.list_selectable_folders(src_conn)
    label_folders = [f for f in folders if is_label_folder(f)]

    label_index = {}
    total = len(label_folders)
    for i, folder in enumerate(label_folders, start=1):
        safe_print_func(f"[{i}/{total}] Scanning label folder for Message-IDs: {folder}")
        try:
            src_conn.select(f'"{folder}"', readonly=True)
            msg_ids = set(imap_common.get_message_ids_in_folder(src_conn).values())
        except Exception as e:
            safe_print_func(f"Error getting message IDs from {folder}: {e}")
            msg_ids = set()
        label = folder_to_label(folder)
        for msg_id in msg_ids:
            label_index.setdefault(msg_id, set()).add(label)

    return label_index
