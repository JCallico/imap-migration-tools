"""
IMAP Email Migration Script

This script migrates emails from a source IMAP account to a destination IMAP account.
It iterates through all folders in the source account and copies emails to the destination.
It effectively handles folder creation and duplication checks (based on Message-ID).

Features:
- Progressive migration (folder by folder, email by email).
- Safe duplicate detection (skips widely identical messages).
- Optional deletion from source (set DELETE_FROM_SOURCE=true or use --src-delete).
- Optional deletion from destination (--dest-delete): removes emails not in source.
- Optional flag preservation (--preserve-flags): copies Seen, Answered, Flagged, Draft flags.
    - If a message already exists on the destination, missing flags can be synced onto it.
- Optional Gmail mode (--gmail-mode): migrates only "[Gmail]/All Mail" (no duplicates) and
    applies additional Gmail labels by copying the message into label folders.
    - In Gmail mode, label preservation is enabled automatically.
    - Note: --dest-delete is not supported in --gmail-mode.

Configuration (Environment Variables):
  Source Account:
    SRC_IMAP_HOST       : Source IMAP Host (e.g., imap.gmail.com)
    SRC_IMAP_USERNAME   : Source Username/Email
    SRC_IMAP_PASSWORD   : Source Password (or App Password)

  Destination Account:
    DEST_IMAP_HOST      : Destination IMAP Host
    DEST_IMAP_USERNAME  : Destination Username/Email
    DEST_IMAP_PASSWORD  : Destination Password

  Options:
    DELETE_FROM_SOURCE  : Set to "true" to delete emails from source after successful transfer.
                          Default is "false" (Copy only).
    DEST_DELETE         : Set to "true" to delete emails from destination not found in source.
                          Default is "false".
    PRESERVE_LABELS     : Set to "true" to preserve Gmail labels during migration. Default is "false".
    PRESERVE_FLAGS      : Set to "true" to preserve IMAP flags during migration. Default is "false".
    GMAIL_MODE          : Set to "true" for Gmail migration mode. Default is "false".
    MAX_WORKERS         : Number of concurrent threads (default: 10).
    BATCH_SIZE          : Number of emails to process in a batch per thread (default: 10).

Usage Example:
    # Basic migration (all folders)
    python3 migrate_imap_emails.py \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Migrate only one folder (positional argument)
    python3 migrate_imap_emails.py "INBOX" \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Preserve IMAP flags (read/starred/answered/draft). If the message already exists on the
    # destination, missing flags may be synced on it.
    python3 migrate_imap_emails.py \
        --preserve-flags \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Sync mode: delete emails from dest that aren't in the source folder (non-Gmail-mode only)
    python3 migrate_imap_emails.py --dest-delete \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Move instead of copy: delete from source after successful migration
    python3 migrate_imap_emails.py \
        --src-delete \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Gmail mode (recommended for Gmail -> Gmail): migrates only "[Gmail]/All Mail" and
    # applies labels by copying messages into label folders.
    python3 migrate_imap_emails.py \
        --gmail-mode \
        --src-host "imap.gmail.com" \
        --src-user "source@gmail.com" \
        --src-pass "SOURCE_APP_PASSWORD" \
        --dest-host "imap.gmail.com" \
        --dest-user "dest@gmail.com" \
        --dest-pass "DEST_APP_PASSWORD"
"""

import argparse
import concurrent.futures
import os
import re
import sys
import threading
from email.parser import BytesParser

import imap_common

# Configuration defaults
DELETE_FROM_SOURCE_DEFAULT = False
MAX_WORKERS = 10  # Initial default, updated in main
BATCH_SIZE = 10  # Initial default, updated in main

# Thread-local storage for IMAP connections
thread_local = threading.local()
print_lock = threading.Lock()


def safe_print(message):
    t_name = threading.current_thread().name
    # Shorten thread name for cleaner logs e.g. ThreadPoolExecutor-0_0 -> T-0_0
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with print_lock:
        print(f"[{short_name}] {message}")


def filter_preservable_flags(flags_str):
    """
    Filter a flags string to only include preservable flags.
    Returns filtered flags string or None if empty.
    """
    if not flags_str:
        return None
    # Split and filter
    flags = [f for f in flags_str.split() if f in imap_common.PRESERVABLE_FLAGS]
    return " ".join(flags) if flags else None


def sync_flags_on_existing(imap_conn, folder_name, message_id, flags, size):
    """Sync preservable flags on an existing email.

    This mirrors the restore script behavior: if the destination email exists but
    is missing flags, add them and log each synced flag.
    """
    if not flags or not message_id:
        return

    try:
        imap_conn.select(f'"{folder_name}"')

        clean_id = message_id.replace('"', '\\"')
        typ, data = imap_conn.search(None, f'(HEADER Message-ID "{clean_id}")')
        if typ != "OK" or not data or not data[0]:
            return

        # Use the first match (best-effort)
        msg_num = data[0].split()[0]

        typ, msg_data = imap_conn.fetch(msg_num, "(FLAGS)")
        if typ != "OK" or not msg_data:
            return

        current_flags = set()
        for item in msg_data:
            if isinstance(item, tuple) and item[0]:
                resp_str = item[0].decode("utf-8", errors="ignore")
                match = re.search(r"FLAGS\s+\((.*?)\)", resp_str)
                if match:
                    current_flags.update(match.group(1).split())

        desired_flags = set(flags.split())
        missing = desired_flags - current_flags
        for flag in missing:
            try:
                imap_conn.store(msg_num, "+FLAGS", flag)
                safe_print(f"  -> Synced flag: {flag}")
            except Exception:
                pass

    except Exception as e:
        safe_print(f"Error syncing flags for {message_id} in {folder_name}: {e}")


def is_gmail_label_folder(folder_name):
    """Determine whether a folder represents a Gmail label worth preserving."""
    if folder_name in imap_common.GMAIL_SYSTEM_FOLDERS:
        return False
    if folder_name == imap_common.FOLDER_INBOX:
        return True
    if folder_name in (imap_common.GMAIL_SENT, imap_common.GMAIL_STARRED):
        return True
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


def build_gmail_label_index(src_conn):
    """Build a mapping of Message-ID -> set(labels) by scanning label folders."""
    folders = imap_common.list_selectable_folders(src_conn)
    label_folders = [f for f in folders if is_gmail_label_folder(f)]

    label_index = {}
    total = len(label_folders)
    for i, folder in enumerate(label_folders, start=1):
        safe_print(f"[{i}/{total}] Scanning label folder for Message-IDs: {folder}")
        msg_ids = get_message_ids_in_folder(src_conn, folder)
        label = folder_to_label(folder)
        for msg_id in msg_ids:
            label_index.setdefault(msg_id, set()).add(label)

    return label_index


def parse_message_id_from_bytes(raw_message):
    if not raw_message:
        return None
    try:
        parser = BytesParser()
        email_obj = parser.parsebytes(raw_message)
        return email_obj.get("Message-ID")
    except Exception:
        return None


def get_message_ids_in_folder(imap_conn, folder_name):
    """
    Get a set of Message-IDs for all emails in a folder.
    Used for destination deletion sync.
    """
    message_ids = set()
    try:
        imap_conn.select(f'"{folder_name}"', readonly=True)
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data or not data[0]:
            return message_ids

        uids = data[0].split()
        if not uids:
            return message_ids

        # Fetch Message-IDs in batches
        batch_size = 200
        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            uid_range = b",".join(batch)
            try:
                resp, items = imap_conn.uid("fetch", uid_range, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
                if resp != "OK":
                    continue

                for item in items:
                    if isinstance(item, tuple) and len(item) >= 2:
                        header_data = item[1]
                        if isinstance(header_data, bytes):
                            header_str = header_data.decode("utf-8", errors="ignore")
                            for line in header_str.split("\n"):
                                if line.lower().startswith("message-id:"):
                                    msg_id = line.split(":", 1)[1].strip()
                                    if msg_id:
                                        message_ids.add(msg_id)
                                    break
            except Exception:
                continue
    except Exception as e:
        safe_print(f"Error getting message IDs from {folder_name}: {e}")

    return message_ids


def delete_orphan_emails(imap_conn, folder_name, source_msg_ids):
    """
    Delete emails from destination folder that don't exist in source.
    Returns count of deleted emails.
    """
    deleted_count = 0
    try:
        imap_conn.select(f'"{folder_name}"', readonly=False)
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data or not data[0]:
            return 0

        uids = data[0].split()
        if not uids:
            return 0

        # Check each UID's Message-ID against source
        batch_size = 100
        uids_to_delete = []

        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            uid_range = b",".join(batch)
            try:
                resp, items = imap_conn.uid("fetch", uid_range, "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
                if resp != "OK":
                    continue

                for item in items:
                    if isinstance(item, tuple) and len(item) >= 2:
                        # Extract UID from response
                        meta_str = (
                            item[0].decode("utf-8", errors="ignore") if isinstance(item[0], bytes) else str(item[0])
                        )
                        uid_match = re.search(r"UID\s+(\d+)", meta_str)
                        if not uid_match:
                            continue
                        uid = uid_match.group(1)

                        # Extract Message-ID
                        header_data = item[1]
                        msg_id = None
                        if isinstance(header_data, bytes):
                            header_str = header_data.decode("utf-8", errors="ignore")
                            for line in header_str.split("\n"):
                                if line.lower().startswith("message-id:"):
                                    msg_id = line.split(":", 1)[1].strip()
                                    break

                        # If not in source, mark for deletion
                        if msg_id and msg_id not in source_msg_ids:
                            uids_to_delete.append(uid)

            except Exception:
                continue

        # Delete orphan emails
        for uid in uids_to_delete:
            try:
                imap_conn.uid(imap_common.CMD_STORE, uid, imap_common.OP_ADD_FLAGS, imap_common.FLAG_DELETED_LITERAL)
                deleted_count += 1
            except Exception:
                pass

        if deleted_count > 0:
            imap_conn.expunge()
            safe_print(f"[{folder_name}] Deleted {deleted_count} orphan emails from destination")

    except Exception as e:
        safe_print(f"Error deleting orphans from {folder_name}: {e}")

    return deleted_count


def get_thread_connections(src_conf, dest_conf):
    # Initialize connections for this thread if they don't exist or are closed
    if not hasattr(thread_local, "src") or thread_local.src is None:
        thread_local.src = imap_common.get_imap_connection(*src_conf)
    if not hasattr(thread_local, "dest") or thread_local.dest is None:
        thread_local.dest = imap_common.get_imap_connection(*dest_conf)

    # Simple check if alive (noop)
    try:
        if thread_local.src:
            thread_local.src.noop()
    except Exception:
        thread_local.src = imap_common.get_imap_connection(*src_conf)

    try:
        if thread_local.dest:
            thread_local.dest.noop()
    except Exception:
        thread_local.dest = imap_common.get_imap_connection(*dest_conf)

    return thread_local.src, thread_local.dest


def process_batch(
    uids,
    folder_name,
    src_conf,
    dest_conf,
    delete_from_source,
    trash_folder=None,
    preserve_flags=False,
    gmail_mode=False,
    label_index=None,
):
    src, dest = get_thread_connections(src_conf, dest_conf)
    if not src or not dest:
        safe_print("Error: Could not establish connections in worker thread.")
        return

    # Select source folder
    try:
        src.select(f'"{folder_name}"', readonly=False)
    except Exception as e:
        safe_print(f"Error selecting folder {folder_name} in worker: {e}")
        return

    def ensure_dest_folder(folder):
        try:
            if folder.upper() != imap_common.FOLDER_INBOX:
                dest.create(f'"{folder}"')
        except Exception:
            pass

    # In non-Gmail-mode, we keep a selected destination folder for efficiency
    if not gmail_mode:
        try:
            ensure_dest_folder(folder_name)
            dest.select(f'"{folder_name}"')
        except Exception as e:
            safe_print(f"Error selecting folder {folder_name} in worker: {e}")
            return

    deleted_count = 0
    for uid in uids:
        try:
            # Fetch full message (needed to copy and/or apply labels)
            resp, data = src.uid("fetch", uid, "(FLAGS INTERNALDATE BODY.PEEK[])")
            if resp != "OK":
                uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)
                safe_print(f"[{folder_name}] ERROR Fetch | UID {uid_str}")
                continue

            msg_content = None
            flags = None
            date_str = None

            for item in data:
                if isinstance(item, tuple):
                    msg_content = item[1]
                    meta = item[0].decode("utf-8", errors="ignore")
                    flags_match = re.search(r"FLAGS\s+\((.*?)\)", meta)
                    if flags_match:
                        flags = filter_preservable_flags(flags_match.group(1))
                    date_match = re.search(r"INTERNALDATE\s+\"(.*?)\"", meta)
                    if date_match:
                        date_str = f'"{date_match.group(1)}"'

            if not msg_content:
                continue

            # Compute size and parse headers from the already-fetched message bytes.
            size = len(msg_content) if isinstance(msg_content, (bytes, bytearray)) else 0
            size_str = f"{size / 1024:.1f}KB" if size else "0KB"
            msg_id, subject = imap_common.parse_message_id_and_subject_from_bytes(msg_content)

            # Prefer Message-ID from body if missing from header parse
            if not msg_id:
                msg_id = parse_message_id_from_bytes(msg_content)

            # Determine target folder and labels for Gmail mode
            apply_labels = gmail_mode
            labels = []
            if apply_labels and msg_id and label_index is not None:
                labels = sorted(label_index.get(msg_id, set()))

            if apply_labels:
                skip_folders = {imap_common.GMAIL_ALL_MAIL, imap_common.GMAIL_SPAM, imap_common.GMAIL_TRASH}
                target_folder = None
                remaining_labels = []

                for label in labels:
                    label_folder = label_to_folder(label)
                    if label_folder in skip_folders:
                        continue
                    if target_folder is None:
                        target_folder = label_folder
                    else:
                        remaining_labels.append(label)

                if target_folder is None:
                    target_folder = imap_common.FOLDER_RESTORED_UNLABELED
                    remaining_labels = []
            else:
                target_folder = folder_name
                remaining_labels = []

            ensure_dest_folder(target_folder)
            dest.select(f'"{target_folder}"')

            is_duplicate = bool(msg_id and imap_common.message_exists_in_folder(dest, msg_id))

            if is_duplicate:
                safe_print(f"[{target_folder}] SKIP (exists) | {size_str:<8} | {subject[:40]}")
                if preserve_flags and flags and msg_id:
                    sync_flags_on_existing(dest, target_folder, msg_id, flags, size)
            else:
                valid_flags = f"({flags})" if (preserve_flags and flags) else None
                dest.append(f'"{target_folder}"', valid_flags, date_str, msg_content)
                safe_print(f"[{target_folder}] {'COPIED':<12} | {size_str:<8} | {subject[:40]}")
                if preserve_flags and flags:
                    for flag in flags.split():
                        safe_print(f"  -> Applied flag: {flag}")

            # Apply remaining Gmail labels (always, whether copied or skipped)
            if apply_labels and remaining_labels and msg_id:
                for label in remaining_labels:
                    label_folder = label_to_folder(label)
                    if label_folder == target_folder:
                        continue
                    if label_folder in (imap_common.GMAIL_ALL_MAIL, imap_common.GMAIL_SPAM, imap_common.GMAIL_TRASH):
                        continue
                    try:
                        ensure_dest_folder(label_folder)
                        dest.select(f'"{label_folder}"')
                        if not imap_common.message_exists_in_folder(dest, msg_id):
                            valid_flags = f"({flags})" if (preserve_flags and flags) else None
                            dest.append(f'"{label_folder}"', valid_flags, date_str, msg_content)
                            safe_print(f"  -> Applied label: {label}")
                            if preserve_flags and flags:
                                for flag in flags.split():
                                    safe_print(f"    -> Applied flag: {flag}")
                        elif preserve_flags and flags:
                            sync_flags_on_existing(dest, label_folder, msg_id, flags, size)
                    except Exception as e:
                        safe_print(f"  -> Error applying label {label}: {e}")

            if delete_from_source:
                if trash_folder and folder_name != trash_folder:
                    try:
                        src.uid("copy", uid, f'"{trash_folder}"')
                    except Exception:
                        pass
                src.uid(imap_common.CMD_STORE, uid, imap_common.OP_ADD_FLAGS, imap_common.FLAG_DELETED_LITERAL)
                deleted_count += 1

        except Exception as e:
            safe_print(f"[{folder_name}] ERROR Exec | UID {uid}: {e}")

    if delete_from_source and deleted_count > 0:
        try:
            src.expunge()
            safe_print(f"[{folder_name}] Expunged {deleted_count} messages from batch.")
        except Exception as e:
            safe_print(f"[{folder_name}] ERROR Expunge: {e}")


def migrate_folder(
    src,
    dest,
    folder_name,
    delete_from_source,
    src_conf,
    dest_conf,
    trash_folder=None,
    dest_delete=False,
    preserve_flags=False,
    gmail_mode=False,
    label_index=None,
):
    safe_print(f"--- Preparing Folder: {folder_name} ---")

    # Maintain folder structure (skip in Gmail mode; worker will create/select target label folders)
    if not gmail_mode:
        try:
            if folder_name.upper() != imap_common.FOLDER_INBOX:
                dest.create(f'"{folder_name}"')
        except Exception:
            pass

    # Select in main thread to get UIDs
    try:
        src.select(f'"{folder_name}"', readonly=False)
        if not gmail_mode:
            dest.select(f'"{folder_name}"')
    except Exception as e:
        safe_print(f"Skipping {folder_name}: {e}")
        return

    # Get UIDs
    # Search for UNDELETED to avoid processing messages marked for deletion but not yet expunged
    resp, data = src.uid("search", None, "UNDELETED")
    if resp != "OK":
        return

    uids = data[0].split()
    total = len(uids)

    if total == 0:
        safe_print(f"Folder {folder_name} is empty.")
        # Even if empty, we might need to delete from dest
        if dest_delete:
            safe_print("Checking destination for orphan emails to delete...")
            delete_orphan_emails(dest, folder_name, set())
        return

    safe_print(f"Found {total} messages. Starting parallel migration...")

    # If dest_delete is enabled, gather source Message-IDs first
    source_msg_ids = None
    if dest_delete and not gmail_mode:
        safe_print("Building source Message-ID index for sync...")
        source_msg_ids = get_message_ids_in_folder(src, folder_name)
        safe_print(f"Found {len(source_msg_ids)} unique Message-IDs in source.")
    elif dest_delete and gmail_mode:
        safe_print("Warning: --dest-delete is not supported in --gmail-mode; ignoring.")

    # Create batches
    uid_batches = [uids[i : i + BATCH_SIZE] for i in range(0, len(uids), BATCH_SIZE)]

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = []
        for batch in uid_batches:
            futures.append(
                executor.submit(
                    process_batch,
                    batch,
                    folder_name,
                    src_conf,
                    dest_conf,
                    delete_from_source,
                    trash_folder,
                    preserve_flags,
                    gmail_mode,
                    label_index,
                )
            )

        # Wait for all batches to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"Batch Error: {e}")
    except KeyboardInterrupt:
        safe_print("\n\n!!! Migration interrupted by user. Shutting down threads... !!!\n")
        executor.shutdown(wait=False, cancel_futures=True)
        raise  # Re-raise to stop main loop
    finally:
        executor.shutdown(wait=True)

    if delete_from_source:
        safe_print(f"Expunging any remaining deleted messages from {folder_name}...")
        try:
            src.select(f'"{folder_name}"', readonly=False)
            src.expunge()
        except Exception as e:
            safe_print(f"Error Expunging: {e}")

    # Delete orphan emails from destination if enabled
    if dest_delete and source_msg_ids is not None and not gmail_mode:
        safe_print("Syncing destination: removing emails not in source...")
        delete_orphan_emails(dest, folder_name, source_msg_ids)


def main():
    parser = argparse.ArgumentParser(description="Migrate emails between IMAP accounts.")

    # Positional arg for folder (optional) to keep backward compatibility with previous quick-fix
    parser.add_argument("folder", nargs="?", help="Specific folder to migrate (e.g. '[Gmail]/Important')")

    # Source args
    parser.add_argument("--src-host", default=os.getenv("SRC_IMAP_HOST"), help="Source IMAP Host")
    parser.add_argument("--src-user", default=os.getenv("SRC_IMAP_USERNAME"), help="Source Username")
    parser.add_argument("--src-pass", default=os.getenv("SRC_IMAP_PASSWORD"), help="Source Password")

    # Dest args
    parser.add_argument("--dest-host", default=os.getenv("DEST_IMAP_HOST"), help="Destination IMAP Host")
    parser.add_argument("--dest-user", default=os.getenv("DEST_IMAP_USERNAME"), help="Destination Username")
    parser.add_argument("--dest-pass", default=os.getenv("DEST_IMAP_PASSWORD"), help="Destination Password")

    # Options
    # Check env var for boolean default (msg "true" -> True)
    env_delete = os.getenv("DELETE_FROM_SOURCE", "false").lower() == "true"
    parser.add_argument(
        "--src-delete",
        dest="delete",
        action="store_true",
        default=env_delete,
        help="Delete from source after migration (move semantics)",
    )

    # Sync mode: delete from dest emails not in source
    env_dest_delete = os.getenv("DEST_DELETE", "false").lower() == "true"
    parser.add_argument(
        "--dest-delete",
        action="store_true",
        default=env_dest_delete,
        help="Delete emails from destination that don't exist in source (sync mode)",
    )

    parser.add_argument(
        "--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Number of concurrent threads"
    )
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Batch size per thread")

    # Gmail/Labels options
    env_preserve_labels = os.getenv("PRESERVE_LABELS", "false").lower() == "true"
    parser.add_argument(
        "--preserve-labels",
        action="store_true",
        default=env_preserve_labels,
        help="Preserve Gmail labels during migration",
    )
    env_preserve_flags = os.getenv("PRESERVE_FLAGS", "false").lower() == "true"
    parser.add_argument(
        "--preserve-flags",
        action="store_true",
        default=env_preserve_flags,
        help="Preserve IMAP flags during migration",
    )
    env_gmail_mode = os.getenv("GMAIL_MODE", "false").lower() == "true"
    parser.add_argument(
        "--gmail-mode",
        action="store_true",
        default=env_gmail_mode,
        help="Gmail migration mode",
    )

    args = parser.parse_args()

    # Assign to variables
    SRC_HOST = args.src_host
    SRC_USER = args.src_user
    SRC_PASS = args.src_pass
    DEST_HOST = args.dest_host
    DEST_USER = args.dest_user
    DEST_PASS = args.dest_pass
    DELETE_SOURCE = args.delete
    DEST_DELETE = args.dest_delete

    gmail_mode = bool(args.gmail_mode)
    preserve_flags = bool(args.preserve_flags) or gmail_mode
    preserve_labels = bool(args.preserve_labels) or gmail_mode

    if preserve_labels and not gmail_mode:
        safe_print("Warning: --preserve-labels is only applied in --gmail-mode for direct migration; ignoring.")
        preserve_labels = False

    # Folder priority: CLI Arg > Env Var
    TARGET_FOLDER = args.folder
    if not TARGET_FOLDER and os.getenv("MIGRATE_ONLY_FOLDER"):
        TARGET_FOLDER = os.getenv("MIGRATE_ONLY_FOLDER")

    # Update Globals
    global MAX_WORKERS, BATCH_SIZE
    MAX_WORKERS = args.workers
    BATCH_SIZE = args.batch

    # Validation
    missing_vars = []
    if not SRC_HOST:
        missing_vars.append("SRC_IMAP_HOST")
    if not SRC_USER:
        missing_vars.append("SRC_IMAP_USERNAME")
    if not SRC_PASS:
        missing_vars.append("SRC_IMAP_PASSWORD")
    if not DEST_HOST:
        missing_vars.append("DEST_IMAP_HOST")
    if not DEST_USER:
        missing_vars.append("DEST_IMAP_USERNAME")
    if not DEST_PASS:
        missing_vars.append("DEST_IMAP_PASSWORD")

    if missing_vars:
        print(f"Error: Missing configuration variables: {', '.join(missing_vars)}")
        print("Please provide them via environment variables or command-line arguments.")
        sys.exit(1)

    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {SRC_HOST}")
    print(f"Source User     : {SRC_USER}")
    print(f"Destination Host: {DEST_HOST}")
    print(f"Destination User: {DEST_USER}")
    print(f"Delete fm Source: {DELETE_SOURCE}")
    print(f"Dest Delete     : {DEST_DELETE}")
    print(f"Preserve Flags  : {preserve_flags}")
    print(f"Gmail Mode      : {gmail_mode}")
    if TARGET_FOLDER:
        print(f"Target Folder   : {TARGET_FOLDER}")
    print("-----------------------------\n")

    src_conf = (SRC_HOST, SRC_USER, SRC_PASS)
    dest_conf = (DEST_HOST, DEST_USER, DEST_PASS)

    try:
        # Initial connection to list folders
        safe_print("Connecting to Source to list folders...")
        src_main = imap_common.get_imap_connection(SRC_HOST, SRC_USER, SRC_PASS)
        if not src_main:
            sys.exit(1)

        # Detect Trash Folder if deletion is enabled
        trash_folder = None
        if DELETE_SOURCE:
            safe_print("Deletion enabled. Attempting to detect Trash folder for proper moving...")
            trash_folder = imap_common.detect_trash_folder(src_main)
            if trash_folder:
                safe_print(f"Trash folder detected: '{trash_folder}'. Deleted emails will be moved here first.")
            else:
                safe_print(
                    "Warning: Could not detect Trash folder. Emails will be marked \\Deleted only (standard IMAP delete)."
                )

        # We need a dummy dest connection just to pass to migrate_folder for folder creation checks?
        safe_print("Connecting to Destination...")
        dest_main = imap_common.get_imap_connection(DEST_HOST, DEST_USER, DEST_PASS)
        if not dest_main:
            sys.exit(1)

        label_index = None
        if gmail_mode and preserve_labels:
            safe_print("Gmail mode enabled: building label index from source...")
            label_index = build_gmail_label_index(src_main)
            safe_print(f"Label index built for {len(label_index)} messages.")

        if TARGET_FOLDER:
            # Migration for specific folder
            if DELETE_SOURCE and trash_folder and trash_folder == TARGET_FOLDER:
                safe_print(
                    f"Aborting: Cannot migrate Trash folder '{TARGET_FOLDER}' while --src-delete is enabled. This would create a loop."
                )
                sys.exit(1)

            safe_print(f"Starting migration for single folder: {TARGET_FOLDER}")
            # Verify folder exists first? imaplib usually handles select error if not found
            migrate_folder(
                src_main,
                dest_main,
                TARGET_FOLDER,
                DELETE_SOURCE,
                src_conf,
                dest_conf,
                trash_folder,
                DEST_DELETE,
                preserve_flags,
                gmail_mode,
                label_index,
            )
        else:
            # Migration for all folders
            if gmail_mode:
                folders = imap_common.list_selectable_folders(src_main)
                if imap_common.GMAIL_ALL_MAIL not in folders:
                    safe_print(
                        "Warning: --gmail-mode requested but source does not have [Gmail]/All Mail. Falling back to normal folder migration."
                    )
                    gmail_mode = False
                else:
                    migrate_folder(
                        src_main,
                        dest_main,
                        imap_common.GMAIL_ALL_MAIL,
                        DELETE_SOURCE,
                        src_conf,
                        dest_conf,
                        trash_folder,
                        DEST_DELETE,
                        preserve_flags,
                        True,
                        label_index,
                    )

            if not gmail_mode:
                folders = imap_common.list_selectable_folders(src_main)
                for name in folders:
                    if DELETE_SOURCE and trash_folder and name == trash_folder:
                        safe_print(f"Skipping migration of Trash folder '{name}' (preventing circular migration).")
                        continue

                    migrate_folder(
                        src_main,
                        dest_main,
                        name,
                        DELETE_SOURCE,
                        src_conf,
                        dest_conf,
                        trash_folder,
                        DEST_DELETE,
                        preserve_flags,
                        False,
                        None,
                    )

        src_main.logout()
        dest_main.logout()

    except KeyboardInterrupt:
        safe_print("\n\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        safe_print(f"Fatal Error: {e}")


if __name__ == "__main__":
    main()
