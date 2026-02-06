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

    OAuth2 (Optional - instead of password):
    SRC_OAUTH2_CLIENT_ID     : OAuth2 Client ID
    SRC_OAUTH2_CLIENT_SECRET : OAuth2 Client Secret (required for Google)

  Destination Account:
    DEST_IMAP_HOST      : Destination IMAP Host
    DEST_IMAP_USERNAME  : Destination Username/Email
    DEST_IMAP_PASSWORD  : Destination Password

    OAuth2 (Optional - instead of password):
    DEST_OAUTH2_CLIENT_ID     : OAuth2 Client ID
    DEST_OAUTH2_CLIENT_SECRET : OAuth2 Client Secret (required for Google)

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

import imap_common
import provider_exchange
import provider_gmail
import imap_oauth2
import imap_session

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


def delete_orphan_emails(imap_conn, folder_name, source_msg_ids, dest_uid_to_msgid=None):
    """
    Delete emails from destination folder that don't exist in source.
    Returns count of deleted emails.

    If dest_uid_to_msgid is provided (dict of UID -> Message-ID), it will be used
    instead of fetching from the server, avoiding redundant IMAP calls.
    """
    deleted_count = 0
    try:
        imap_conn.select(f'"{folder_name}"', readonly=False)

        # Use provided map or fetch from server
        if dest_uid_to_msgid is None:
            dest_uid_to_msgid = imap_common.get_message_ids_in_folder(imap_conn)

        # Find UIDs to delete (in destination but not in source)
        uids_to_delete = []
        for uid, msg_id in dest_uid_to_msgid.items():
            if msg_id not in source_msg_ids:
                # Convert bytes UID to string for STORE command
                uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                uids_to_delete.append(uid_str)

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
    thread_local.src = imap_session.ensure_connection(getattr(thread_local, "src", None), src_conf)
    thread_local.dest = imap_session.ensure_connection(getattr(thread_local, "dest", None), dest_conf)
    return thread_local.src, thread_local.dest


def process_single_uid(
    src,
    dest,
    uid,
    folder_name,
    delete_from_source,
    trash_folder,
    preserve_flags,
    gmail_mode,
    label_index,
    check_duplicate,
):
    """
    Migrate a single email by UID.

    Returns:
        Tuple of (success, src, dest, deleted):
        - success=True: UID processed (copied, skipped, or non-auth error)
        - success=False: Auth error, caller should retry after reconnect
        - deleted: 1 if message was marked for deletion, 0 otherwise
    """
    uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)

    try:
        resp, data = src.uid("fetch", uid, "(FLAGS INTERNALDATE BODY.PEEK[])")
        if resp != "OK":
            safe_print(f"[{folder_name}] ERROR Fetch | UID {uid_str}")
            return (True, src, dest, 0)

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
            return (True, src, dest, 0)

        size = len(msg_content) if isinstance(msg_content, (bytes, bytearray)) else 0
        size_str = f"{size / 1024:.1f}KB" if size else "0KB"
        msg_id, subject = imap_common.parse_message_id_and_subject_from_bytes(msg_content)

        if not msg_id:
            msg_id = imap_common.parse_message_id_from_bytes(msg_content)

        # Determine target folder and labels for Gmail mode
        apply_labels = gmail_mode
        labels = []
        if apply_labels and msg_id and label_index is not None:
            labels = sorted(label_index.get(msg_id, set()))

        if apply_labels:
            skip_folders = {provider_gmail.GMAIL_ALL_MAIL, provider_gmail.GMAIL_SPAM, provider_gmail.GMAIL_TRASH}
            target_folder = None
            remaining_labels = []

            for label in labels:
                label_folder = provider_gmail.label_to_folder(label)
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

        imap_common.ensure_folder_exists(dest, target_folder)
        dest.select(f'"{target_folder}"')

        is_duplicate = bool(msg_id and check_duplicate and imap_common.message_exists_in_folder(dest, msg_id))

        if is_duplicate:
            safe_print(f"[{target_folder}] SKIP (exists) | {size_str:<8} | {subject[:40]}")
            if preserve_flags and flags and msg_id:
                sync_flags_on_existing(dest, target_folder, msg_id, flags, size)
        else:
            valid_flags = f"({flags})" if (preserve_flags and flags) else None
            imap_common.append_email(
                dest,
                target_folder,
                msg_content,
                date_str,
                valid_flags,
                ensure_folder=False,
            )
            safe_print(f"[{target_folder}] {'COPIED':<12} | {size_str:<8} | {subject[:40]}")
            if preserve_flags and flags:
                for flag in flags.split():
                    safe_print(f"  -> Applied flag: {flag}")

        # Apply remaining Gmail labels
        if apply_labels and remaining_labels and msg_id:
            for label in remaining_labels:
                label_folder = provider_gmail.label_to_folder(label)
                if label_folder == target_folder:
                    continue
                if label_folder in (
                    provider_gmail.GMAIL_ALL_MAIL,
                    provider_gmail.GMAIL_SPAM,
                    provider_gmail.GMAIL_TRASH,
                ):
                    continue
                try:
                    imap_common.ensure_folder_exists(dest, label_folder)
                    dest.select(f'"{label_folder}"')
                    if not imap_common.message_exists_in_folder(dest, msg_id):
                        valid_flags = f"({flags})" if (preserve_flags and flags) else None
                        imap_common.append_email(
                            dest,
                            label_folder,
                            msg_content,
                            date_str,
                            valid_flags,
                            ensure_folder=False,
                        )
                        safe_print(f"  -> Applied label: {label}")
                        if preserve_flags and flags:
                            for flag in flags.split():
                                safe_print(f"    -> Applied flag: {flag}")
                    elif preserve_flags and flags:
                        sync_flags_on_existing(dest, label_folder, msg_id, flags, size)
                except Exception as e:
                    safe_print(f"  -> Error applying label {label}: {e}")

        deleted = 0
        if delete_from_source:
            if trash_folder and folder_name != trash_folder:
                try:
                    src.uid("copy", uid, f'"{trash_folder}"')
                except Exception as e:
                    safe_print(f"[{folder_name}] WARNING: Failed to copy UID {uid_str} to trash: {e}")
            src.uid(imap_common.CMD_STORE, uid, imap_common.OP_ADD_FLAGS, imap_common.FLAG_DELETED_LITERAL)
            deleted = 1

        return (True, src, dest, deleted)

    except Exception as e:
        if imap_oauth2.is_auth_error(e):
            safe_print(f"[{folder_name}] Auth error for UID {uid_str}, will retry...")
            return (False, src, dest, 0)
        else:
            safe_print(f"[{folder_name}] ERROR Exec | UID {uid_str}: {e}")
            return (True, src, dest, 0)


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
    check_duplicate=True,
):
    src, dest = get_thread_connections(src_conf, dest_conf)
    if not src or not dest:
        safe_print("Error: Could not establish connections in worker thread.")
        return

    try:
        src.select(f'"{folder_name}"', readonly=False)
    except Exception as e:
        safe_print(f"Error selecting folder {folder_name} in worker: {e}")
        return

    if not gmail_mode:
        try:
            imap_common.ensure_folder_exists(dest, folder_name)
            dest.select(f'"{folder_name}"')
        except Exception as e:
            safe_print(f"Error selecting folder {folder_name} in worker: {e}")
            return

    deleted_count = 0

    for uid in uids:
        uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)
        max_retries = 2

        for attempt in range(max_retries):
            src, src_ok = imap_session.ensure_folder_session(src, src_conf, folder_name, readonly=False)
            thread_local.src = src
            if not src_ok:
                safe_print(f"[{folder_name}] ERROR: Source connection/folder lost for UID {uid_str}")
                return

            if not gmail_mode:
                dest, dest_ok = imap_session.ensure_folder_session(dest, dest_conf, folder_name, readonly=False)
                thread_local.dest = dest
                if not dest_ok:
                    safe_print(f"[{folder_name}] ERROR: Dest connection/folder lost for UID {uid_str}")
                    return
            else:
                dest = imap_session.ensure_connection(dest, dest_conf)
                thread_local.dest = dest
                if not dest:
                    safe_print(f"[{folder_name}] ERROR: Dest connection lost for UID {uid_str}")
                    return

            success, src, dest, deleted = process_single_uid(
                src,
                dest,
                uid,
                folder_name,
                delete_from_source,
                trash_folder,
                preserve_flags,
                gmail_mode,
                label_index,
                check_duplicate,
            )
            thread_local.src = src
            thread_local.dest = dest
            deleted_count += deleted

            if success:
                break
            if attempt < max_retries - 1:
                src = None
                dest = None
                thread_local.src = None
                thread_local.dest = None

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

    # Pre-fetch destination Message-IDs for fast duplicate detection (non-Gmail mode only)
    dest_msg_ids = None
    if not gmail_mode:
        safe_print(f"Pre-fetching destination Message-IDs for {folder_name}...")
        dest_uid_to_msgid = imap_common.get_message_ids_in_folder(dest)
        dest_msg_ids = set(dest_uid_to_msgid.values())
        safe_print(f"Found {len(dest_msg_ids)} existing messages in destination.")

    # Pre-fetch source Message-IDs and filter out duplicates before processing
    # Skip pre-filtering when preserve_flags is True (need to sync flags on duplicates)
    uids_to_process = uids
    src_msg_ids = None
    skipped_duplicate_uids = []
    pre_filtered = False
    if not gmail_mode and dest_msg_ids is not None and not preserve_flags:
        pre_filtered = True
        safe_print(f"Pre-fetching source Message-IDs for {folder_name}...")
        # Use get_uid_to_message_id_map directly since we already have UIDs from folder select
        src_uid_to_msgid = imap_common.get_uid_to_message_id_map(src, uids)
        src_msg_ids = set(src_uid_to_msgid.values())

        # Filter to only UIDs that need migration (not already in destination)
        uids_to_process = []
        for uid in uids:
            msg_id = src_uid_to_msgid.get(uid)
            if msg_id not in dest_msg_ids:
                uids_to_process.append(uid)
            else:
                skipped_duplicate_uids.append(uid)
        safe_print(f"Skipping {len(skipped_duplicate_uids)} duplicates, {len(uids_to_process)} to migrate.")
    elif dest_delete and gmail_mode:
        safe_print("Warning: --dest-delete is not supported in --gmail-mode; ignoring.")

    if not uids_to_process:
        safe_print(f"No new messages to migrate in {folder_name}.")
        if dest_delete and src_msg_ids is not None:
            safe_print("Syncing destination: removing emails not in source...")
            delete_orphan_emails(dest, folder_name, src_msg_ids, dest_uid_to_msgid)
        return

    # Create batches from filtered UIDs
    uid_batches = [uids_to_process[i : i + BATCH_SIZE] for i in range(0, len(uids_to_process), BATCH_SIZE)]

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = []
        # When pre-filtered, we know UIDs are non-duplicates; otherwise need to check
        check_duplicate = not pre_filtered
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
                    check_duplicate,
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
        # Delete skipped duplicates from source (already exist in destination)
        if skipped_duplicate_uids:
            safe_print(f"Deleting {len(skipped_duplicate_uids)} duplicates from source...")
            try:
                src.select(f'"{folder_name}"', readonly=False)
                for uid in skipped_duplicate_uids:
                    src.uid(imap_common.CMD_STORE, uid, imap_common.OP_ADD_FLAGS, imap_common.FLAG_DELETED_LITERAL)
            except Exception as e:
                safe_print(f"Error deleting duplicates: {e}")

        safe_print(f"Expunging deleted messages from {folder_name}...")
        try:
            src.select(f'"{folder_name}"', readonly=False)
            src.expunge()
        except Exception as e:
            safe_print(f"Error Expunging: {e}")

    # Delete orphan emails from destination if enabled
    if dest_delete and src_msg_ids is not None and not gmail_mode:
        safe_print("Syncing destination: removing emails not in source...")
        delete_orphan_emails(dest, folder_name, src_msg_ids, dest_uid_to_msgid)


def main():
    parser = argparse.ArgumentParser(description="Migrate emails between IMAP accounts.")

    # Positional arg for folder (optional) to keep backward compatibility with previous quick-fix
    parser.add_argument("folder", nargs="?", help="Specific folder to migrate (e.g. '[Gmail]/Important')")

    # Source args
    default_src_host = os.getenv("SRC_IMAP_HOST")
    default_src_user = os.getenv("SRC_IMAP_USERNAME")
    default_src_pass = os.getenv("SRC_IMAP_PASSWORD")
    default_src_client_id = os.getenv("SRC_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--src-host",
        default=default_src_host,
        required=not bool(default_src_host),
        help="Source IMAP Host (or SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--src-user",
        default=default_src_user,
        required=not bool(default_src_user),
        help="Source Username (or SRC_IMAP_USERNAME)",
    )
    src_auth_required = not bool(default_src_pass or default_src_client_id)
    src_auth = parser.add_mutually_exclusive_group(required=src_auth_required)
    src_auth.add_argument("--src-pass", default=default_src_pass, help="Source Password (or SRC_IMAP_PASSWORD)")
    src_auth.add_argument(
        "--src-oauth2-client-id",
        default=default_src_client_id,
        dest="src_client_id",
        help="Source OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        default=os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        dest="src_client_secret",
        help="Source OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )

    # Dest args
    default_dest_host = os.getenv("DEST_IMAP_HOST")
    default_dest_user = os.getenv("DEST_IMAP_USERNAME")
    default_dest_pass = os.getenv("DEST_IMAP_PASSWORD")
    default_dest_client_id = os.getenv("DEST_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--dest-host",
        default=default_dest_host,
        required=not bool(default_dest_host),
        help="Destination IMAP Host (or DEST_IMAP_HOST)",
    )
    parser.add_argument(
        "--dest-user",
        default=default_dest_user,
        required=not bool(default_dest_user),
        help="Destination Username (or DEST_IMAP_USERNAME)",
    )
    dest_auth_required = not bool(default_dest_pass or default_dest_client_id)
    dest_auth = parser.add_mutually_exclusive_group(required=dest_auth_required)
    dest_auth.add_argument(
        "--dest-pass",
        default=default_dest_pass,
        help="Destination Password (or DEST_IMAP_PASSWORD)",
    )
    dest_auth.add_argument(
        "--dest-oauth2-client-id",
        default=default_dest_client_id,
        dest="dest_client_id",
        help="Destination OAuth2 Client ID (or DEST_OAUTH2_CLIENT_ID)",
    )
    dest_auth.add_argument(
        "--dest-client-id",
        default=default_dest_client_id,
        dest="dest_client_id",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dest-oauth2-client-secret",
        default=os.getenv("DEST_OAUTH2_CLIENT_SECRET"),
        dest="dest_client_secret",
        help="Destination OAuth2 Client Secret (if required) (or DEST_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--dest-client-secret",
        default=os.getenv("DEST_OAUTH2_CLIENT_SECRET"),
        dest="dest_client_secret",
        help=argparse.SUPPRESS,
    )

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

    src_use_oauth2 = bool(args.src_client_id)
    dest_use_oauth2 = bool(args.dest_client_id)

    # Acquire OAuth2 tokens if configured
    src_oauth2_token = None
    src_oauth2_provider = None
    if src_use_oauth2:
        src_oauth2_provider = imap_oauth2.detect_oauth2_provider(SRC_HOST)
        if not src_oauth2_provider:
            print(f"Error: Could not detect OAuth2 provider from host '{SRC_HOST}'.")
            sys.exit(1)
        print(f"Acquiring OAuth2 token for source ({src_oauth2_provider})...")
        src_oauth2_token = imap_oauth2.acquire_oauth2_token_for_provider(
            src_oauth2_provider, args.src_client_id, SRC_USER, args.src_client_secret
        )
        if not src_oauth2_token:
            print("Error: Failed to acquire OAuth2 token for source.")
            sys.exit(1)
        print("Source OAuth2 token acquired successfully.\n")

    dest_oauth2_token = None
    dest_oauth2_provider = None
    if dest_use_oauth2:
        dest_oauth2_provider = imap_oauth2.detect_oauth2_provider(DEST_HOST)
        if not dest_oauth2_provider:
            print(f"Error: Could not detect OAuth2 provider from host '{DEST_HOST}'.")
            sys.exit(1)
        print(f"Acquiring OAuth2 token for destination ({dest_oauth2_provider})...")
        dest_oauth2_token = imap_oauth2.acquire_oauth2_token_for_provider(
            dest_oauth2_provider, args.dest_client_id, DEST_USER, args.dest_client_secret
        )
        if not dest_oauth2_token:
            print("Error: Failed to acquire OAuth2 token for destination.")
            sys.exit(1)
        print("Destination OAuth2 token acquired successfully.\n")

    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {SRC_HOST}")
    print(f"Source User     : {SRC_USER}")
    print(
        f"Source Auth     : {'OAuth2/' + src_oauth2_provider + ' (XOAUTH2)' if src_use_oauth2 else 'Basic (password)'}"
    )
    print(f"Destination Host: {DEST_HOST}")
    print(f"Destination User: {DEST_USER}")
    print(
        f"Destination Auth: {'OAuth2/' + dest_oauth2_provider + ' (XOAUTH2)' if dest_use_oauth2 else 'Basic (password)'}"
    )
    print(f"Delete fm Source: {DELETE_SOURCE}")
    print(f"Dest Delete     : {DEST_DELETE}")
    print(f"Preserve Flags  : {preserve_flags}")
    print(f"Gmail Mode      : {gmail_mode}")
    if TARGET_FOLDER:
        print(f"Target Folder   : {TARGET_FOLDER}")
    print("-----------------------------\n")

    # Use dicts so token updates propagate to worker threads
    src_conf = {
        "host": SRC_HOST,
        "user": SRC_USER,
        "password": SRC_PASS,
        "oauth2_token": src_oauth2_token,
        "oauth2": {
            "provider": src_oauth2_provider,
            "client_id": args.src_client_id,
            "email": SRC_USER,
            "client_secret": args.src_client_secret,
        }
        if src_use_oauth2
        else None,
    }
    dest_conf = {
        "host": DEST_HOST,
        "user": DEST_USER,
        "password": DEST_PASS,
        "oauth2_token": dest_oauth2_token,
        "oauth2": {
            "provider": dest_oauth2_provider,
            "client_id": args.dest_client_id,
            "email": DEST_USER,
            "client_secret": args.dest_client_secret,
        }
        if dest_use_oauth2
        else None,
    }

    try:
        # Initial connection to list folders
        safe_print("Connecting to Source to list folders...")
        src_main = imap_common.get_imap_connection_from_conf(src_conf)
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
        dest_main = imap_common.get_imap_connection_from_conf(dest_conf)
        if not dest_main:
            sys.exit(1)

        label_index = None
        if gmail_mode and preserve_labels:
            safe_print("Gmail mode enabled: building label index from source...")
            label_index = provider_gmail.build_gmail_label_index(src_main, safe_print)
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
                if provider_gmail.GMAIL_ALL_MAIL not in folders:
                    safe_print(
                        "Warning: --gmail-mode requested but source does not have [Gmail]/All Mail. Falling back to normal folder migration."
                    )
                    gmail_mode = False
                else:
                    migrate_folder(
                        src_main,
                        dest_main,
                        provider_gmail.GMAIL_ALL_MAIL,
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
                    if provider_exchange.is_special_folder(name):
                        safe_print(f"Skipping Exchange system folder: {name}")
                        continue

                    src_main = imap_session.ensure_connection(src_main, src_conf)
                    if not src_main:
                        safe_print("Fatal: Could not reconnect to source IMAP server. Aborting.")
                        sys.exit(1)
                    dest_main = imap_session.ensure_connection(dest_main, dest_conf)
                    if not dest_main:
                        safe_print("Fatal: Could not reconnect to destination IMAP server. Aborting.")
                        sys.exit(1)

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
