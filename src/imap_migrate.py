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
- Cached Incremental Migration (--migrate-cache):
    - Uses a local JSON cache to track migrated Message-IDs.
    - Dramatically speeds up re-runs by skipping already processed emails without server checks.
    - Use --full-migrate to ignore cache skipping (force check) while still updating cache.

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
    python3 imap_migrate.py \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Migrate only one folder (positional argument)
    python3 imap_migrate.py "INBOX" \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Preserve IMAP flags (read/starred/answered/draft). If the message already exists on the
    # destination, missing flags may be synced on it.
    python3 imap_migrate.py \
        --preserve-flags \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Sync mode: delete emails from dest that aren't in the source folder (non-Gmail-mode only)
    python3 imap_migrate.py --dest-delete \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Move instead of copy: delete from source after successful migration
    python3 imap_migrate.py \
        --src-delete \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Gmail mode (recommended for Gmail -> Gmail): migrates only "[Gmail]/All Mail" and
    # applies labels by copying messages into label folders.
    python3 imap_migrate.py \
        --gmail-mode \
        --src-host "imap.gmail.com" \
        --src-user "source@gmail.com" \
        --src-pass "SOURCE_APP_PASSWORD" \
        --dest-host "imap.gmail.com" \
        --dest-user "dest@gmail.com" \
        --dest-pass "DEST_APP_PASSWORD"

    # Cached Incremental Migration (Recommended for large accounts):
    # Uses a local cache to track progress and skip already migrated emails.
    python3 imap_migrate.py \
        --migrate-cache "./migration_cache" \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"
"""

import argparse
import concurrent.futures
import os
import re
import sys
import threading
from typing import Optional

import imap_common
import imap_oauth2
import imap_session
import provider_exchange
import provider_gmail
import restore_cache

# Configuration defaults
DELETE_FROM_SOURCE_DEFAULT = False
MAX_WORKERS = 10  # Initial default, updated in main
BATCH_SIZE = 10  # Initial default, updated in main

# Thread-local storage for IMAP connections
thread_local = threading.local()
safe_print = imap_common.safe_print


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


def pre_filter_uids(src, uids, dest_msg_ids, folder_name):
    """Filter out UIDs whose Message-IDs already exist in the destination.

    Returns:
        Tuple of (uids_to_process, src_msg_ids, skipped_duplicate_uids)
    """
    safe_print(f"Pre-fetching source Message-IDs for {folder_name}...")
    src_uid_to_msgid = imap_common.get_uid_to_message_id_map(src, uids)
    src_msg_ids = set(src_uid_to_msgid.values())

    uids_to_process = []
    skipped_duplicate_uids = []
    for uid in uids:
        msg_id = src_uid_to_msgid.get(uid)
        if msg_id not in dest_msg_ids:
            uids_to_process.append(uid)
        else:
            skipped_duplicate_uids.append(uid)
    safe_print(f"Skipping {len(skipped_duplicate_uids)} duplicates, {len(uids_to_process)} to migrate.")
    return uids_to_process, src_msg_ids, skipped_duplicate_uids


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
    full_migrate: bool = False,
    existing_dest_msg_ids_by_folder: Optional[dict[str, set[str]]] = None,
    existing_dest_msg_ids_lock: Optional[threading.Lock] = None,
    progress_cache_path: Optional[str] = None,
    progress_cache_data: Optional[dict] = None,
    progress_cache_lock: Optional[threading.Lock] = None,
    dest_host: Optional[str] = None,
    dest_user: Optional[str] = None,
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
            target_folder, remaining_labels = provider_gmail.resolve_target(labels)
        else:
            target_folder = folder_name

        is_duplicate = False

        # Fast path: check source folder cache to skip without any IMAP ops
        cached_dest_msg_ids = (
            existing_dest_msg_ids_by_folder.get(folder_name) if existing_dest_msg_ids_by_folder else None
        )
        cache_hit = False
        if not full_migrate and msg_id and cached_dest_msg_ids is not None:
            if existing_dest_msg_ids_lock is not None:
                with existing_dest_msg_ids_lock:
                    cache_hit = msg_id in cached_dest_msg_ids
            else:
                cache_hit = msg_id in cached_dest_msg_ids

        if cache_hit:
            is_duplicate = True
            safe_print(f"[{target_folder}] SKIP (cached) | {size_str:<8} | {subject[:40]}")
        elif msg_id and check_duplicate:
            # Check target folder using pre-fetched Message-ID set (one-time fetch per folder)
            target_msg_ids = imap_common.load_folder_msg_ids(
                dest,
                target_folder,
                existing_dest_msg_ids_by_folder,
                existing_dest_msg_ids_lock,
                progress_cache_data,
                progress_cache_lock,
                dest_host,
                dest_user,
            )
            if target_msg_ids is not None and msg_id in target_msg_ids:
                is_duplicate = True
                safe_print(f"[{target_folder}] SKIP (exists) | {size_str:<8} | {subject[:40]}")

        if is_duplicate:
            if preserve_flags and flags and msg_id:
                imap_common.sync_flags_on_existing(dest, target_folder, msg_id, flags, size)
        else:
            valid_flags = f"({flags})" if (preserve_flags and flags) else None
            success = imap_common.append_email(
                dest,
                target_folder,
                msg_content,
                date_str,
                valid_flags,
                ensure_folder=False,
            )
            if success:
                safe_print(f"[{target_folder}] {'COPIED':<12} | {size_str:<8} | {subject[:40]}")
                if preserve_flags and flags:
                    for flag in flags.split():
                        safe_print(f"  -> Applied flag: {flag}")
            else:
                safe_print(f"[{target_folder}] FAILED        | {size_str:<8} | {subject[:40]}")

        # Update cache if processed effectively (copied or duplicate)
        if msg_id:
            cached_dest_msg_ids = (
                existing_dest_msg_ids_by_folder.get(folder_name) if existing_dest_msg_ids_by_folder else None
            )
            restore_cache.record_progress(
                message_id=msg_id,
                folder_name=folder_name,
                existing_dest_msg_ids=cached_dest_msg_ids,
                existing_dest_msg_ids_lock=existing_dest_msg_ids_lock,
                progress_cache_path=progress_cache_path,
                progress_cache_data=progress_cache_data,
                progress_cache_lock=progress_cache_lock,
                dest_host=dest_host,
                dest_user=dest_user,
                log_fn=safe_print,
            )

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
                    # Get or fetch Message-IDs for label folder (one-time server fetch per folder)
                    label_folder_msg_ids = imap_common.load_folder_msg_ids(
                        dest,
                        label_folder,
                        existing_dest_msg_ids_by_folder,
                        existing_dest_msg_ids_lock,
                        progress_cache_data,
                        progress_cache_lock,
                        dest_host,
                        dest_user,
                    )

                    # Check duplicate using pre-fetched set instead of per-message SEARCH
                    label_already_exists = label_folder_msg_ids is not None and msg_id in label_folder_msg_ids

                    if not label_already_exists:
                        valid_flags = f"({flags})" if (preserve_flags and flags) else None
                        if imap_common.append_email(
                            dest,
                            label_folder,
                            msg_content,
                            date_str,
                            valid_flags,
                            ensure_folder=False,
                        ):
                            # Update in-memory set so subsequent emails see this one
                            if label_folder_msg_ids is not None and existing_dest_msg_ids_lock is not None:
                                with existing_dest_msg_ids_lock:
                                    label_folder_msg_ids.add(msg_id)
                            safe_print(f"  -> Applied label: {label}")
                            if preserve_flags and flags:
                                for flag in flags.split():
                                    safe_print(f"    -> Applied flag: {flag}")
                        else:
                            safe_print(f"  -> Failed to apply label {label}")
                    elif preserve_flags and flags:
                        imap_common.sync_flags_on_existing(dest, label_folder, msg_id, flags, size)
                except Exception as e:
                    if imap_oauth2.is_auth_error(e):
                        raise
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
    full_migrate=False,
    existing_dest_msg_ids_by_folder: Optional[dict[str, set[str]]] = None,
    existing_dest_msg_ids_lock: Optional[threading.Lock] = None,
    progress_cache_path: Optional[str] = None,
    progress_cache_data: Optional[dict] = None,
    progress_cache_lock: Optional[threading.Lock] = None,
):
    src = imap_session.get_thread_connection(thread_local, "src", src_conf)
    dest = imap_session.get_thread_connection(thread_local, "dest", dest_conf)
    if not src or not dest:
        safe_print("Error: Could not establish connections in worker thread.")
        return False, 0

    try:
        src.select(f'"{folder_name}"', readonly=False)
    except Exception as e:
        safe_print(f"Error selecting folder {folder_name} in worker: {e}")
        return False, 0

    # Extract info for cache update if needed
    dest_host = dest_conf.get("host")
    dest_user = dest_conf.get("user")

    deleted_count = 0
    max_uid_processed = 0

    for uid in uids:
        uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)

        # Track max UID seen in this batch
        try:
            uid_int = int(uid_str)
            if uid_int > max_uid_processed:
                max_uid_processed = uid_int
        except ValueError:
            pass

        max_retries = 2

        for attempt in range(max_retries):
            src, src_ok = imap_session.ensure_folder_session(src, src_conf, folder_name, readonly=False)
            thread_local.src = src
            if not src_ok:
                safe_print(f"[{folder_name}] ERROR: Source connection/folder lost for UID {uid_str}")
                return False, 0

            dest = imap_session.ensure_connection(dest, dest_conf)
            thread_local.dest = dest
            if not dest:
                safe_print(f"[{folder_name}] ERROR: Dest connection lost for UID {uid_str}")
                return False, 0

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
                full_migrate,
                existing_dest_msg_ids_by_folder=existing_dest_msg_ids_by_folder,
                existing_dest_msg_ids_lock=existing_dest_msg_ids_lock,
                progress_cache_path=progress_cache_path,
                progress_cache_data=progress_cache_data,
                progress_cache_lock=progress_cache_lock,
                dest_host=dest_host,
                dest_user=dest_user,
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

    return True, max_uid_processed


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
    progress_cache_path: Optional[str] = None,
    full_migrate=False,
    progress_cache_file: Optional[str] = None,
    progress_cache_data: Optional[dict] = None,
    progress_cache_lock: Optional[threading.Lock] = None,
):
    safe_print(f"--- Preparing Folder: {folder_name} ---")

    # Load cache if provided
    existing_dest_msg_ids_by_folder: Optional[dict[str, set[str]]] = {}
    existing_dest_msg_ids_lock: Optional[threading.Lock] = threading.Lock()
    dest_host = dest_conf.get("host")
    dest_user = dest_conf.get("user")
    cache_file = progress_cache_file

    if progress_cache_path:
        if progress_cache_data is None or progress_cache_lock is None or cache_file is None:
            try:
                cache_file, progress_cache_data, progress_cache_lock = imap_common.load_progress_cache(
                    progress_cache_path,
                    dest_host,
                    dest_user,
                    log_fn=safe_print,
                )
            except Exception as e:
                safe_print(f"Warning: Failed to load cache: {e}")

        if imap_common.is_progress_cache_ready(progress_cache_data, progress_cache_lock):
            try:
                cache_ids = restore_cache.get_cached_message_ids(
                    progress_cache_data,
                    progress_cache_lock,
                    dest_host,
                    dest_user,
                    folder_name,
                )
                existing_dest_msg_ids_by_folder[folder_name] = cache_ids
                safe_print(f"Cache has {len(cache_ids)} Message-IDs for this folder.")
            except Exception as e:
                safe_print(f"Warning: Failed to read cache for folder '{folder_name}': {e}")
                existing_dest_msg_ids_by_folder[folder_name] = set()

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

    # Get Current UIDVALIDITY (for resume check)
    current_validity = None
    try:
        typ, val_data = src.response("UIDVALIDITY")
        if val_data:
            current_validity = int(val_data[0])
    except Exception:
        pass

    start_uid = 0
    if not full_migrate and current_validity and progress_cache_data:
        try:
            src_data = restore_cache.get_source_data(progress_cache_data, folder_name)
            if src_data and src_data.get("uid_validity") == current_validity:
                start_uid = src_data.get("last_uid", 0) or 0
                if start_uid > 0:
                    safe_print(
                        f"Resuming {folder_name} from Source UID > {start_uid} (UIDVALIDITY: {current_validity})"
                    )
        except Exception:
            pass

    # Get UIDs
    # Search for UNDELETED to avoid processing messages marked for deletion but not yet expunged
    resp, data = src.uid("search", None, "UNDELETED")
    if resp != "OK":
        return

    uids = data[0].split()
    total = len(uids)

    # Filter UIDs if resuming
    if start_uid > 0:
        filtered = []
        for u in uids:
            try:
                if int(u) > start_uid:
                    filtered.append(u)
            except ValueError:
                filtered.append(u)
        uids = filtered
        safe_print(f"Filtered to {len(uids)} new UIDs (was {total}).")

    if not uids:
        safe_print(f"Folder {folder_name} is up to date (no new UIDs).")
        # Do not perform dest_delete if we filtered or found nothing via resume,
        # as we don't have the full source picture.
        if dest_delete and start_uid == 0:
            safe_print("Checking destination for orphan emails to delete...")
            imap_common.delete_orphan_emails(dest, folder_name, set())
        return

    # Pre-fetch destination Message-IDs for fast duplicate detection (non-Gmail mode only)
    dest_msg_ids = None
    if not gmail_mode:
        safe_print(f"Pre-fetching destination Message-IDs for {folder_name}...")
        dest_uid_to_msgid = imap_common.get_message_ids_in_folder(dest)
        dest_msg_ids = set(dest_uid_to_msgid.values())
        # Update destination Message-IDs with what we processed
        if not full_migrate:
            existing_dest_msg_ids_by_folder.setdefault(folder_name, set()).update(dest_msg_ids)
        else:
            existing_dest_msg_ids_by_folder[folder_name] = dest_msg_ids
        dest_msg_ids = existing_dest_msg_ids_by_folder[folder_name]
        safe_print(f"Found {len(dest_msg_ids)} existing messages in destination (server + cache).")

    # Pre-fetch source Message-IDs and filter out duplicates before processing
    # Skip pre-filtering when preserve_flags is True (need to sync flags on duplicates)
    uids_to_process = uids
    src_msg_ids = None
    skipped_duplicate_uids = []
    pre_filtered = False
    if not gmail_mode and dest_msg_ids is not None and not preserve_flags:
        pre_filtered = True
        uids_to_process, src_msg_ids, skipped_duplicate_uids = pre_filter_uids(src, uids, dest_msg_ids, folder_name)
    elif dest_delete and gmail_mode:
        safe_print("Warning: --dest-delete is not supported in --gmail-mode; ignoring.")

    if not uids_to_process:
        safe_print(f"No new messages to migrate in {folder_name}.")
        # Only support orphan delete if we have full user list (no start_uid resume)
        if dest_delete and src_msg_ids is not None and start_uid == 0:
            safe_print("Syncing destination: removing emails not in source...")
            imap_common.delete_orphan_emails(dest, folder_name, src_msg_ids, dest_uid_to_msgid)
        # Still deleting skipped duplicates from source is valid?
        # Only if we aren't resuming? If skipping duplicates, we found duplicates.
        # But we return here.
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
                    full_migrate,
                    existing_dest_msg_ids_by_folder,
                    existing_dest_msg_ids_lock,
                    cache_file,
                    progress_cache_data,
                    progress_cache_lock,
                )
            )

        # Wait for all batches to complete and update watermark
        should_update_watermark = True

        for future in futures:
            try:
                success, batch_max_uid = future.result()
                if success:
                    if should_update_watermark and current_validity and progress_cache_data and batch_max_uid > 0:
                        restore_cache.record_source_progress(
                            folder_name=folder_name,
                            uid_validity=current_validity,
                            last_uid=batch_max_uid,
                            progress_cache_path=cache_file,
                            progress_cache_data=progress_cache_data,
                            progress_cache_lock=progress_cache_lock,
                            log_fn=safe_print,
                        )
                else:
                    should_update_watermark = False
            except Exception as e:
                safe_print(f"Batch Error: {e}")
                should_update_watermark = False
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
        imap_common.delete_orphan_emails(dest, folder_name, src_msg_ids, dest_uid_to_msgid)

    # Force-flush progress cache at end of folder migration.
    if cache_file and imap_common.is_progress_cache_ready(progress_cache_data, progress_cache_lock):
        restore_cache.maybe_save_dest_index_cache(cache_file, progress_cache_data, progress_cache_lock, force=True)


def main():
    parser = argparse.ArgumentParser(description="Migrate emails between IMAP accounts.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")

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

    parser.add_argument(
        "--migrate-cache",
        help="Path to directory for migration progress cache (enables incremental migration)",
    )
    parser.add_argument(
        "--full-migrate",
        action="store_true",
        help="Force full migration (ignore cache for skipping), but still update cache if --migrate-cache provided",
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
    migrate_cache = args.migrate_cache
    full_migrate = args.full_migrate
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

    # Build connection configs (acquires OAuth2 tokens if configured)
    src_conf = imap_session.build_imap_conf(
        SRC_HOST, SRC_USER, SRC_PASS, args.src_client_id, args.src_client_secret, "source"
    )
    dest_conf = imap_session.build_imap_conf(
        DEST_HOST, DEST_USER, DEST_PASS, args.dest_client_id, args.dest_client_secret, "destination"
    )

    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {SRC_HOST}")
    print(f"Source User     : {SRC_USER}")
    print(f"Source Auth     : {imap_oauth2.auth_description(src_conf['oauth2'] and src_conf['oauth2']['provider'])}")
    print(f"Destination Host: {DEST_HOST}")
    print(f"Destination User: {DEST_USER}")
    print(f"Destination Auth: {imap_oauth2.auth_description(dest_conf['oauth2'] and dest_conf['oauth2']['provider'])}")
    print(f"Delete fm Source: {DELETE_SOURCE}")
    print(f"Dest Delete     : {DEST_DELETE}")
    print(f"Preserve Flags  : {preserve_flags}")
    print(f"Gmail Mode      : {gmail_mode}")
    if TARGET_FOLDER:
        print(f"Target Folder   : {TARGET_FOLDER}")
    print("-----------------------------\n")

    progress_cache_file = None
    progress_cache_data = None
    progress_cache_lock = None
    if migrate_cache:
        try:
            progress_cache_file, progress_cache_data, progress_cache_lock = imap_common.load_progress_cache(
                migrate_cache,
                DEST_HOST,
                DEST_USER,
                log_fn=safe_print,
            )
        except Exception as e:
            safe_print(f"Warning: Failed to load progress cache: {e}")

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
                progress_cache_path=migrate_cache,
                full_migrate=full_migrate,
                progress_cache_file=progress_cache_file,
                progress_cache_data=progress_cache_data,
                progress_cache_lock=progress_cache_lock,
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
                        progress_cache_path=migrate_cache,
                        full_migrate=full_migrate,
                        progress_cache_file=progress_cache_file,
                        progress_cache_data=progress_cache_data,
                        progress_cache_lock=progress_cache_lock,
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
                        progress_cache_path=migrate_cache,
                        full_migrate=full_migrate,
                        progress_cache_file=progress_cache_file,
                        progress_cache_data=progress_cache_data,
                        progress_cache_lock=progress_cache_lock,
                    )

        src_main.logout()
        dest_main.logout()

    except KeyboardInterrupt:
        raise


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        safe_print("\n\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        safe_print(f"Fatal Error: {e}")
        sys.exit(1)
