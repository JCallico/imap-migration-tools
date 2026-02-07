"""
IMAP Email Restore Script

Restores emails from a local backup to an IMAP account.
Reads .eml files from a local directory and uploads them to the destination server.

Features:
- Folder Restoration: Recreates the folder structure from the backup.
- Gmail Labels Restoration: Uses labels_manifest.json to apply Gmail labels.
- Incremental Restore: Skips emails that already exist (based on Message-ID).
- Parallel Processing: Uses multithreading for fast uploads.
- Date Preservation: Restores emails with their original dates.

Configuration (Environment Variables):
    DEST_IMAP_HOST, DEST_IMAP_USERNAME: Destination credentials.
    DEST_IMAP_PASSWORD: Destination password (or App Password).

    OAuth2 (Optional - instead of password):
    DEST_OAUTH2_CLIENT_ID: OAuth2 Client ID
    DEST_OAUTH2_CLIENT_SECRET: OAuth2 Client Secret (required for Google)

  BACKUP_LOCAL_PATH: Source local directory containing the backup.
  MAX_WORKERS: Number of concurrent threads (default: 4).
  BATCH_SIZE: Number of emails to process per batch (default: 10).
  APPLY_LABELS: Set to "true" to apply Gmail labels from manifest. Default is "false".
  APPLY_FLAGS: Set to "true" to apply IMAP flags from manifest. Default is "false".
  GMAIL_MODE: Set to "true" for Gmail restore mode. Default is "false".
  DEST_DELETE: Set to "true" to delete emails from destination not found in local backup.
              Default is "false".

Usage:
    python3 restore_imap_emails.py \
        --src-path "./my_backup" \
        --dest-host "imap.gmail.com" \
        --dest-user "you@gmail.com" \
        --dest-pass "your-app-password"

Gmail Labels Restoration:
    python3 restore_imap_emails.py \
        --src-path "./gmail_backup" \
        --dest-host "imap.gmail.com" \
        --dest-user "you@gmail.com" \
        --dest-pass "your-app-password" \
        --apply-labels
  This uploads emails and applies labels from labels_manifest.json to recreate
  the original Gmail label structure.
"""

import argparse
import concurrent.futures
import json
import os
import sys
import threading
import time
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Optional

import imap_common
import imap_oauth2
import imap_session
import provider_gmail
import restore_cache


class UploadResult(Enum):
    """Result of an email upload operation."""

    SUCCESS = "success"
    ALREADY_EXISTS = "already_exists"
    FAILURE = "failure"


# Defaults
MAX_WORKERS = 4  # Lower default for restore to avoid rate limits
BATCH_SIZE = 10

# Thread-local storage
thread_local = threading.local()
print_lock = threading.Lock()


def safe_print(message):
    t_name = threading.current_thread().name
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with print_lock:
        print(f"[{short_name}] {message}")


def get_thread_connection(dest_conf):
    """Get or create a thread-local IMAP connection."""
    thread_local.dest = imap_session.ensure_connection(getattr(thread_local, "dest", None), dest_conf)
    return thread_local.dest


def load_labels_manifest(local_path):
    """
    Loads the labels manifest from the backup directory.
    Returns the manifest dict or empty dict if not found.
    """
    manifest_path = os.path.join(local_path, "labels_manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
                safe_print(f"Loaded labels manifest with {len(manifest)} entries.")
                return manifest
        except Exception as e:
            safe_print(f"Warning: Could not load labels manifest: {e}")
    return {}


def load_flags_manifest(local_path):
    """
    Loads the flags manifest from the backup directory.
    Returns the manifest dict or empty dict if not found.
    """
    manifest_path = os.path.join(local_path, "flags_manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
                safe_print(f"Loaded flags manifest with {len(manifest)} entries.")
                return manifest
        except Exception as e:
            safe_print(f"Warning: Could not load flags manifest: {e}")
    return {}


def get_flags_from_manifest(manifest, message_id):
    """
    Extract IMAP flags string from manifest entry.
    Returns flags string like "\\Seen \\Flagged" or None.
    """
    if not message_id or message_id not in manifest:
        return None

    entry = manifest[message_id]

    if isinstance(entry, dict) and "flags" in entry:
        flags = entry.get("flags", [])
        if flags:
            return " ".join(flags)

    return None


def sync_flags_on_existing(imap_conn, folder_name, message_id, flags, size):
    """
    Sync flags on an existing email in the given folder.
    Finds the email by Message-ID and updates its flags.

    Args:
        imap_conn: IMAP connection
        folder_name: Folder containing the email
        message_id: Message-ID header value
        flags: Space-separated flags string like "\\Seen \\Flagged"
        size: Email size for verification
    """
    try:
        # Select folder
        imap_conn.select(f'"{folder_name}"')

        # Search for the message by Message-ID
        search_id = message_id.strip("<>")
        resp, data = imap_conn.search(None, f'HEADER Message-ID "{search_id}"')

        if resp != "OK" or not data[0]:
            return

        msg_nums = data[0].split()
        if not msg_nums:
            return

        # Use the first matching message
        msg_num = msg_nums[0]

        # Parse flags into a list
        flag_list = flags.split() if flags else []
        if not flag_list:
            return

        # Get current flags
        resp, flag_data = imap_conn.fetch(msg_num, "(FLAGS)")
        if resp != "OK":
            return

        # Check which flags need to be added
        current_flags_str = str(flag_data[0]) if flag_data and flag_data[0] else ""
        flags_to_add = []

        for flag in flag_list:
            # Normalize flag for comparison (case-insensitive)
            if flag.lower() not in current_flags_str.lower():
                flags_to_add.append(flag)

        if flags_to_add:
            # Add missing flags
            flags_str = " ".join(flags_to_add)
            resp, _ = imap_conn.store(msg_num, "+FLAGS", f"({flags_str})")
            if resp == "OK":
                for flag in flags_to_add:
                    safe_print(f"  -> Synced flag: {flag}")

    except Exception as e:
        safe_print(f"  -> Error syncing flags: {e}")


def extract_message_id_from_eml(file_path):
    """
    Extract just the Message-ID from an .eml file efficiently.
    Returns the Message-ID string or None on error.
    """
    try:
        with open(file_path, "rb") as f:
            # Read just the first 64KB to get headers
            header_bytes = f.read(65536)

        msg_id = imap_common.extract_message_id(header_bytes)
        return msg_id
    except Exception:
        return None


def parse_eml_file(file_path):
    """
    Parse an .eml file and extract metadata.
    Returns (message_id, date_str, raw_content, subject) or (None, None, None, None) on error.
    """
    try:
        with open(file_path, "rb") as f:
            raw_content = f.read()

        # Use compat32 to preserve raw headers with continuation lines
        parser = BytesParser(policy=policy.compat32)
        msg = parser.parsebytes(raw_content, headersonly=True)

        message_id = imap_common.decode_message_id(msg.get("Message-ID"))
        raw_subject = msg.get("Subject")
        subject = imap_common.decode_mime_header(raw_subject) if raw_subject else "(No Subject)"
        date_header = msg.get("Date")

        # Parse date for IMAP INTERNALDATE
        date_str = None
        if date_header:
            try:
                dt = parsedate_to_datetime(date_header)
                # Format: "DD-Mon-YYYY HH:MM:SS +ZZZZ"
                date_str = dt.strftime('"%d-%b-%Y %H:%M:%S %z"')
            except Exception:
                pass

        return message_id, date_str, raw_content, subject

    except Exception as e:
        safe_print(f"Error parsing {file_path}: {e}")
        return None, None, None, None


def get_eml_files(folder_path):
    """
    Get all .eml files in a folder.
    Returns list of (file_path, filename) tuples.
    """
    eml_files = []
    if not os.path.exists(folder_path):
        return eml_files

    try:
        for filename in os.listdir(folder_path):
            if filename.endswith(".eml"):
                file_path = os.path.join(folder_path, filename)
                eml_files.append((file_path, filename))
    except Exception as e:
        safe_print(f"Error listing {folder_path}: {e}")

    return eml_files


def email_exists_in_folder(imap_conn, message_id):
    """
    Check if an email with the given Message-ID exists in the currently selected folder.
    """
    if not message_id:
        return False

    try:
        return imap_common.message_exists_in_folder(imap_conn, message_id)
    except Exception:
        return False


def upload_email(dest, folder_name, raw_content, date_str, message_id, flags=None, check_duplicate=True):
    """
    Upload a single email to the destination folder.
    Returns UploadResult enum: SUCCESS, ALREADY_EXISTS, or FAILURE.

    Args:
        flags: Optional string of IMAP flags like "\\Seen" for read emails.
        check_duplicate: Whether to check for duplicates before uploading.
    """
    try:
        # Ensure folder exists
        imap_common.ensure_folder_exists(dest, folder_name)

        # Select folder
        dest.select(f'"{folder_name}"')

        # Check for duplicates if requested
        if check_duplicate and message_id and email_exists_in_folder(dest, message_id):
            return UploadResult.ALREADY_EXISTS

        # Upload with original date and flags
        success = imap_common.append_email(
            dest,
            folder_name,
            raw_content,
            date_str,
            flags,
            ensure_folder=False,
        )
        return UploadResult.SUCCESS if success else UploadResult.FAILURE

    except Exception as e:
        safe_print(f"Error uploading to {folder_name}: {e}")
        return UploadResult.FAILURE


def get_labels_from_manifest(manifest, message_id):
    """
    Get the list of labels for a message from the manifest.
    Returns list of label strings or empty list.
    """
    if not message_id or message_id not in manifest:
        return []

    entry = manifest[message_id]
    if isinstance(entry, dict):
        return entry.get("labels", [])
    elif isinstance(entry, list):
        return entry  # Old format: list of labels
    return []


def label_to_folder(label):
    """
    Convert a Gmail label name to an IMAP folder path.
    """
    if label == imap_common.FOLDER_INBOX:
        return imap_common.FOLDER_INBOX
    elif label in ("Sent Mail", "Starred", "Drafts", "Important"):
        return f"[Gmail]/{label}"
    else:
        return label


def process_restore_batch(
    eml_files,
    folder_name,
    dest_conf,
    manifest,
    apply_labels,
    apply_flags,
    full_restore: bool = False,
    existing_dest_msg_ids_by_folder: Optional[dict[str, set[str]]] = None,
    existing_dest_msg_ids_lock: Optional[threading.Lock] = None,
    progress_cache_data: Optional[dict] = None,
    progress_cache_lock: Optional[threading.Lock] = None,
    progress_cache_path: Optional[str] = None,
    dest_host: Optional[str] = None,
    dest_user: Optional[str] = None,
):
    """
    Process a batch of .eml files for restoration.

    Args:
        folder_name: Target folder, or "__GMAIL_MODE__" for per-email folder selection
        manifest: Combined manifest with labels and/or flags
        apply_labels: Whether to apply Gmail labels from manifest
        apply_flags: Whether to apply IMAP flags from manifest
    """
    dest = get_thread_connection(dest_conf)
    if not dest:
        safe_print("Error: Could not establish connection for batch.")
        return

    gmail_mode = folder_name == "__GMAIL_MODE__"

    for file_path, filename in eml_files:
        # Proactively refresh token if needed
        dest = get_thread_connection(dest_conf)
        if not dest:
            safe_print(f"ERROR: Connection lost for {filename}")
            return

        try:
            message_id, date_str, raw_content, subject = parse_eml_file(file_path)
            if raw_content is None:
                continue  # No content, skip to next file

            size = len(raw_content)
            size_str = f"{size / 1024:.1f}KB"

            # Truncate subject for display
            display_subject = (subject[:40] + "...") if len(subject) > 40 else subject

            # Get flags from manifest if apply_flags is enabled
            flags = None
            if apply_flags:
                flags = get_flags_from_manifest(manifest, message_id)

            # Get labels for this message
            labels = get_labels_from_manifest(manifest, message_id) if apply_labels else []

            # Determine target folder and remaining labels
            if gmail_mode:
                # In Gmail mode, upload to first valid label folder
                # Skip system folders we can't upload to
                skip_folders = {"[Gmail]/All Mail", "[Gmail]/Spam", "[Gmail]/Trash"}

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

                # If no valid label found, use a dedicated label folder as fallback.
                # This avoids placing non-draft messages into Gmail Drafts.
                if target_folder is None:
                    target_folder = imap_common.FOLDER_RESTORED_UNLABELED
                    remaining_labels = []
            else:
                target_folder = folder_name
                remaining_labels = labels

            existing_dest_msg_ids: Optional[set[str]] = None
            if existing_dest_msg_ids_by_folder is not None:
                if existing_dest_msg_ids_lock is None:
                    existing_dest_msg_ids_lock = threading.Lock()

                with existing_dest_msg_ids_lock:
                    existing_dest_msg_ids = existing_dest_msg_ids_by_folder.get(target_folder)

                # Lazy-load per-folder progress cache (no destination scan).
                if existing_dest_msg_ids is None:
                    built: set[str] = set()
                    if progress_cache_data is not None and progress_cache_lock is not None and dest_host and dest_user:
                        built = restore_cache.get_cached_message_ids(
                            progress_cache_data,
                            progress_cache_lock,
                            dest_host,
                            dest_user,
                            target_folder,
                        )
                    with existing_dest_msg_ids_lock:
                        existing_dest_msg_ids_by_folder.setdefault(target_folder, built)
                        existing_dest_msg_ids = existing_dest_msg_ids_by_folder[target_folder]

            # Incremental default: if we already know we processed it before, skip entirely.
            if (
                not full_restore
                and message_id
                and existing_dest_msg_ids is not None
                and message_id in existing_dest_msg_ids
            ):
                safe_print(f"[{target_folder}] SKIP (already present) | {size_str:<8} | {display_subject}")
                continue  # Skip to next file

            # Upload to target folder.
            # Keep server-side duplicate checks enabled to avoid creating duplicates for emails
            # that exist on the destination but are not in our local progress cache.
            upload_result = upload_email(dest, target_folder, raw_content, date_str, message_id, flags)

            # Only record progress when upload succeeds or email already exists.
            # Failed uploads should not be marked as processed to allow retry on next run.
            if upload_result in (UploadResult.SUCCESS, UploadResult.ALREADY_EXISTS):
                restore_cache.record_progress(
                    message_id=message_id,
                    folder_name=target_folder,
                    existing_dest_msg_ids=existing_dest_msg_ids,
                    existing_dest_msg_ids_lock=existing_dest_msg_ids_lock,
                    progress_cache_path=progress_cache_path,
                    progress_cache_data=progress_cache_data,
                    progress_cache_lock=progress_cache_lock,
                    dest_host=dest_host,
                    dest_user=dest_user,
                    log_fn=safe_print,
                )

            if upload_result == UploadResult.ALREADY_EXISTS:
                safe_print(f"[{target_folder}] SKIP (exists) | {size_str:<8} | {display_subject}")
                # Full restore preserves legacy behavior: sync flags on existing email if requested
                if full_restore and apply_flags and flags and message_id:
                    sync_flags_on_existing(dest, target_folder, message_id, flags, size)
            elif upload_result == UploadResult.SUCCESS:
                safe_print(f"[{target_folder}] UPLOADED      | {size_str:<8} | {display_subject}")
                # Show applied flags in same style as labels
                if flags:
                    for flag in flags.split():
                        safe_print(f"  -> Applied flag: {flag}")
            else:  # FAILURE
                safe_print(f"[{target_folder}] FAILED        | {size_str:<8} | {display_subject}")

            # Apply remaining Gmail labels:
            # - Full restore: apply/sync labels even for existing emails
            # - Incremental (default): apply labels only for newly uploaded emails
            if apply_labels and remaining_labels and (upload_result == UploadResult.SUCCESS or full_restore):
                for label in remaining_labels:
                    label_folder = label_to_folder(label)

                    # Skip if this is the same as the target folder
                    if label_folder == target_folder:
                        continue

                    # Skip system folders we can't upload to
                    if label_folder in (
                        provider_gmail.GMAIL_ALL_MAIL,
                        provider_gmail.GMAIL_SPAM,
                        provider_gmail.GMAIL_TRASH,
                    ):
                        continue

                    try:
                        # Ensure label folder exists
                        imap_common.ensure_folder_exists(dest, label_folder)

                        # Select and check for duplicate
                        dest.select(f'"{label_folder}"')
                        if not email_exists_in_folder(dest, message_id):
                            append_success = imap_common.append_email(
                                dest,
                                label_folder,
                                raw_content,
                                date_str,
                                flags,
                                ensure_folder=False,
                            )
                            if append_success:
                                # Look up the correct set for label_folder
                                label_folder_msg_ids: Optional[set[str]] = None
                                if existing_dest_msg_ids_by_folder is not None:
                                    with existing_dest_msg_ids_lock:
                                        label_folder_msg_ids = existing_dest_msg_ids_by_folder.get(label_folder)

                                    # Lazy-load per-folder progress cache if not yet loaded
                                    if label_folder_msg_ids is None:
                                        built: set[str] = set()
                                        if (
                                            progress_cache_data is not None
                                            and progress_cache_lock is not None
                                            and dest_host
                                            and dest_user
                                        ):
                                            built = restore_cache.get_cached_message_ids(
                                                progress_cache_data,
                                                progress_cache_lock,
                                                dest_host,
                                                dest_user,
                                                label_folder,
                                            )
                                        with existing_dest_msg_ids_lock:
                                            existing_dest_msg_ids_by_folder.setdefault(label_folder, built)
                                            label_folder_msg_ids = existing_dest_msg_ids_by_folder[label_folder]

                                restore_cache.record_progress(
                                    message_id=message_id,
                                    folder_name=label_folder,
                                    existing_dest_msg_ids=label_folder_msg_ids,
                                    existing_dest_msg_ids_lock=existing_dest_msg_ids_lock,
                                    progress_cache_path=progress_cache_path,
                                    progress_cache_data=progress_cache_data,
                                    progress_cache_lock=progress_cache_lock,
                                    dest_host=dest_host,
                                    dest_user=dest_user,
                                    log_fn=safe_print,
                                )
                                safe_print(f"  -> Applied label: {label}")
                            else:
                                safe_print(f"  -> Failed to apply label {label} (will retry on next restore)")
                        # If email exists in this label folder, sync flags (full restore only)
                        elif full_restore and apply_flags and flags:
                            sync_flags_on_existing(dest, label_folder, message_id, flags, size)
                    except Exception as e:
                        safe_print(f"  -> Error applying label {label}: {e}")

        except Exception as e:
            safe_print(f"Error processing {filename}: {e}")


def get_local_message_ids(local_folder_path):
    """
    Get a set of Message-IDs from all .eml files in a local folder.
    Used for destination deletion sync.
    """
    message_ids = set()
    eml_files = get_eml_files(local_folder_path)
    for file_path, _filename in eml_files:
        message_id, _, _, _ = parse_eml_file(file_path)
        if message_id:
            message_ids.add(message_id)
    return message_ids


def delete_orphan_emails_from_dest(imap_conn, folder_name, local_msg_ids):
    """
    Delete emails from destination folder that don't exist in local backup.
    Returns count of deleted emails.
    """
    import re

    deleted_count = 0
    try:
        imap_conn.select(f'"{folder_name}"', readonly=False)
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data or not data[0]:
            return 0

        uids = data[0].split()
        if not uids:
            return 0

        # Check each UID's Message-ID against local backup
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
                        msg_id = imap_common.extract_message_id(item[1])

                        # If not in local backup, mark for deletion
                        if msg_id and msg_id not in local_msg_ids:
                            uids_to_delete.append(uid)

            except Exception:
                continue

        # Delete orphan emails
        for uid in uids_to_delete:
            try:
                imap_conn.uid("store", uid, "+FLAGS", "(\\Deleted)")
                deleted_count += 1
            except Exception:
                pass

        if deleted_count > 0:
            imap_conn.expunge()
            safe_print(f"[{folder_name}] Deleted {deleted_count} orphan emails from destination")

    except Exception as e:
        safe_print(f"Error deleting orphans from {folder_name}: {e}")

    return deleted_count


def restore_folder(
    folder_name,
    local_folder_path,
    dest_conf,
    manifest,
    apply_labels,
    apply_flags,
    dest_delete=False,
    full_restore: bool = False,
    cache_root: Optional[str] = None,
):
    """
    Restore all emails from a local folder to the destination IMAP server.
    """
    safe_print(f"--- Restoring Folder: {folder_name} ---")

    eml_files = get_eml_files(local_folder_path)
    if not eml_files:
        safe_print(f"No .eml files found in {folder_name}")
        # Even if empty, check for orphans to delete
        if dest_delete:
            dest = imap_common.get_imap_connection_from_conf(dest_conf)
            if dest:
                delete_orphan_emails_from_dest(dest, folder_name, set())
                dest.logout()
        return

    safe_print(f"Found {len(eml_files)} emails to restore.")

    cache_root = cache_root or local_folder_path
    cache_path = restore_cache.get_dest_index_cache_path(cache_root, dest_conf["host"], dest_conf["user"])
    cache_data: dict = restore_cache.load_dest_index_cache(cache_path)
    cache_lock = threading.Lock()

    safe_print(f"Using progress cache: {cache_path}")

    # Incremental mode uses cached Message-IDs to skip already-processed emails.
    existing_dest_msg_ids_by_folder: Optional[dict[str, set[str]]] = {folder_name: set()}
    existing_dest_msg_ids_lock: Optional[threading.Lock] = threading.Lock()
    try:
        existing_dest_msg_ids_by_folder[folder_name] = restore_cache.get_cached_message_ids(
            cache_data,
            cache_lock,
            dest_conf["host"],
            dest_conf["user"],
            folder_name,
        )
        safe_print(f"Cache has {len(existing_dest_msg_ids_by_folder[folder_name])} Message-IDs for this folder.")
    except Exception as e:
        # Fall back to an empty cache for this folder if reading cached Message-IDs fails.
        safe_print(f"Warning: Failed to load cached Message-IDs for folder '{folder_name}': {e}")
        existing_dest_msg_ids_by_folder[folder_name] = set()

    # If dest_delete enabled, get local Message-IDs for comparison
    local_msg_ids = None
    if dest_delete:
        safe_print("Building local Message-ID index for sync...")
        local_msg_ids = get_local_message_ids(local_folder_path)
        safe_print(f"Found {len(local_msg_ids)} unique Message-IDs in local backup.")

    # Pre-fetch destination Message-IDs and filter duplicates (non-Gmail mode only)
    gmail_mode = folder_name == "__GMAIL_MODE__"
    files_to_restore = eml_files

    if not gmail_mode:
        dest_msg_ids = set()
        try:
            dest_tmp = imap_common.get_imap_connection_from_conf(dest_conf)
            if dest_tmp:
                # Ensure folder exists before selecting
                if folder_name.upper() != "INBOX":
                    try:
                        dest_tmp.create(f'"{folder_name}"')
                    except Exception:
                        pass
                dest_tmp.select(f'"{folder_name}"')
                dest_msg_ids = set(imap_common.get_message_ids_in_folder(dest_tmp).values())
                dest_tmp.logout()
        except Exception:
            dest_msg_ids = set()

        safe_print(f"{len(dest_msg_ids)} existing messages in destination.")

        # Pre-filter files to skip duplicates
        if dest_msg_ids:
            safe_print("Pre-filtering duplicates...")
            files_to_restore = []
            skipped = 0
            for file_path, filename in eml_files:
                msg_id = extract_message_id_from_eml(file_path)
                if msg_id and msg_id in dest_msg_ids:
                    skipped += 1
                else:
                    files_to_restore.append((file_path, filename))
            safe_print(f"Skipping {skipped} duplicates, {len(files_to_restore)} to restore.")

    if not files_to_restore:
        safe_print("No new emails to restore.")
        return

    safe_print(f"Starting parallel restore of {len(files_to_restore)} emails...")

    # Create batches
    batches = [files_to_restore[i : i + BATCH_SIZE] for i in range(0, len(files_to_restore), BATCH_SIZE)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for batch in batches:
            futures.append(
                executor.submit(
                    process_restore_batch,
                    batch,
                    folder_name,
                    dest_conf,
                    manifest,
                    apply_labels,
                    apply_flags,
                    full_restore,
                    existing_dest_msg_ids_by_folder,
                    existing_dest_msg_ids_lock,
                    cache_data,
                    cache_lock,
                    cache_path,
                    dest_conf.get("host"),
                    dest_conf.get("user"),
                )
            )

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"Batch error: {e}")

    # Delete orphan emails from destination if enabled
    if dest_delete and local_msg_ids is not None:
        safe_print("Syncing destination: removing emails not in local backup...")
        dest = imap_session.ensure_connection(None, dest_conf)
        if dest:
            delete_orphan_emails_from_dest(dest, folder_name, local_msg_ids)
            dest.logout()

    # Force-flush progress cache at end.
    restore_cache.maybe_save_dest_index_cache(cache_path, cache_data, cache_lock, force=True)


def restore_gmail_with_labels(local_path, dest_conf, manifest, apply_flags, full_restore: bool = False):
    """
    Special restoration mode for Gmail: Upload emails to their first label folder
    and then apply additional labels from the manifest.

    This avoids putting all emails in INBOX - emails only appear in INBOX
    if they originally had the INBOX label.
    """
    # Find the All Mail folder in the backup
    all_mail_path = os.path.join(local_path, "[Gmail]", "All Mail")
    if not os.path.exists(all_mail_path):
        # Try without subfolder structure
        all_mail_path = local_path

    safe_print("--- Gmail Restore with Labels ---")
    safe_print(f"Source path: {all_mail_path}")
    safe_print(f"Entries in manifest: {len(manifest)}")

    eml_files = get_eml_files(all_mail_path)
    if not eml_files:
        safe_print("No .eml files found for restoration.")
        return

    safe_print(f"Found {len(eml_files)} emails to restore.\n")

    # Process in batches
    total = len(eml_files)
    start_time = time.time()

    batches = [eml_files[i : i + BATCH_SIZE] for i in range(0, len(eml_files), BATCH_SIZE)]

    cache_path = restore_cache.get_dest_index_cache_path(local_path, dest_conf["host"], dest_conf["user"])
    progress_cache_data: dict = restore_cache.load_dest_index_cache(cache_path)
    progress_cache_lock = threading.Lock()

    safe_print(f"Using progress cache: {cache_path}")
    safe_print(
        "Cache will be populated as restore runs (no up-front destination indexing). "
        "First run may still do per-message duplicate checks; subsequent runs will skip quickly."
    )

    existing_dest_msg_ids_by_folder: Optional[dict[str, set[str]]] = {}  # lazily loaded per folder
    existing_dest_msg_ids_lock: Optional[threading.Lock] = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for batch in batches:
            # For Gmail, we use a special folder marker to indicate gmail-mode
            # The process_restore_batch will determine the target folder per-email
            # based on the manifest labels
            futures.append(
                executor.submit(
                    process_restore_batch,
                    batch,
                    "__GMAIL_MODE__",  # Special marker - target determined per-email from manifest
                    dest_conf,
                    manifest,
                    True,  # apply_labels
                    apply_flags,  # apply_flags
                    full_restore,
                    existing_dest_msg_ids_by_folder,
                    existing_dest_msg_ids_lock,
                    progress_cache_data,
                    progress_cache_lock,
                    cache_path,
                    dest_conf.get("host"),
                    dest_conf.get("user"),
                )
            )

        completed = 0
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
                completed += 1
                elapsed = time.time() - start_time
                progress = (completed / len(batches)) * 100
                safe_print(f"Progress: {progress:.1f}% ({elapsed:.0f}s elapsed)")
            except Exception as e:
                safe_print(f"Batch error: {e}")

    elapsed = time.time() - start_time
    safe_print(f"\nRestore completed in {elapsed:.1f}s")

    # Force-flush progress cache at end.
    restore_cache.maybe_save_dest_index_cache(cache_path, progress_cache_data, progress_cache_lock, force=True)


def get_backup_folders(local_path):
    """
    Scan the backup directory and return list of folder paths.
    Returns list of (folder_name, local_path) tuples.
    """
    folders = []

    def scan_dir(path, prefix=""):
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


def main():
    parser = argparse.ArgumentParser(description="Restore IMAP emails from local .eml files.")

    # Source (Local Path)
    env_path = os.getenv("BACKUP_LOCAL_PATH")
    parser.add_argument(
        "--src-path",
        default=env_path,
        required=not bool(env_path),
        help="Local source path containing backup (or BACKUP_LOCAL_PATH)",
    )

    # Destination
    default_dest_host = os.getenv("DEST_IMAP_HOST")
    default_dest_user = os.getenv("DEST_IMAP_USERNAME")
    default_dest_pass = os.getenv("DEST_IMAP_PASSWORD")
    default_dest_client_id = os.getenv("DEST_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--dest-host",
        default=default_dest_host,
        required=not bool(default_dest_host),
        help="Destination IMAP Server (or DEST_IMAP_HOST)",
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

    # Config
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("MAX_WORKERS", 4)),
        help="Thread count (default: 4)",
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=int(os.getenv("BATCH_SIZE", 10)),
        help="Emails per batch",
    )

    # Gmail Labels
    env_apply_labels = os.getenv("APPLY_LABELS", "false").lower() == "true"
    parser.add_argument(
        "--apply-labels",
        action="store_true",
        default=env_apply_labels,
        help="Apply Gmail labels from labels_manifest.json",
    )
    env_apply_flags = os.getenv("APPLY_FLAGS", "false").lower() == "true"
    parser.add_argument(
        "--apply-flags",
        action="store_true",
        default=env_apply_flags,
        help="Apply IMAP flags (read/starred/answered/draft) from manifest",
    )
    env_gmail_mode = os.getenv("GMAIL_MODE", "false").lower() == "true"
    parser.add_argument(
        "--gmail-mode",
        action="store_true",
        default=env_gmail_mode,
        help="Gmail restore mode: Upload to INBOX and apply labels + flags from manifest",
    )

    env_full_restore = os.getenv("FULL_RESTORE", "false").lower() == "true"
    parser.add_argument(
        "--full-restore",
        action="store_true",
        default=env_full_restore,
        help="Force full restore (legacy): process all emails and sync labels/flags for already-present messages.",
    )

    # Sync mode: delete from dest emails not in local backup
    env_dest_delete = os.getenv("DEST_DELETE", "false").lower() == "true"
    parser.add_argument(
        "--dest-delete",
        action="store_true",
        default=env_dest_delete,
        help="Delete emails from destination that don't exist in local backup (sync mode)",
    )

    # Optional folder filter
    parser.add_argument("folder", nargs="?", help="Specific folder to restore")

    args = parser.parse_args()

    dest_use_oauth2 = bool(args.dest_client_id)

    global MAX_WORKERS, BATCH_SIZE
    MAX_WORKERS = args.workers
    BATCH_SIZE = args.batch

    # Acquire OAuth2 token if configured
    dest_oauth2_token = None
    dest_oauth2_provider = None
    if dest_use_oauth2:
        dest_oauth2_provider = imap_oauth2.detect_oauth2_provider(args.dest_host)
        if not dest_oauth2_provider:
            print(f"Error: Could not detect OAuth2 provider from host '{args.dest_host}'.")
            sys.exit(1)
        print(f"Acquiring OAuth2 token for destination ({dest_oauth2_provider})...")
        dest_oauth2_token = imap_oauth2.acquire_oauth2_token_for_provider(
            dest_oauth2_provider, args.dest_client_id, args.dest_user, args.dest_client_secret
        )
        if not dest_oauth2_token:
            print("Error: Failed to acquire OAuth2 token for destination.")
            sys.exit(1)
        print("Destination OAuth2 token acquired successfully.\n")

    # Use a dict so token updates propagate to worker threads
    dest_conf = {
        "host": args.dest_host,
        "user": args.dest_user,
        "password": args.dest_pass,
        "oauth2_token": dest_oauth2_token,
        "oauth2": {
            "provider": dest_oauth2_provider,
            "client_id": args.dest_client_id,
            "email": args.dest_user,
            "client_secret": args.dest_client_secret,
        }
        if dest_use_oauth2
        else None,
    }

    # Expand path
    local_path = os.path.expanduser(args.src_path)
    if not os.path.exists(local_path):
        print(f"Error: Source path does not exist: {local_path}")
        sys.exit(1)

    # Load manifest(s) if needed
    manifest = {}
    apply_labels = args.apply_labels or args.gmail_mode
    apply_flags = args.apply_flags or args.gmail_mode

    if apply_labels or apply_flags:
        # Try to load labels manifest first (contains both labels and flags for Gmail backups)
        manifest = load_labels_manifest(local_path)

        # If no labels manifest, try flags-only manifest
        if not manifest and apply_flags:
            manifest = load_flags_manifest(local_path)

        if not manifest:
            print("Warning: No manifest found. Labels/flags will not be applied.")

    print("\n--- Configuration Summary ---")
    print(f"Source Path     : {local_path}")
    print(f"Destination Host: {args.dest_host}")
    print(f"Destination User: {args.dest_user}")
    print(
        f"Destination Auth: {'OAuth2/' + dest_oauth2_provider + ' (XOAUTH2)' if dest_use_oauth2 else 'Basic (password)'}"
    )
    print(f"Workers         : {args.workers}")
    if args.gmail_mode:
        print("Mode            : Gmail Restore with Labels + Flags")
    elif args.folder:
        print(f"Target Folder   : {args.folder}")
    if apply_labels:
        print(f"Apply Labels    : Yes ({len(manifest)} mappings)")
    if apply_flags:
        print("Apply Flags     : Yes (read/starred/answered/draft)")
    if args.dest_delete:
        print("Dest Delete     : Yes (remove orphans from destination)")
    print(
        f"Restore Mode    : {'Full (all emails)' if args.full_restore else 'Incremental (new emails only, use --full-restore to restore all)'}"
    )
    print("-----------------------------\n")

    try:
        # Test connection
        dest = imap_common.get_imap_connection_from_conf(dest_conf)
        if not dest:
            print("Error: Could not connect to destination server.")
            sys.exit(1)

        if args.gmail_mode:
            dest.logout()
            # Special Gmail mode
            restore_gmail_with_labels(local_path, dest_conf, manifest, apply_flags, full_restore=args.full_restore)
            dest = None  # Connection handled by restore_gmail_with_labels
        elif args.folder:
            # Restore specific folder
            folder_path = os.path.join(local_path, args.folder.replace("/", os.sep))
            if not os.path.exists(folder_path):
                print(f"Error: Folder not found: {folder_path}")
                sys.exit(1)
            restore_folder(
                args.folder,
                folder_path,
                dest_conf,
                manifest,
                apply_labels,
                apply_flags,
                args.dest_delete,
                full_restore=args.full_restore,
                cache_root=local_path,
            )
            dest.logout()
        else:
            # Restore all folders
            folders = get_backup_folders(local_path)
            if not folders:
                print("No backup folders found.")
                sys.exit(1)

            print(f"Found {len(folders)} folders to restore.\n")
            for folder_name, folder_path in folders:
                # Skip manifest files
                if folder_name in ("labels_manifest.json", "flags_manifest.json"):
                    continue

                # Proactively refresh OAuth2 token and ensure connection is healthy between folders
                dest = imap_session.ensure_connection(dest, dest_conf)
                if not dest:
                    print("Fatal: Could not reconnect to destination IMAP server. Aborting.")
                    sys.exit(1)

                restore_folder(
                    folder_name,
                    folder_path,
                    dest_conf,
                    manifest,
                    apply_labels,
                    apply_flags,
                    args.dest_delete,
                    full_restore=args.full_restore,
                    cache_root=local_path,
                )

            dest.logout()

        print("\nRestore completed successfully.")

    except KeyboardInterrupt:
        print("\nRestore interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
