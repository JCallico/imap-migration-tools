"""
IMAP Email Backup Script

Backs up emails from an IMAP account to a local directory.
Stores each email as a separate .eml file (RFC 5322 format) which is compatible with
most email clients (Thunderbird, Apple Mail, Outlook, etc.).

Features:
- Incremental Backup: Skips messages that have already been downloaded (checks existing UIDs locally).
- Filename Sanitization: Saves files as "{UID}_{Subject}.eml" with unsafe characters removed.
- Folder Replication: Recreates the IMAP folder structure locally.
- Parallel Processing: Uses multithreading for fast downloads.
- Gmail Labels Preservation: Creates a manifest mapping Message-IDs to Gmail labels for restoration.

Configuration (Environment Variables):
    SRC_IMAP_HOST, SRC_IMAP_USERNAME: Source credentials.
    SRC_IMAP_PASSWORD: Source password (or App Password).

    OAuth2 (Optional - instead of password):
    SRC_OAUTH2_CLIENT_ID: OAuth2 Client ID
    SRC_OAUTH2_CLIENT_SECRET: OAuth2 Client Secret (required for Google)

  BACKUP_LOCAL_PATH: Destination local directory.
  MAX_WORKERS: Number of concurrent threads (default: 10).
  BATCH_SIZE: Number of emails to process per batch (default: 10).
  PRESERVE_LABELS: Set to "true" to create labels_manifest.json (Gmail). Default is "false".
  PRESERVE_FLAGS: Set to "true" to preserve IMAP flags in manifest. Default is "false".
  MANIFEST_ONLY: Set to "true" to only build manifest without downloading. Default is "false".
  GMAIL_MODE: Set to "true" for Gmail backup mode. Default is "false".
  DEST_DELETE: Set to "true" to delete local files not found on server (sync mode).
              Default is "false".

Usage:
    python3 imap_backup.py \
        --src-host "imap.example.com" \
        --src-user "you@example.com" \
        --src-pass "your-app-password" \
        --dest-path "./my_backup"

Gmail Labels:
    python3 imap_backup.py \
        --src-host "imap.gmail.com" \
        --src-user "you@gmail.com" \
        --src-pass "your-app-password" \
        --dest-path "./my_backup" \
        --preserve-labels \
        "[Gmail]/All Mail"
  This backs up all emails from [Gmail]/All Mail and creates a labels_manifest.json
  file that maps each email's Message-ID to its Gmail labels for later restoration.
"""

import argparse
import concurrent.futures
import json
import os
import sys
import threading

from auth import imap_oauth2
from core import imap_session
from providers import provider_exchange, provider_gmail
from utils import imap_common

# Defaults
MAX_WORKERS = 10
BATCH_SIZE = 10
MANIFEST_FILENAME = "labels_manifest.json"

# Thread-local storage
thread_local = threading.local()
safe_print = imap_common.safe_print


def process_single_uid(src, uid, folder_name, local_folder_path):
    """
    Fetch and save a single email by UID.

    Args:
        src: IMAP connection
        uid: Message UID to fetch
        folder_name: Current folder name (for logging)
        local_folder_path: Local directory to save email

    Returns:
        Tuple of (success: bool, connection):
        - (True, src): UID processed successfully (or skipped)
        - (False, src): Auth error occurred, caller should retry after reconnect
    """
    uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)

    try:
        resp, data = src.uid("fetch", uid, "(RFC822)")
        if resp != "OK" or not data or data[0] is None:
            safe_print(f"[{folder_name}] ERROR Fetch Body | UID {uid_str}")
            return (True, src)  # Don't retry, move on

        raw_email = None
        for item in data:
            if isinstance(item, tuple):
                raw_email = item[1]
                break

        # Derive Subject for filename from the already-fetched message bytes.
        _, subject = imap_common.parse_message_id_and_subject_from_bytes(raw_email)
        if not subject:
            clean_subject = "No Subject"
        else:
            clean_subject = imap_common.sanitize_filename(subject)
            clean_subject = clean_subject[:100]

        filename = f"{uid_str}_{clean_subject}.eml"
        full_path = os.path.join(local_folder_path, filename)

        if os.path.exists(full_path):
            return (True, src)  # Already exists

        if raw_email:
            try:
                with open(full_path, "wb") as f:
                    f.write(raw_email)
                safe_print(f"[{folder_name}] SAVED  | {filename[:60]}...")
            except OSError as e:
                safe_print(f"[{folder_name}] ERROR Write | {uid_str}: {e}")
        else:
            safe_print(f"[{folder_name}] EMPTY Content | UID {uid_str}")

        return (True, src)

    except Exception as e:
        if imap_oauth2.is_auth_error(e):
            safe_print(f"[{folder_name}] Auth error for UID {uid_str}, will retry...")
            return (False, src)  # Signal retry needed
        else:
            safe_print(f"[{folder_name}] ERROR Processing UID {uid}: {e}")
            return (True, src)  # Don't retry other errors


def process_batch(uids, folder_name, src_conf, local_folder_path):
    src = imap_session.get_thread_connection(thread_local, "src", src_conf)
    if not src:
        safe_print("Error: Could not establish connection for batch.")
        return

    try:
        src.select(f'"{folder_name}"', readonly=True)
    except Exception as e:
        safe_print(f"Error selecting folder {folder_name} in worker: {e}")
        return

    for uid in uids:
        uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)
        max_retries = 2

        for attempt in range(max_retries):
            src, ok = imap_session.ensure_folder_session(src, src_conf, folder_name, readonly=True)
            thread_local.src = src
            if not ok:
                safe_print(f"[{folder_name}] ERROR: Connection/folder lost for UID {uid_str}")
                return

            success, src = process_single_uid(src, uid, folder_name, local_folder_path)
            thread_local.src = src

            if success:
                break
            if attempt < max_retries - 1:
                src = None
                thread_local.src = None


def get_existing_uids(local_path):
    """
    Scans the local directory for files matching pattern matches {UID}_*.eml
    Returns a set of UIDs (as strings).
    """
    existing = set()
    if not os.path.exists(local_path):
        return existing

    try:
        for filename in os.listdir(local_path):
            if filename.endswith(".eml") and "_" in filename:
                # Expecting UID_Subject.eml
                parts = filename.split("_", 1)
                if parts[0].isdigit():
                    existing.add(parts[0])
    except Exception:
        pass
    return existing


# Standard IMAP flags that can be preserved during migration
# \Recent is session-specific and cannot be set by clients
# \Deleted should not be preserved as it marks messages for removal
PRESERVABLE_FLAGS = imap_common.PRESERVABLE_FLAGS


def get_message_info_in_folder_with_conf(imap_conn, folder_name, src_conf, progress_callback=None):
    """
    Returns a dict of Message-IDs and their IMAP flags for all emails in a folder,
    with OAuth2 session management.

    Args:
        imap_conn: IMAP connection
        folder_name: Folder to scan
        src_conf: Connection config dict for OAuth2 refresh
        progress_callback: Optional callback(current, total) for progress reporting

    Returns:
        Tuple of (message_info, imap_conn) where message_info is:
        { "message-id": {"flags": ["\\Seen", "\\Flagged", ...]}, ... }
        The returned imap_conn may be different if reconnection occurred.
    """
    message_info = {}

    # Ensure connection is healthy (refresh OAuth2 token if needed) before initial select
    if src_conf:
        imap_conn = imap_session.ensure_connection(imap_conn, src_conf)
        if not imap_conn:
            safe_print(f"Could not establish connection for folder {folder_name}")
            return (message_info, None)

    try:
        imap_conn.select(f'"{folder_name}"', readonly=True)
    except Exception as e:
        safe_print(f"Could not select folder {folder_name}: {e}")
        return (message_info, imap_conn)

    try:
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data or not data[0]:
            return (message_info, imap_conn)

        uids = data[0].split()
        if not uids:
            return (message_info, imap_conn)

        total_uids = len(uids)

        # Fetch Message-IDs and FLAGS in batches - use larger batch for header-only fetches
        batch_size = 200
        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            uid_range = b",".join(batch)

            # Report progress
            if progress_callback:
                progress_callback(min(i + batch_size, total_uids), total_uids)

            # Proactively refresh token and ensure folder is selected
            if src_conf:
                imap_conn, ok = imap_session.ensure_folder_session(imap_conn, src_conf, folder_name, readonly=True)
                if not ok:
                    safe_print(f"ERROR: Connection/folder lost in {folder_name}")
                    break

            try:
                # Fetch both Message-ID header and FLAGS
                resp, items = imap_conn.uid("fetch", uid_range, "(FLAGS BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
                if resp != "OK":
                    continue

                # Parse response - items come in pairs for each message
                for item in items:
                    if isinstance(item, tuple) and len(item) >= 2:
                        # First element contains UID and FLAGS info
                        meta_str = (
                            item[0].decode("utf-8", errors="ignore") if isinstance(item[0], bytes) else str(item[0])
                        )

                        # Extract all preservable flags from the metadata
                        flags = []
                        for flag in imap_common.PRESERVABLE_FLAGS:
                            if flag in meta_str:
                                flags.append(flag)

                        # Second element contains the header
                        msg_id = imap_common.extract_message_id(item[1])
                        if msg_id:
                            message_info[msg_id] = {"flags": flags}
            except Exception as e:
                safe_print(f"Error fetching batch in {folder_name}: {e}")
                continue

    except Exception as e:
        safe_print(f"Error searching folder {folder_name}: {e}")

    return (message_info, imap_conn)


def get_message_info_in_folder(imap_conn, folder_name, progress_callback=None):
    """
    Returns a dict of Message-IDs and their IMAP flags for all emails in a folder.

    Returns: { "message-id": {"flags": ["\\Seen", "\\Flagged", ...]}, ... }
    Optional progress_callback(current, total) for progress reporting.
    """
    message_info, _ = get_message_info_in_folder_with_conf(imap_conn, folder_name, None, progress_callback)
    return message_info


def get_message_ids_in_folder_with_conf(imap_conn, folder_name, src_conf, progress_callback=None):
    """
    Returns a set of Message-IDs for all emails in a given folder,
    with OAuth2 session management.

    Args:
        imap_conn: IMAP connection
        folder_name: Folder to scan
        src_conf: Connection config dict for OAuth2 refresh
        progress_callback: Optional callback(current, total) for progress reporting

    Returns:
        Tuple of (message_ids, imap_conn) where message_ids is a set of strings.
        The returned imap_conn may be different if reconnection occurred.
    """
    info, imap_conn = get_message_info_in_folder_with_conf(imap_conn, folder_name, src_conf, progress_callback)
    return (set(info.keys()), imap_conn)


def get_message_ids_in_folder(imap_conn, folder_name, progress_callback=None):
    """
    Returns a set of Message-IDs for all emails in a given folder.
    This is a convenience wrapper around get_message_info_in_folder.
    Optional progress_callback(current, total) for progress reporting.
    """
    info = get_message_info_in_folder(imap_conn, folder_name, progress_callback)
    return set(info.keys())


def build_labels_manifest(imap_conn, local_path, src_conf=None):
    """
    Builds a manifest mapping Message-IDs to their Gmail labels and IMAP flags.
    Scans all folders (labels) in the account and records which Message-IDs
    appear in each label, plus their flags from [Gmail]/All Mail.

    Returns a dict: { "message-id": {"labels": ["Label1", ...], "flags": ["\\Seen", ...]}, ... }
    Saves the manifest to labels_manifest.json in the backup directory.
    Optional src_conf for automatic token refresh on expiration.
    """
    import time

    manifest = {}
    start_time = time.time()
    total_emails_scanned = 0

    safe_print("--- Building Gmail Labels Manifest ---")

    # Get all selectable folders and filter to label folders
    all_folders = imap_common.list_selectable_folders(imap_conn)
    if not all_folders:
        safe_print("Error: Could not list folders for label mapping.")
        return manifest

    # First, scan [Gmail]/All Mail to get the authoritative flags for all emails
    safe_print("[0/N] Scanning [Gmail]/All Mail for flags (read/starred/etc)...")
    all_mail_start = time.time()

    def all_mail_progress_cb(current, total):
        elapsed = time.time() - start_time
        print(
            f"\r  Progress: {current}/{total} emails scanned (elapsed: {elapsed:.0f}s)   ",
            end="",
            flush=True,
        )

    all_mail_info, imap_conn = get_message_info_in_folder_with_conf(
        imap_conn, provider_gmail.GMAIL_ALL_MAIL, src_conf, all_mail_progress_cb
    )
    print()  # New line after progress

    # Initialize manifest with flags from All Mail
    for msg_id, info in all_mail_info.items():
        manifest[msg_id] = {"labels": [], "flags": info.get("flags", [])}

    all_mail_elapsed = time.time() - all_mail_start
    # Count flag statistics
    read_count = sum(1 for m in manifest.values() if imap_common.FLAG_SEEN in m.get("flags", []))
    flagged_count = sum(1 for m in manifest.values() if imap_common.FLAG_FLAGGED in m.get("flags", []))
    safe_print(f"  -> {len(all_mail_info)} emails scanned ({all_mail_elapsed:.1f}s)")
    safe_print(f"  -> Read: {read_count}, Unread: {len(manifest) - read_count}, Starred: {flagged_count}\n")

    # Keep connection alive
    try:
        imap_conn.noop()
    except Exception:
        pass

    # Parse folder names and filter to label folders
    label_folders = [f for f in all_folders if provider_gmail.is_label_folder(f)]

    total_folders = len(label_folders)
    safe_print(f"Found {total_folders} label folders to scan.\n")

    # Scan each label folder
    for folder_idx, folder_name in enumerate(label_folders, 1):
        folder_start = time.time()

        # Progress callback for this folder
        def progress_cb(current, total):
            elapsed = time.time() - start_time
            print(
                f"\r  Progress: {current}/{total} emails scanned (elapsed: {elapsed:.0f}s)   ",
                end="",
                flush=True,
            )

        safe_print(f"[{folder_idx}/{total_folders}] Scanning: {folder_name}")
        message_ids, imap_conn = get_message_ids_in_folder_with_conf(imap_conn, folder_name, src_conf, progress_cb)
        print()  # New line after progress

        # Keep connection alive between folders
        try:
            imap_conn.noop()
        except Exception:
            pass

        # Determine the label name to store
        # For [Gmail]/Sent Mail -> "Sent Mail"
        # For [Gmail]/Starred -> "Starred"
        # For INBOX -> "INBOX"
        # For user folders -> folder name as-is
        if folder_name.startswith("[Gmail]/"):
            label_name = folder_name[8:]  # Remove "[Gmail]/" prefix
        else:
            label_name = folder_name

        for msg_id in message_ids:
            if msg_id not in manifest:
                # Email not in All Mail (rare, but handle it)
                manifest[msg_id] = {"labels": [], "flags": []}
            if label_name not in manifest[msg_id]["labels"]:
                manifest[msg_id]["labels"].append(label_name)

        folder_elapsed = time.time() - folder_start
        total_emails_scanned += len(message_ids)
        safe_print(f"  -> {len(message_ids)} emails with label '{label_name}' ({folder_elapsed:.1f}s)")

    # Summary
    total_elapsed = time.time() - start_time
    read_count = sum(1 for m in manifest.values() if imap_common.FLAG_SEEN in m.get("flags", []))
    flagged_count = sum(1 for m in manifest.values() if imap_common.FLAG_FLAGGED in m.get("flags", []))
    safe_print("\nManifest building complete:")
    safe_print(f"  - Folders scanned: {total_folders + 1}")  # +1 for All Mail
    safe_print(f"  - Total email-label mappings: {total_emails_scanned}")
    safe_print(f"  - Unique emails: {len(manifest)}")
    safe_print(f"  - Read: {read_count}, Unread: {len(manifest) - read_count}, Starred: {flagged_count}")
    safe_print(f"  - Time elapsed: {total_elapsed:.1f}s")

    # Save manifest
    manifest_path = os.path.join(local_path, MANIFEST_FILENAME)
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        safe_print(f"\nLabels manifest saved to: {manifest_path}")
    except Exception as e:
        safe_print(f"Error saving manifest: {e}")

    return manifest


def build_flags_manifest(imap_conn, local_path, folders_to_scan=None, src_conf=None):
    """
    Builds a manifest mapping Message-IDs to their IMAP flags.
    For non-Gmail servers, scans specified folders (or all folders if not specified).

    Returns a dict: { "message-id": {"flags": ["\\Seen", ...]}, ... }
    Saves the manifest to flags_manifest.json in the backup directory.
    Optional src_conf for automatic token refresh on expiration.
    """
    import time

    manifest = {}
    start_time = time.time()

    safe_print("--- Building Flags Manifest ---")

    # Get folders to scan
    if folders_to_scan:
        all_folders = folders_to_scan
    else:
        try:
            typ, folders = imap_conn.list()
            if typ != "OK":
                safe_print("Error: Could not list folders.")
                return manifest
            all_folders = [imap_common.normalize_folder_name(f) for f in folders]
        except Exception as e:
            safe_print(f"Error listing folders: {e}")
            return manifest

    total_folders = len(all_folders)
    safe_print(f"Found {total_folders} folders to scan.\n")

    # Scan each folder
    for folder_idx, folder_name in enumerate(all_folders, 1):
        folder_start = time.time()

        def progress_cb(current, total):
            elapsed = time.time() - start_time
            print(
                f"\r  Progress: {current}/{total} emails scanned (elapsed: {elapsed:.0f}s)   ",
                end="",
                flush=True,
            )

        safe_print(f"[{folder_idx}/{total_folders}] Scanning: {folder_name}")
        folder_info, imap_conn = get_message_info_in_folder_with_conf(imap_conn, folder_name, src_conf, progress_cb)
        print()  # New line after progress

        # Merge into manifest (keep first occurrence of flags)
        for msg_id, info in folder_info.items():
            if msg_id not in manifest:
                manifest[msg_id] = {"flags": info.get("flags", [])}

        folder_elapsed = time.time() - folder_start
        safe_print(f"  -> {len(folder_info)} emails ({folder_elapsed:.1f}s)")

        # Keep connection alive
        try:
            imap_conn.noop()
        except Exception:
            pass

    # Summary
    total_elapsed = time.time() - start_time
    read_count = sum(1 for m in manifest.values() if imap_common.FLAG_SEEN in m.get("flags", []))
    flagged_count = sum(1 for m in manifest.values() if imap_common.FLAG_FLAGGED in m.get("flags", []))
    safe_print("\nFlags manifest building complete:")
    safe_print(f"  - Folders scanned: {total_folders}")
    safe_print(f"  - Unique emails: {len(manifest)}")
    safe_print(f"  - Read: {read_count}, Unread: {len(manifest) - read_count}, Flagged: {flagged_count}")
    safe_print(f"  - Time elapsed: {total_elapsed:.1f}s")

    # Save manifest
    manifest_path = os.path.join(local_path, "flags_manifest.json")
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        safe_print(f"\nFlags manifest saved to: {manifest_path}")
    except Exception as e:
        safe_print(f"Error saving manifest: {e}")

    return manifest


def delete_orphan_local_files(local_folder_path, server_uids):
    """
    Delete local .eml files that no longer exist on the server.
    Args:
        local_folder_path: Path to local folder containing .eml files
        server_uids: Set of UID strings currently on server
    Returns:
        Count of deleted files
    """
    deleted_count = 0
    if not os.path.exists(local_folder_path):
        return deleted_count

    try:
        for filename in os.listdir(local_folder_path):
            if not filename.endswith(".eml") or "_" not in filename:
                continue

            # Extract UID from filename (format: {UID}_{Subject}.eml)
            parts = filename.split("_", 1)
            if not parts[0].isdigit():
                continue

            local_uid = parts[0]
            if local_uid not in server_uids:
                file_path = os.path.join(local_folder_path, filename)
                try:
                    os.remove(file_path)
                    safe_print(f"  -> Deleted orphan: {filename}")
                    deleted_count += 1
                except Exception as e:
                    safe_print(f"  -> Error deleting {filename}: {e}")
    except Exception as e:
        safe_print(f"Error scanning for orphan files: {e}")

    return deleted_count


def backup_folder(src_main, folder_name, local_base_path, src_conf, dest_delete=False):
    safe_print(f"--- Processing Folder: {folder_name} ---")

    # create local path
    # Handle folder separators. IMAP output might be "Parent/Child"
    # We rely on OS to handle "Parent/Child" as subdirectories using join
    # But clean the segments
    cleaned_name = folder_name.replace("/", os.sep)
    local_folder_path = os.path.join(local_base_path, cleaned_name)

    try:
        os.makedirs(local_folder_path, exist_ok=True)
    except Exception as e:
        safe_print(f"Error creating directory {local_folder_path}: {e}")
        return

    # Select IMAP folder
    try:
        src_main.select(f'"{folder_name}"', readonly=True)
    except Exception as e:
        safe_print(f"Skipping {folder_name}: {e}")
        return

    # Search all
    resp, data = src_main.uid("search", None, "ALL")
    if resp != "OK":
        return

    uids = data[0].split()
    total_on_server = len(uids)

    # Build set of server UIDs for comparison
    server_uid_set = set()
    for u in uids:
        u_str = u.decode("utf-8") if isinstance(u, bytes) else str(u)
        server_uid_set.add(u_str)

    if total_on_server == 0:
        safe_print(f"Folder {folder_name} is empty.")
        # If dest_delete enabled, delete all local files
        if dest_delete:
            deleted = delete_orphan_local_files(local_folder_path, set())
            if deleted > 0:
                safe_print(f"Deleted {deleted} orphan files from local backup.")
        return

    # Incremental Optimization
    # Read local directory to find UIDs we already have
    existing_uids = get_existing_uids(local_folder_path)

    # Delete orphan local files if dest_delete is enabled
    if dest_delete:
        orphan_uids = existing_uids - server_uid_set
        if orphan_uids:
            safe_print(f"Found {len(orphan_uids)} local files not on server, deleting...")
            deleted = delete_orphan_local_files(local_folder_path, server_uid_set)
            if deleted > 0:
                safe_print(f"Deleted {deleted} orphan files from local backup.")

    # Filter UIDs
    # decode uid first if bytes
    uids_to_download = []
    for u in uids:
        u_str = u.decode("utf-8") if isinstance(u, bytes) else str(u)
        if u_str not in existing_uids:
            uids_to_download.append(u)

    skipped = total_on_server - len(uids_to_download)
    if skipped > 0:
        safe_print(f"Skipping {skipped} emails (already exist locally).")

    if not uids_to_download:
        safe_print(f"Folder {folder_name} is up to date.")
        return

    safe_print(f"Downloading {len(uids_to_download)} new emails...")

    # Create batches
    uid_batches = [uids_to_download[i : i + BATCH_SIZE] for i in range(0, len(uids_to_download), BATCH_SIZE)]

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = []
        for batch in uid_batches:
            futures.append(executor.submit(process_batch, batch, folder_name, src_conf, local_folder_path))

        for future in concurrent.futures.as_completed(futures):
            future.result()

    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        executor.shutdown(wait=True)


def main():
    parser = argparse.ArgumentParser(description="Backup IMAP emails to local .eml files.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")

    # Source
    default_src_host = os.getenv("SRC_IMAP_HOST")
    default_src_user = os.getenv("SRC_IMAP_USERNAME")
    default_src_pass = os.getenv("SRC_IMAP_PASSWORD")
    default_src_client_id = os.getenv("SRC_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--src-host",
        default=default_src_host,
        required=not bool(default_src_host),
        help="Source IMAP Server (or SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--src-user",
        default=default_src_user,
        required=not bool(default_src_user),
        help="Source Username (or SRC_IMAP_USERNAME)",
    )

    # Authentication: require either password OR OAuth2 client-id (unless provided via env vars)
    auth_required = not bool(default_src_pass or default_src_client_id)
    auth_group = parser.add_mutually_exclusive_group(required=auth_required)
    auth_group.add_argument("--src-pass", default=default_src_pass, help="Source Password (or SRC_IMAP_PASSWORD)")
    # OAuth2
    auth_group.add_argument(
        "--src-oauth2-client-id",
        default=default_src_client_id,
        dest="src_client_id",
        help="OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        default=os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        dest="src_client_secret",
        help="OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )

    # Destination (Local Path)
    env_path = os.getenv("BACKUP_LOCAL_PATH")
    parser.add_argument(
        "--dest-path",
        default=env_path,
        required=not bool(env_path),
        help="Local destination path (or BACKUP_LOCAL_PATH)",
    )

    # Config
    parser.add_argument("--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Thread count")
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Emails per batch")

    # Gmail Labels
    env_preserve_labels = os.getenv("PRESERVE_LABELS", "false").lower() == "true"
    parser.add_argument(
        "--preserve-labels",
        action="store_true",
        default=env_preserve_labels,
        help="Gmail only: Create a labels_manifest.json mapping Message-IDs to labels for restoration",
    )
    env_preserve_flags = os.getenv("PRESERVE_FLAGS", "false").lower() == "true"
    parser.add_argument(
        "--preserve-flags",
        action="store_true",
        default=env_preserve_flags,
        help="Preserve IMAP flags (read/unread, starred, answered, draft) in manifest for restoration",
    )
    env_manifest_only = os.getenv("MANIFEST_ONLY", "false").lower() == "true"
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        default=env_manifest_only,
        help="Gmail only: Build the labels manifest and exit without downloading emails",
    )
    env_gmail_mode = os.getenv("GMAIL_MODE", "false").lower() == "true"
    parser.add_argument(
        "--gmail-mode",
        action="store_true",
        default=env_gmail_mode,
        help="Gmail backup mode: Build labels manifest and backup [Gmail]/All Mail only (recommended)",
    )

    # Sync mode: delete local files not on server
    env_dest_delete = os.getenv("DEST_DELETE", "false").lower() == "true"
    parser.add_argument(
        "--dest-delete",
        action="store_true",
        default=env_dest_delete,
        help="Delete local .eml files that no longer exist on the IMAP server (sync mode)",
    )

    parser.add_argument("folder", nargs="?", help="Specific folder to backup")

    args = parser.parse_args()

    global MAX_WORKERS, BATCH_SIZE
    MAX_WORKERS = args.workers
    BATCH_SIZE = args.batch

    # Build connection config (acquires OAuth2 token if configured)
    src_conf = imap_session.build_imap_conf(
        args.src_host, args.src_user, args.src_pass, args.src_client_id, args.src_client_secret
    )

    # Expand path (~/...)
    local_path = os.path.expanduser(args.dest_path)
    if not os.path.exists(local_path):
        try:
            os.makedirs(local_path)
            print(f"Created backup directory: {local_path}")
        except Exception as e:
            print(f"Error creating backup directory: {e}")
            sys.exit(1)

    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {args.src_host}")
    print(f"Source User     : {args.src_user}")
    print(f"Auth Method     : {imap_oauth2.auth_description(src_conf['oauth2'] and src_conf['oauth2']['provider'])}")
    print(f"Destination Path: {local_path}")
    if args.gmail_mode:
        print("Mode            : Gmail Backup (All Mail + Labels + Flags)")
    elif args.manifest_only:
        print("Mode            : Manifest Only (no email download)")
    elif args.folder:
        print(f"Target Folder   : {args.folder}")
    if args.preserve_labels or args.manifest_only or args.gmail_mode:
        print("Preserve Labels : Yes (Gmail)")
    if args.preserve_flags or args.gmail_mode:
        print("Preserve Flags  : Yes (read/starred/answered/draft)")
    if args.dest_delete:
        print("Dest Delete     : Yes (remove local orphans)")
    print("-----------------------------\n")

    try:
        src = imap_common.get_imap_connection_from_conf(src_conf)
        if not src:
            sys.exit(1)

        # Build labels manifest BEFORE backing up emails (Gmail mode)
        # This way we capture the label state at backup time
        if args.preserve_labels or args.manifest_only or args.gmail_mode:
            print("Building Gmail labels manifest...")
            print("This scans all folders to map Message-IDs to labels and flags.\n")
            build_labels_manifest(src, local_path, src_conf)
            print("")  # Blank line after manifest building
        # Build flags-only manifest for non-Gmail servers
        elif args.preserve_flags:
            print("Building flags manifest...")
            print("This scans folders to capture read/starred/etc status.\n")
            # Get folders to scan
            folders_to_scan = [args.folder] if args.folder else None
            build_flags_manifest(src, local_path, folders_to_scan, src_conf)
            print("")  # Blank line after manifest building

        # If manifest-only mode, we're done
        if args.manifest_only:
            try:
                src.logout()
            except Exception:
                pass  # Connection may already be closed
            manifest_path = os.path.join(local_path, MANIFEST_FILENAME)
            print("\nManifest-only mode complete.")
            print(f"Labels manifest saved to: {manifest_path}")
            print("\nTo download emails, run again without --manifest-only:")
            print(f'  python3 imap_backup.py --dest-path "{local_path}" "[Gmail]/All Mail"')
            sys.exit(0)

        # Gmail mode: backup only [Gmail]/All Mail
        if args.gmail_mode:
            backup_folder(src, provider_gmail.GMAIL_ALL_MAIL, local_path, src_conf, args.dest_delete)
        elif args.folder:
            backup_folder(src, args.folder, local_path, src_conf, args.dest_delete)
        else:
            # Reconnect after potentially long manifest building
            src = imap_session.ensure_connection(src, src_conf)
            if not src:
                print("Warning: Could not reconnect to IMAP server for backup. Manifest was saved successfully.")
                sys.exit(0)
            folders = imap_common.list_selectable_folders(src)
            for name in folders:
                if provider_exchange.is_special_folder(name):
                    print(f"Skipping Exchange system folder: {name}")
                    continue
                src = imap_session.ensure_connection(src, src_conf)
                if not src:
                    print("Fatal: Could not reconnect to IMAP server. Aborting.")
                    sys.exit(1)
                backup_folder(src, name, local_path, src_conf, args.dest_delete)

        try:
            src.logout()
        except Exception:
            pass  # Connection may already be closed
        print("\nBackup completed successfully.")

        if args.preserve_labels or args.gmail_mode:
            manifest_path = os.path.join(local_path, "labels_manifest.json")
            print(f"\nGmail labels manifest saved to: {manifest_path}")
            print("Use this file when restoring to reapply labels and flags to emails.")
        elif args.preserve_flags:
            manifest_path = os.path.join(local_path, "flags_manifest.json")
            print(f"\nFlags manifest saved to: {manifest_path}")
            print("Use this file when restoring to reapply read/starred status to emails.")

    except KeyboardInterrupt:
        raise


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)
