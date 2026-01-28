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

Configuration:
  SRC_IMAP_HOST, SRC_IMAP_USERNAME, SRC_IMAP_PASSWORD: Source credentials.
  BACKUP_LOCAL_PATH: Destination local directory.

Usage:
  python3 backup_imap_emails.py --dest-path "./my_backup"

Gmail Labels:
  python3 backup_imap_emails.py --dest-path "./my_backup" --preserve-labels "[Gmail]/All Mail"
  This backs up all emails from [Gmail]/All Mail and creates a labels_manifest.json
  file that maps each email's Message-ID to its Gmail labels for later restoration.
"""

import argparse
import concurrent.futures
import json
import os
import sys
import threading

import imap_common

# Defaults
MAX_WORKERS = 10
BATCH_SIZE = 10

# Thread-local storage
thread_local = threading.local()
print_lock = threading.Lock()

# Gmail-specific folders to exclude from label mapping
GMAIL_SYSTEM_FOLDERS = {
    "[Gmail]/All Mail",
    "[Gmail]/Spam",
    "[Gmail]/Trash",
    "[Gmail]/Drafts",
    "[Gmail]/Bin",
    "[Gmail]/Important",  # This is actually a label, but often system-managed
}


def safe_print(message):
    t_name = threading.current_thread().name
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with print_lock:
        print(f"[{short_name}] {message}")


def get_thread_connection(src_conf):
    if not hasattr(thread_local, "src") or thread_local.src is None:
        thread_local.src = imap_common.get_imap_connection(*src_conf)
    try:
        if thread_local.src:
            thread_local.src.noop()
    except:
        thread_local.src = imap_common.get_imap_connection(*src_conf)
    return thread_local.src


def process_batch(uids, folder_name, src_conf, local_folder_path):
    src = get_thread_connection(src_conf)
    if not src:
        safe_print("Error: Could not establish connection for batch.")
        return

    try:
        src.select(f'"{folder_name}"', readonly=True)
    except Exception as e:
        safe_print(f"Error selecting folder {folder_name} in worker: {e}")
        return

    for uid in uids:
        try:
            # 1. Fetch Subject for Filename
            # We fetch headers first to generate the nice filename
            msg_id, size, subject = imap_common.get_msg_details(src, uid)

            # Helper to handle byte UIDs
            uid_str = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)

            if not subject:
                clean_subject = "No Subject"
            else:
                clean_subject = imap_common.sanitize_filename(subject)
                # Limit subject len to avoid FS path length limits (max 255 usually)
                clean_subject = clean_subject[:100]

            filename = f"{uid_str}_{clean_subject}.eml"
            full_path = os.path.join(local_folder_path, filename)

            # Double check existence (in case optimization missed it or naming collision)
            # Actually, the main purpose here is just to save.
            # However, if we migrated to a new naming convention, we might have duplicates with different names?
            # The incremental check in `backup_folder` relies on UID prefix, so we are safe.

            if os.path.exists(full_path):
                continue

            # 2. Fetch Full Content
            # RFC822 gets the whole message including headers and attachments
            resp, data = src.uid("fetch", uid, "(RFC822)")
            if resp != "OK" or not data or data[0] is None:
                safe_print(f"[{folder_name}] ERROR Fetch Body | UID {uid_str}")
                continue

            raw_email = None
            for item in data:
                if isinstance(item, tuple):
                    raw_email = item[1]
                    break

            if raw_email:
                try:
                    with open(full_path, "wb") as f:
                        f.write(raw_email)
                    safe_print(f"[{folder_name}] SAVED  | {filename[:60]}...")
                except OSError as e:
                    # Valid filename might still fail if path too long
                    safe_print(f"[{folder_name}] ERROR Write | {uid_str}: {e}")
            else:
                safe_print(f"[{folder_name}] EMPTY Content | UID {uid_str}")

        except Exception as e:
            safe_print(f"[{folder_name}] ERROR Processing UID {uid}: {e}")


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


def is_gmail_label_folder(folder_name):
    """
    Determines if a folder represents a Gmail label (user-created or system label
    that should be preserved).
    Excludes system folders like All Mail, Spam, Trash, Drafts.
    """
    # Exclude system folders that aren't really "labels"
    if folder_name in GMAIL_SYSTEM_FOLDERS:
        return False

    # INBOX is a special case - it's a label in Gmail
    if folder_name == "INBOX":
        return True

    # [Gmail]/Sent Mail and [Gmail]/Starred are labels worth preserving
    if folder_name in ("[Gmail]/Sent Mail", "[Gmail]/Starred"):
        return True

    # Any folder NOT under [Gmail]/ is a user label
    if not folder_name.startswith("[Gmail]/"):
        return True

    return False


def get_message_ids_in_folder(imap_conn, folder_name, progress_callback=None):
    """
    Returns a set of Message-IDs for all emails in a given folder.
    Optional progress_callback(current, total) for progress reporting.
    """
    message_ids = set()

    try:
        imap_conn.select(f'"{folder_name}"', readonly=True)
    except Exception as e:
        safe_print(f"Could not select folder {folder_name}: {e}")
        return message_ids

    try:
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data or not data[0]:
            return message_ids

        uids = data[0].split()
        if not uids:
            return message_ids

        total_uids = len(uids)

        # Fetch Message-IDs in batches - use larger batch for header-only fetches
        batch_size = 200
        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            uid_range = b",".join(batch)

            # Report progress
            if progress_callback:
                progress_callback(min(i + batch_size, total_uids), total_uids)

            try:
                resp, items = imap_conn.uid("fetch", uid_range, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
                if resp != "OK":
                    continue

                for item in items:
                    if isinstance(item, tuple) and len(item) >= 2:
                        header_data = item[1]
                        if isinstance(header_data, bytes):
                            header_str = header_data.decode("utf-8", errors="ignore")
                            # Extract Message-ID from header
                            for line in header_str.split("\n"):
                                if line.lower().startswith("message-id:"):
                                    msg_id = line.split(":", 1)[1].strip()
                                    if msg_id:
                                        message_ids.add(msg_id)
                                    break
            except Exception as e:
                safe_print(f"Error fetching batch in {folder_name}: {e}")
                # Try to keep connection alive
                try:
                    imap_conn.noop()
                except Exception:
                    pass
                continue

    except Exception as e:
        safe_print(f"Error searching folder {folder_name}: {e}")

    return message_ids


def build_labels_manifest(imap_conn, local_path):
    """
    Builds a manifest mapping Message-IDs to their Gmail labels.
    Scans all folders (labels) in the account and records which Message-IDs
    appear in each label.

    Returns a dict: { "message-id": ["Label1", "Label2", ...], ... }
    Saves the manifest to labels_manifest.json in the backup directory.
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

    label_folders = [f for f in all_folders if is_gmail_label_folder(f)]

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
        message_ids = get_message_ids_in_folder(imap_conn, folder_name, progress_cb)
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
                manifest[msg_id] = []
            if label_name not in manifest[msg_id]:
                manifest[msg_id].append(label_name)

        folder_elapsed = time.time() - folder_start
        total_emails_scanned += len(message_ids)
        safe_print(f"  -> {len(message_ids)} emails with label '{label_name}' ({folder_elapsed:.1f}s)")

    # Summary
    total_elapsed = time.time() - start_time
    safe_print("\nManifest building complete:")
    safe_print(f"  - Folders scanned: {total_folders}")
    safe_print(f"  - Total email-label mappings: {total_emails_scanned}")
    safe_print(f"  - Unique emails with labels: {len(manifest)}")
    safe_print(f"  - Time elapsed: {total_elapsed:.1f}s")

    # Save manifest
    manifest_path = os.path.join(local_path, "labels_manifest.json")
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        safe_print(f"\nLabels manifest saved to: {manifest_path}")
    except Exception as e:
        safe_print(f"Error saving manifest: {e}")

    return manifest


def load_labels_manifest(local_path):
    """
    Loads an existing labels manifest from the backup directory.
    Returns the manifest dict or empty dict if not found.
    """
    manifest_path = os.path.join(local_path, "labels_manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def backup_folder(src_main, folder_name, local_base_path, src_conf):
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

    if total_on_server == 0:
        safe_print(f"Folder {folder_name} is empty.")
        return

    # Incremental Optimization
    # Read local directory to find UIDs we already have
    existing_uids = get_existing_uids(local_folder_path)

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

    # Source
    parser.add_argument("--src-host", default=os.getenv("SRC_IMAP_HOST"), help="Source IMAP Server")
    parser.add_argument("--src-user", default=os.getenv("SRC_IMAP_USERNAME"), help="Source Username")
    parser.add_argument("--src-pass", default=os.getenv("SRC_IMAP_PASSWORD"), help="Source Password")

    # Destination (Local Path)
    env_path = os.getenv("BACKUP_LOCAL_PATH")
    parser.add_argument("--dest-path", default=env_path, help="Local destination path (Mandatory)")

    # Config
    parser.add_argument("--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Thread count")
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Emails per batch")

    # Gmail Labels
    parser.add_argument(
        "--preserve-labels",
        action="store_true",
        help="Gmail only: Create a labels_manifest.json mapping Message-IDs to labels for restoration",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Gmail only: Build the labels manifest and exit without downloading emails",
    )

    parser.add_argument("folder", nargs="?", help="Specific folder to backup")

    args = parser.parse_args()

    # Validate
    missing = []
    if not args.src_host:
        missing.append("SRC_IMAP_HOST")
    if not args.src_user:
        missing.append("SRC_IMAP_USERNAME")
    if not args.src_pass:
        missing.append("SRC_IMAP_PASSWORD")

    if missing:
        print(f"Error: Missing credentials: {', '.join(missing)}")
        sys.exit(1)

    if not args.dest_path:
        print("Error: Destination path is required.")
        print("Please provide --dest-path or set environment variable BACKUP_LOCAL_PATH.")
        sys.exit(1)

    global MAX_WORKERS, BATCH_SIZE
    MAX_WORKERS = args.workers
    BATCH_SIZE = args.batch

    src_conf = (args.src_host, args.src_user, args.src_pass)

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
    print(f"Destination Path: {local_path}")
    if args.manifest_only:
        print("Mode            : Manifest Only (no email download)")
    elif args.folder:
        print(f"Target Folder   : {args.folder}")
    if args.preserve_labels or args.manifest_only:
        print("Preserve Labels : Yes (Gmail)")
    print("-----------------------------\n")

    try:
        src = imap_common.get_imap_connection(*src_conf)
        if not src:
            sys.exit(1)

        # Build labels manifest BEFORE backing up emails
        # This way we capture the label state at backup time
        if args.preserve_labels or args.manifest_only:
            print("Building Gmail labels manifest...")
            print("This scans all folders to map Message-IDs to labels.\n")
            build_labels_manifest(src, local_path)
            print("")  # Blank line after manifest building

        # If manifest-only mode, we're done
        if args.manifest_only:
            src.logout()
            manifest_path = os.path.join(local_path, "labels_manifest.json")
            print("\nManifest-only mode complete.")
            print(f"Labels manifest saved to: {manifest_path}")
            print("\nTo download emails, run again without --manifest-only:")
            print(f'  python3 backup_imap_emails.py --dest-path "{local_path}" "[Gmail]/All Mail"')
            sys.exit(0)

        if args.folder:
            backup_folder(src, args.folder, local_path, src_conf)
        else:
            folders = imap_common.list_selectable_folders(src)
            for name in folders:
                # Ensure connection is alive (reconnect on broken pipe, timeout, etc.)
                src = imap_common.ensure_connection(src, *src_conf)
                if not src:
                    print("Fatal: Could not reconnect to IMAP server. Aborting.")
                    sys.exit(1)
                backup_folder(src, name, local_path, src_conf)

        src.logout()
        print("\nBackup completed successfully.")

        if args.preserve_labels:
            manifest_path = os.path.join(local_path, "labels_manifest.json")
            print(f"\nGmail labels manifest saved to: {manifest_path}")
            print("Use this file when restoring to reapply labels to emails.")

    except KeyboardInterrupt:
        print("\nBackup interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")


if __name__ == "__main__":
    main()
