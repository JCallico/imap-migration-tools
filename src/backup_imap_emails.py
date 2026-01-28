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


# Standard IMAP flags that can be preserved during migration
# \Recent is session-specific and cannot be set by clients
# \Deleted should not be preserved as it marks messages for removal
PRESERVABLE_FLAGS = {"\\Seen", "\\Answered", "\\Flagged", "\\Draft"}


def get_message_info_in_folder(imap_conn, folder_name, progress_callback=None):
    """
    Returns a dict of Message-IDs and their IMAP flags for all emails in a folder.
    Returns: { "message-id": {"flags": ["\\Seen", "\\Flagged", ...]}, ... }
    Optional progress_callback(current, total) for progress reporting.
    """
    message_info = {}

    try:
        imap_conn.select(f'"{folder_name}"', readonly=True)
    except Exception as e:
        safe_print(f"Could not select folder {folder_name}: {e}")
        return message_info

    try:
        resp, data = imap_conn.uid("search", None, "ALL")
        if resp != "OK" or not data or not data[0]:
            return message_info

        uids = data[0].split()
        if not uids:
            return message_info

        total_uids = len(uids)

        # Fetch Message-IDs and FLAGS in batches - use larger batch for header-only fetches
        batch_size = 200
        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            uid_range = b",".join(batch)

            # Report progress
            if progress_callback:
                progress_callback(min(i + batch_size, total_uids), total_uids)

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
                        for flag in PRESERVABLE_FLAGS:
                            if flag in meta_str:
                                flags.append(flag)

                        # Second element contains the header
                        header_data = item[1]
                        if isinstance(header_data, bytes):
                            header_str = header_data.decode("utf-8", errors="ignore")
                            # Extract Message-ID from header
                            for line in header_str.split("\n"):
                                if line.lower().startswith("message-id:"):
                                    msg_id = line.split(":", 1)[1].strip()
                                    if msg_id:
                                        message_info[msg_id] = {"flags": flags}
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

    return message_info


def get_message_ids_in_folder(imap_conn, folder_name, progress_callback=None):
    """
    Returns a set of Message-IDs for all emails in a given folder.
    This is a convenience wrapper around get_message_info_in_folder.
    Optional progress_callback(current, total) for progress reporting.
    """
    info = get_message_info_in_folder(imap_conn, folder_name, progress_callback)
    return set(info.keys())


def build_labels_manifest(imap_conn, local_path):
    """
    Builds a manifest mapping Message-IDs to their Gmail labels and IMAP flags.
    Scans all folders (labels) in the account and records which Message-IDs
    appear in each label, plus their flags from [Gmail]/All Mail.

    Returns a dict: { "message-id": {"labels": ["Label1", ...], "flags": ["\\Seen", ...]}, ... }
    Saves the manifest to labels_manifest.json in the backup directory.
    """
    import time

    manifest = {}
    start_time = time.time()
    total_emails_scanned = 0

    safe_print("--- Building Gmail Labels Manifest ---")

    # Get all folders
    try:
        typ, folders = imap_conn.list()
        if typ != "OK":
            safe_print("Error: Could not list folders for label mapping.")
            return manifest
    except Exception as e:
        safe_print(f"Error listing folders: {e}")
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

    all_mail_info = get_message_info_in_folder(imap_conn, "[Gmail]/All Mail", all_mail_progress_cb)
    print()  # New line after progress

    # Initialize manifest with flags from All Mail
    for msg_id, info in all_mail_info.items():
        manifest[msg_id] = {"labels": [], "flags": info.get("flags", [])}

    all_mail_elapsed = time.time() - all_mail_start
    # Count flag statistics
    read_count = sum(1 for m in manifest.values() if "\\Seen" in m.get("flags", []))
    flagged_count = sum(1 for m in manifest.values() if "\\Flagged" in m.get("flags", []))
    safe_print(f"  -> {len(all_mail_info)} emails scanned ({all_mail_elapsed:.1f}s)")
    safe_print(f"  -> Read: {read_count}, Unread: {len(manifest) - read_count}, Starred: {flagged_count}\n")

    # Keep connection alive
    try:
        imap_conn.noop()
    except Exception:
        pass

    # Parse folder names and filter to label folders
    label_folders = []
    for f_info in folders:
        name = imap_common.normalize_folder_name(f_info)
        if is_gmail_label_folder(name):
            label_folders.append(name)

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
                # Email not in All Mail (rare, but handle it)
                manifest[msg_id] = {"labels": [], "flags": []}
            if label_name not in manifest[msg_id]["labels"]:
                manifest[msg_id]["labels"].append(label_name)

        folder_elapsed = time.time() - folder_start
        total_emails_scanned += len(message_ids)
        safe_print(f"  -> {len(message_ids)} emails with label '{label_name}' ({folder_elapsed:.1f}s)")

    # Summary
    total_elapsed = time.time() - start_time
    read_count = sum(1 for m in manifest.values() if "\\Seen" in m.get("flags", []))
    flagged_count = sum(1 for m in manifest.values() if "\\Flagged" in m.get("flags", []))
    safe_print("\nManifest building complete:")
    safe_print(f"  - Folders scanned: {total_folders + 1}")  # +1 for All Mail
    safe_print(f"  - Total email-label mappings: {total_emails_scanned}")
    safe_print(f"  - Unique emails: {len(manifest)}")
    safe_print(f"  - Read: {read_count}, Unread: {len(manifest) - read_count}, Starred: {flagged_count}")
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


def build_flags_manifest(imap_conn, local_path, folders_to_scan=None):
    """
    Builds a manifest mapping Message-IDs to their IMAP flags.
    For non-Gmail servers, scans specified folders (or all folders if not specified).

    Returns a dict: { "message-id": {"flags": ["\\Seen", ...]}, ... }
    Saves the manifest to flags_manifest.json in the backup directory.
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
        folder_info = get_message_info_in_folder(imap_conn, folder_name, progress_cb)
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
    read_count = sum(1 for m in manifest.values() if "\\Seen" in m.get("flags", []))
    flagged_count = sum(1 for m in manifest.values() if "\\Flagged" in m.get("flags", []))
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
        "--preserve-flags",
        action="store_true",
        help="Preserve IMAP flags (read/unread, starred, answered, draft) in manifest for restoration",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Gmail only: Build the labels manifest and exit without downloading emails",
    )
    parser.add_argument(
        "--gmail-mode",
        action="store_true",
        help="Gmail backup mode: Build labels manifest and backup [Gmail]/All Mail only (recommended)",
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
    print("-----------------------------\n")

    try:
        src = imap_common.get_imap_connection(*src_conf)
        if not src:
            sys.exit(1)

        # Build labels manifest BEFORE backing up emails (Gmail mode)
        # This way we capture the label state at backup time
        if args.preserve_labels or args.manifest_only or args.gmail_mode:
            print("Building Gmail labels manifest...")
            print("This scans all folders to map Message-IDs to labels and flags.\n")
            build_labels_manifest(src, local_path)
            print("")  # Blank line after manifest building
        # Build flags-only manifest for non-Gmail servers
        elif args.preserve_flags:
            print("Building flags manifest...")
            print("This scans folders to capture read/starred/etc status.\n")
            # Get folders to scan
            folders_to_scan = [args.folder] if args.folder else None
            build_flags_manifest(src, local_path, folders_to_scan)
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

        # Gmail mode: backup only [Gmail]/All Mail
        if args.gmail_mode:
            backup_folder(src, "[Gmail]/All Mail", local_path, src_conf)
        elif args.folder:
            backup_folder(src, args.folder, local_path, src_conf)
        else:
            typ, folders = src.list()
            if typ == "OK":
                for f_info in folders:
                    name = imap_common.normalize_folder_name(f_info)
                    backup_folder(src, name, local_path, src_conf)

        src.logout()
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
        print("\nBackup interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")


if __name__ == "__main__":
    main()
