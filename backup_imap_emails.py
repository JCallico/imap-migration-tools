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

Configuration:
  SRC_IMAP_SERVER, SRC_IMAP_USERNAME, SRC_IMAP_PASSWORD: Source credentials.
  BACKUP_LOCAL_PATH: Destination local directory.
  
Usage:
  python3 backup_imap_emails.py --dest-path "./my_backup"
"""

import imaplib
import os
import sys
import re
import concurrent.futures
import threading
import argparse
import imap_common

# Defaults
MAX_WORKERS = 10
BATCH_SIZE = 10

# Thread-local storage
thread_local = threading.local()
print_lock = threading.Lock()

def safe_print(message):
    t_name = threading.current_thread().name
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with print_lock:
        print(f"[{short_name}] {message}")

def get_thread_connection(src_conf):
    if not hasattr(thread_local, "src") or thread_local.src is None:
        thread_local.src = imap_common.get_imap_connection(*src_conf)
    try:
        if thread_local.src: thread_local.src.noop()
    except:
        thread_local.src = imap_common.get_imap_connection(*src_conf)
    return thread_local.src

def process_batch(uids, folder_name, src_conf, local_folder_path):
    src = get_thread_connection(src_conf)
    if not src:
        safe_print(f"Error: Could not establish connection for batch.")
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
            uid_str = uid.decode('utf-8') if isinstance(uid, bytes) else str(uid)
            
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
            resp, data = src.uid('fetch', uid, '(RFC822)')
            if resp != 'OK' or not data or data[0] is None:
                 safe_print(f"[{folder_name}] ERROR Fetch Body | UID {uid_str}")
                 continue
            
            raw_email = None
            for item in data:
                if isinstance(item, tuple):
                    raw_email = item[1]
                    break
            
            if raw_email:
                try:
                    with open(full_path, 'wb') as f:
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
                parts = filename.split('_', 1)
                if parts[0].isdigit():
                    existing.add(parts[0])
    except Exception:
        pass
    return existing

def backup_folder(src_main, folder_name, local_base_path, src_conf):
    safe_print(f"--- Processing Folder: {folder_name} ---")
    
    # create local path
    # Handle folder separators. IMAP output might be "Parent/Child"
    # We rely on OS to handle "Parent/Child" as subdirectories using join
    # But clean the segments
    cleaned_name = folder_name.replace('/', os.sep)
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
    resp, data = src_main.uid('search', None, 'ALL')
    if resp != 'OK': return
    
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
        u_str = u.decode('utf-8') if isinstance(u, bytes) else str(u)
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
    uid_batches = [uids_to_download[i:i + BATCH_SIZE] for i in range(0, len(uids_to_download), BATCH_SIZE)]
    
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
    parser.add_argument("--src-host", default=os.getenv("SRC_IMAP_SERVER"), help="Source IMAP Server")
    parser.add_argument("--src-user", default=os.getenv("SRC_IMAP_USERNAME"), help="Source Username")
    parser.add_argument("--src-pass", default=os.getenv("SRC_IMAP_PASSWORD"), help="Source Password")
    
    # Destination (Local Path)
    env_path = os.getenv("BACKUP_LOCAL_PATH")
    parser.add_argument("--dest-path", default=env_path, help="Local destination path (Mandatory)")
    
    # Config
    parser.add_argument("--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Thread count")
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Emails per batch")
    parser.add_argument("folder", nargs="?", help="Specific folder to backup")

    args = parser.parse_args()
    
    # Validate
    missing = []
    if not args.src_host: missing.append("SRC_IMAP_SERVER")
    if not args.src_user: missing.append("SRC_IMAP_USERNAME")
    if not args.src_pass: missing.append("SRC_IMAP_PASSWORD")
    
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
            
    print("\n--- Backup Configuration ---")
    print(f"Source: {args.src_host} ({args.src_user})")
    print(f"Destination: {local_path}")
    if args.folder:
        print(f"Folder: {args.folder}")
    print("----------------------------\n")
            
    try:
        src = imap_common.get_imap_connection(*src_conf)
        if not src: sys.exit(1)
        
        if args.folder:
             backup_folder(src, args.folder, local_path, src_conf)
        else:
            typ, folders = src.list()
            if typ == 'OK':
                for f_info in folders:
                    name = imap_common.normalize_folder_name(f_info)
                    backup_folder(src, name, local_path, src_conf)
        
        src.logout()
        print("\nBackup completed successfully.")
        
    except KeyboardInterrupt:
        print("\nBackup interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")

if __name__ == "__main__":
    main()
