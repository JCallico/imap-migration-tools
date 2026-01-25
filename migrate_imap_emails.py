"""
IMAP Email Migration Script

This script migrates emails from a source IMAP account to a destination IMAP account.
It iterates through all folders in the source account and copies emails to the destination.
It effectively handles folder creation and duplication checks (based on Message-ID and Size).

Features:
- Progressive migration (folder by folder, email by email).
- Safe duplicate detection (skips widely identical messages).
- Optional deletion from source (set DELETE_FROM_SOURCE=true).

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
    MAX_WORKERS         : Number of concurrent threads (default: 10).
    BATCH_SIZE          : Number of emails to process in a batch per thread (default: 10).

Usage Example:
  export SRC_IMAP_HOST="imap.gmail.com"
  export SRC_IMAP_USERNAME="user@gmail.com"
  export SRC_IMAP_PASSWORD="secretpassword"
  export DEST_IMAP_HOST="imap.other.com"
  export DEST_IMAP_USERNAME="user@other.com"
  export DEST_IMAP_PASSWORD="otherpassword"
  
  python3 migrate_imap_emails.py
"""

import imaplib
import os
import sys
import re
import email
from email.parser import BytesParser
import concurrent.futures
import threading
import argparse
import imap_common

# Configuration defaults
DELETE_FROM_SOURCE_DEFAULT = False
MAX_WORKERS = 10  # Initial default, updated in main
BATCH_SIZE = 10   # Initial default, updated in main

# Thread-local storage for IMAP connections
thread_local = threading.local()
print_lock = threading.Lock()

def safe_print(message):
    t_name = threading.current_thread().name
    # Shorten thread name for cleaner logs e.g. ThreadPoolExecutor-0_0 -> T-0_0
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with print_lock:
        print(f"[{short_name}] {message}")

def get_thread_connections(src_conf, dest_conf):
    # Initialize connections for this thread if they don't exist or are closed
    if not hasattr(thread_local, "src") or thread_local.src is None:
        thread_local.src = imap_common.get_imap_connection(*src_conf)
    if not hasattr(thread_local, "dest") or thread_local.dest is None:
        thread_local.dest = imap_common.get_imap_connection(*dest_conf)
    
    # Simple check if alive (noop)
    try:
        if thread_local.src: thread_local.src.noop()
    except:
        thread_local.src = imap_common.get_imap_connection(*src_conf)

    try:
        if thread_local.dest: thread_local.dest.noop()
    except:
        thread_local.dest = imap_common.get_imap_connection(*dest_conf)

    return thread_local.src, thread_local.dest

def process_batch(uids, folder_name, src_conf, dest_conf, delete_from_source, trash_folder=None):
    src, dest = get_thread_connections(src_conf, dest_conf)
    if not src or not dest:
        safe_print("Error: Could not establish connections in worker thread.")
        return

    # Select folders
    try:
        src.select(f'"{folder_name}"', readonly=False)
        dest.select(f'"{folder_name}"')
    except Exception as e:
        safe_print(f"Error selecting folder {folder_name} in worker: {e}")
        return

    deleted_count = 0
    for uid in uids:
        try:
            msg_id, size, subject = imap_common.get_msg_details(src, uid)
            
            # Format size for display
            size_str = f"{size/1024:.1f}KB" if size else "0KB"
            
            is_duplicate = False
            if msg_id and size:
                is_duplicate = imap_common.message_exists_in_folder(dest, msg_id, size)
            
            if is_duplicate:
                safe_print(f"[{folder_name}] {'SKIP (Dup)':<18} | {size_str:<8} | {subject[:40]}")
                # If it's a duplicate, we can still delete source if requested
                if delete_from_source:
                    # Move to trash if configured
                    if trash_folder and folder_name != trash_folder:
                        try:
                            src.uid('copy', uid, f'"{trash_folder}"')
                        except Exception:
                            pass
                    src.uid('store', uid, '+FLAGS', '(\\Deleted)')
                    deleted_count += 1
            else:
                # Fetch full message
                resp, data = src.uid('fetch', uid, '(FLAGS INTERNALDATE BODY.PEEK[])')
                if resp != 'OK':
                    safe_print(f"[{folder_name}] ERROR Fetch | {subject[:40]}")
                    continue
                
                msg_content = None
                flags = None
                date_str = None
                
                for item in data:
                    if isinstance(item, tuple):
                        msg_content = item[1]
                        meta = item[0].decode('utf-8', errors='ignore')
                        flags_match = re.search(r'FLAGS\s+\((.*?)\)', meta)
                        if flags_match:
                            flags = flags_match.group(1)
                        date_match = re.search(r'INTERNALDATE\s+"(.*?)"', meta)
                        if date_match:
                            date_str = f'"{date_match.group(1)}"'
                
                if msg_content:
                    valid_flags = f"({flags})" if flags else None
                    dest.append(f'"{folder_name}"', valid_flags, date_str, msg_content)
                    safe_print(f"[{folder_name}] {'COPIED':<18} | {size_str:<8} | {subject[:40]}")
                    
                    if delete_from_source:
                        # Move to trash if configured
                        if trash_folder and folder_name != trash_folder:
                            try:
                                src.uid('copy', uid, f'"{trash_folder}"')
                            except Exception:
                                pass
                        src.uid('store', uid, '+FLAGS', '(\\Deleted)')
                        deleted_count += 1

        except Exception as e:
            safe_print(f"[{folder_name}] ERROR Exec | UID {uid}: {e}")

    if delete_from_source and deleted_count > 0:
        try:
            src.expunge()
            safe_print(f"[{folder_name}] Expunged {deleted_count} messages from batch.")
        except Exception as e:
            safe_print(f"[{folder_name}] ERROR Expunge: {e}")

def migrate_folder(src, dest, folder_name, delete_from_source, src_conf, dest_conf, trash_folder=None):
    safe_print(f"--- Preparing Folder: {folder_name} ---")
    
    # Maintain folder structure
    try:
        if folder_name.upper() != "INBOX":
             dest.create(f'"{folder_name}"')
    except Exception:
        pass # Ignore if exists

    # Select in main thread to get UIDs
    try:
        src.select(f'"{folder_name}"', readonly=False)
        dest.select(f'"{folder_name}"')
    except Exception as e:
        safe_print(f"Skipping {folder_name}: {e}")
        return

    # Get UIDs
    # Search for UNDELETED to avoid processing messages marked for deletion but not yet expunged
    resp, data = src.uid('search', None, 'UNDELETED')
    if resp != 'OK':
        return
        
    uids = data[0].split()
    total = len(uids)
    
    if total == 0:
        safe_print(f"Folder {folder_name} is empty.")
        return

    safe_print(f"Found {total} messages. Starting parallel migration...")

    # Create batches
    uid_batches = [uids[i:i + BATCH_SIZE] for i in range(0, len(uids), BATCH_SIZE)]
    
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = []
        for batch in uid_batches:
            futures.append(executor.submit(
                process_batch, 
                batch, 
                folder_name, 
                src_conf, 
                dest_conf, 
                delete_from_source,
                trash_folder
            ))
        
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
    parser.add_argument("--delete", action="store_true", default=env_delete, help="Delete from source after migration (default: False)")
    
    parser.add_argument("--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Number of concurrent threads")
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Batch size per thread")

    args = parser.parse_args()

    # Assign to variables
    SRC_HOST = args.src_host
    SRC_USER = args.src_user
    SRC_PASS = args.src_pass
    DEST_HOST = args.dest_host
    DEST_USER = args.dest_user
    DEST_PASS = args.dest_pass
    DELETE_SOURCE = args.delete
    
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
    if not SRC_HOST: missing_vars.append("SRC_IMAP_HOST")
    if not SRC_USER: missing_vars.append("SRC_IMAP_USERNAME")
    if not SRC_PASS: missing_vars.append("SRC_IMAP_PASSWORD")
    if not DEST_HOST: missing_vars.append("DEST_IMAP_HOST")
    if not DEST_USER: missing_vars.append("DEST_IMAP_USERNAME")
    if not DEST_PASS: missing_vars.append("DEST_IMAP_PASSWORD")

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
                safe_print("Warning: Could not detect Trash folder. Emails will be marked \\Deleted only (standard IMAP delete).")
        
        # We need a dummy dest connection just to pass to migrate_folder for folder creation checks?
        safe_print("Connecting to Destination...")
        dest_main = imap_common.get_imap_connection(DEST_HOST, DEST_USER, DEST_PASS)
        if not dest_main:
             sys.exit(1)
        
        if TARGET_FOLDER:
            # Migration for specific folder
            if DELETE_SOURCE and trash_folder and TARGET_FOLDER == trash_folder:
                 safe_print(f"Aborting: Cannot migrate Trash folder '{TARGET_FOLDER}' while --delete is enabled. This would create a loop.")
                 sys.exit(1)
            
            safe_print(f"Starting migration for single folder: {TARGET_FOLDER}")
            # Verify folder exists first? imaplib usually handles select error if not found
            migrate_folder(src_main, dest_main, TARGET_FOLDER, DELETE_SOURCE, src_conf, dest_conf, trash_folder)
        else:
            # Migration for all folders
            typ, folders = src_main.list()
            if typ == 'OK':
                for folder_info in folders:
                    name = imap_common.normalize_folder_name(folder_info)
                    
                    # Auto-skip trash folder if we are utilizing it as a dump target
                    # This prevents re-migrating the emails we just moved to trash
                    if DELETE_SOURCE and trash_folder and name == trash_folder:
                        safe_print(f"Skipping migration of Trash folder '{name}' (preventing circular migration).")
                        continue

                    migrate_folder(src_main, dest_main, name, DELETE_SOURCE, src_conf, dest_conf, trash_folder)
        
        src_main.logout()
        dest_main.logout()

    except KeyboardInterrupt:
        safe_print("\n\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        safe_print(f"Fatal Error: {e}")

if __name__ == "__main__":
    main()