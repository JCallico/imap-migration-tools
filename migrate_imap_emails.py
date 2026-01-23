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
    SRC_IMAP_SERVER     : Source IMAP Host (e.g., imap.gmail.com)
    SRC_IMAP_USERNAME   : Source Username/Email
    SRC_IMAP_PASSWORD   : Source Password (or App Password)

  Destination Account:
    DEST_IMAP_SERVER    : Destination IMAP Host
    DEST_IMAP_USERNAME  : Destination Username/Email
    DEST_IMAP_PASSWORD  : Destination Password

  Options:
    DELETE_FROM_SOURCE  : Set to "true" to delete emails from source after successful transfer.
                          Default is "false" (Copy only).
    MAX_WORKERS         : Number of concurrent threads (default: 10).
    BATCH_SIZE          : Number of emails to process in a batch per thread (default: 10).

Usage Example:
  export SRC_IMAP_SERVER="imap.gmail.com"
  export SRC_IMAP_USERNAME="user@gmail.com"
  export SRC_IMAP_PASSWORD="secretpassword"
  export DEST_IMAP_SERVER="imap.other.com"
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
from email.header import decode_header
import concurrent.futures
import threading

# Configuration defaults
DELETE_FROM_SOURCE_DEFAULT = False
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 10))  # Number of concurrent threads
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 10))  # Emails per batch per thread

# Thread-local storage for IMAP connections
thread_local = threading.local()
print_lock = threading.Lock()

def safe_print(message):
    t_name = threading.current_thread().name
    # Shorten thread name for cleaner logs e.g. ThreadPoolExecutor-0_0 -> T-0_0
    short_name = t_name.replace("ThreadPoolExecutor-", "T-").replace("MainThread", "MAIN")
    with print_lock:
        print(f"[{short_name}] {message}")

def decode_mime_header(header_value):
    if not header_value:
        return "(No Subject)"
    try:
        decoded_list = decode_header(header_value)
        default_charset = 'utf-8'
        text_parts = []
        for bytes_data, encoding in decoded_list:
            if isinstance(bytes_data, bytes):
                if encoding:
                    try:
                        text_parts.append(bytes_data.decode(encoding, errors='ignore'))
                    except LookupError:
                        text_parts.append(bytes_data.decode(default_charset, errors='ignore'))
                else:
                    text_parts.append(bytes_data.decode(default_charset, errors='ignore'))
            else:
                text_parts.append(str(bytes_data))
        return "".join(text_parts)
    except Exception:
        return str(header_value)

def get_connection(host, user, password):
    try:
        conn = imaplib.IMAP4_SSL(host)
        conn.login(user, password)
        return conn
    except Exception as e:
        safe_print(f"Connection error to {host}: {e}")
        return None

def get_thread_connections(src_conf, dest_conf):
    # Initialize connections for this thread if they don't exist or are closed
    if not hasattr(thread_local, "src") or thread_local.src is None:
        thread_local.src = get_connection(*src_conf)
    if not hasattr(thread_local, "dest") or thread_local.dest is None:
        thread_local.dest = get_connection(*dest_conf)
    
    # Simple check if alive (noop)
    try:
        if thread_local.src: thread_local.src.noop()
    except:
        thread_local.src = get_connection(*src_conf)

    try:
        if thread_local.dest: thread_local.dest.noop()
    except:
        thread_local.dest = get_connection(*dest_conf)

    return thread_local.src, thread_local.dest

def normalize_folder_name(folder_info_str):
    # Regex to extract folder name: (flags) "delimiter" name
    list_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" "?(?P<name>.*)"?')
    match = list_pattern.search(folder_info_str)
    if match:
        return match.group('name').strip('"')
    return folder_info_str.split()[-1].strip('"')

def get_msg_details(imap_conn, uid):
    # Fetch headers (ID, Subject, Size)
    # BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)] prevents marking as read
    resp, data = imap_conn.uid('fetch', uid, '(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)])')
    
    if resp != 'OK':
        return None, None, None
        
    msg_id = None
    subject = "(No Subject)"
    size = 0
    
    for item in data:
        if isinstance(item, tuple):
            content = item[0].decode('utf-8', errors='ignore')
            
            # Parse Size
            size_match = re.search(r'RFC822\.SIZE\s+(\d+)', content)
            if size_match:
                size = int(size_match.group(1))
            
            # Parse Headers
            msg_bytes = item[1]
            parser = BytesParser()
            email_obj = parser.parsebytes(msg_bytes)
            msg_id = email_obj.get('Message-ID')
            raw_subject = email_obj.get('Subject')
            if raw_subject:
                subject = decode_mime_header(raw_subject)
            
    return msg_id, size, subject

def message_exists_in_dest(dest_conn, msg_id, src_size):
    if not msg_id:
        return False
    
    clean_id = msg_id.replace('"', '\\"')
    try:
        typ, data = dest_conn.search(None, f'(HEADER Message-ID "{clean_id}")')
        if typ != 'OK':
            return False
            
        dest_ids = data[0].split()
        if not dest_ids:
            return False
            
        for did in dest_ids:
            resp, items = dest_conn.fetch(did, '(RFC822.SIZE)')
            if resp == 'OK':
                for item in items:
                    if isinstance(item, bytes):
                        content = item.decode('utf-8', errors='ignore')
                    else: 
                        content = item[0].decode('utf-8', errors='ignore')
                    size_match = re.search(r'RFC822\.SIZE\s+(\d+)', content)
                    if size_match and int(size_match.group(1)) == src_size:
                        return True
    except Exception:
        return False
    return False

def process_batch(uids, folder_name, src_conf, dest_conf, delete_from_source):
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
            msg_id, size, subject = get_msg_details(src, uid)
            
            # Format size for display
            size_str = f"{size/1024:.1f}KB" if size else "0KB"
            
            is_duplicate = False
            if msg_id and size:
                is_duplicate = message_exists_in_dest(dest, msg_id, size)
            
            if is_duplicate:
                safe_print(f"[{folder_name}] {'SKIP (Dup)':<18} | {size_str:<8} | {subject[:40]}")
                # If it's a duplicate, we can still delete source if requested
                if delete_from_source:
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

def migrate_folder(src, dest, folder_name, delete_from_source, src_conf, dest_conf):
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
                delete_from_source
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
    # Source Credentials
    SRC_HOST = os.getenv("SRC_IMAP_SERVER")
    SRC_USER = os.getenv("SRC_IMAP_USERNAME")
    SRC_PASS = os.getenv("SRC_IMAP_PASSWORD")

    # Dest Credentials
    DEST_HOST = os.getenv("DEST_IMAP_SERVER")
    DEST_USER = os.getenv("DEST_IMAP_USERNAME")
    DEST_PASS = os.getenv("DEST_IMAP_PASSWORD")
    
    DELETE_SOURCE = os.getenv("DELETE_FROM_SOURCE", "false").lower() == "true"

    if not all([SRC_HOST, SRC_USER, SRC_PASS, DEST_HOST, DEST_USER, DEST_PASS]):
        print("Error: Missing environment variables.")
        sys.exit(1)

    print("\n--- Configuration Summary ---")
    print(f"Source Server   : {SRC_HOST}")
    print(f"Source User     : {SRC_USER}")
    print(f"Destination Host: {DEST_HOST}")
    print(f"Destination User: {DEST_USER}")
    print(f"Delete fm Source: {DELETE_SOURCE}")
    print("-----------------------------\n")

    src_conf = (SRC_HOST, SRC_USER, SRC_PASS)
    dest_conf = (DEST_HOST, DEST_USER, DEST_PASS)

    try:
        # Initial connection to list folders
        safe_print("Connecting to Source to list folders...")
        src_main = imaplib.IMAP4_SSL(SRC_HOST)
        src_main.login(SRC_USER, SRC_PASS)
        
        # We need a dummy dest connection just to pass to migrate_folder for folder creation checks?
        # Actually migrate_folder spawns threads, but it does folder creation validation on main thread first
        safe_print("Connecting to Destination...")
        dest_main = imaplib.IMAP4_SSL(DEST_HOST)
        dest_main.login(DEST_USER, DEST_PASS)
        
        typ, folders = src_main.list()
        
        if typ == 'OK':
            for folder_info in folders:
                name = normalize_folder_name(folder_info.decode('utf-8'))
                migrate_folder(src_main, dest_main, name, DELETE_SOURCE, src_conf, dest_conf)
        
        src_main.logout()
        dest_main.logout()

    except KeyboardInterrupt:
        safe_print("\n\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        safe_print(f"Fatal Error: {e}")

if __name__ == "__main__":
    main()
