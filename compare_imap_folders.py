"""
IMAP Folder Comparison Script

This script compares email counts between a source IMAP account and a destination IMAP account.
It iterates through all folders found in the source account and checks the corresponding
folder in the destination account.

Configuration (Environment Variables):
  Source Account:
    SRC_IMAP_SERVER     : Source IMAP Host
    SRC_IMAP_USERNAME   : Source Username/Email
    SRC_IMAP_PASSWORD   : Source Password

  Destination Account:
    DEST_IMAP_SERVER    : Destination IMAP Host
    DEST_IMAP_USERNAME  : Destination Username/Email
    DEST_IMAP_PASSWORD  : Destination Password

Usage:
  python3 compare_imap_folders.py
"""

import imaplib
import os
import sys
import re

def normalize_folder_name(folder_info_str):
    # Regex to extract folder name: (flags) "delimiter" name
    list_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" "?(?P<name>.*)"?')
    match = list_pattern.search(folder_info_str)
    if match:
        return match.group('name').strip('"')
    return folder_info_str.split()[-1].strip('"')

def get_email_count(conn, folder_name):
    try:
        # Select folder in read-only mode
        # Quote folder name handles spaces
        typ, data = conn.select(f'"{folder_name}"', readonly=True)
        if typ != 'OK':
            return None
        
        # SELECT command returns the number of messages in data[0]
        # data[0] is bytes, e.g. b'123'
        if data and data[0]:
            return int(data[0])
        return 0

    except Exception as e:
        # print(f"Error checking {folder_name}: {e}")
        return None

def main():
    # Source Credentials
    SRC_HOST = os.getenv("SRC_IMAP_SERVER")
    SRC_USER = os.getenv("SRC_IMAP_USERNAME")
    SRC_PASS = os.getenv("SRC_IMAP_PASSWORD")

    # Dest Credentials
    DEST_HOST = os.getenv("DEST_IMAP_SERVER")
    DEST_USER = os.getenv("DEST_IMAP_USERNAME")
    DEST_PASS = os.getenv("DEST_IMAP_PASSWORD")

    if not all([SRC_HOST, SRC_USER, SRC_PASS, DEST_HOST, DEST_USER, DEST_PASS]):
        print("Error: Missing environment variables.")
        print("Please ensure SRC_* and DEST_* variables are set (same as migration script).")
        sys.exit(1)

    print("\n--- Configuration Comparison Summary ---")
    print(f"Source      : {SRC_USER} @ {SRC_HOST}")
    print(f"Destination : {DEST_USER} @ {DEST_HOST}")
    print("----------------------------------------\n")

    src = None
    dest = None

    try:
        # Connect to Source
        print("Connecting to Source...")
        src = imaplib.IMAP4_SSL(SRC_HOST)
        src.login(SRC_USER, SRC_PASS)

        # Connect to Dest
        print("Connecting to Destination...")
        dest = imaplib.IMAP4_SSL(DEST_HOST)
        dest.login(DEST_USER, DEST_PASS)

        # List Source Folders
        print("Listing folders in Source...")
        typ, folders = src.list()
        if typ != 'OK':
            print("Failed to list source folders.")
            return

        # Prepare Table Header
        header = f"{'Folder Name':<40} | {'Source':>10} | {'Dest':>10} | {'Diff':>10}"
        print("-" * len(header))
        print(header)
        print("-" * len(header))

        total_src = 0
        total_dest = 0

        # Iterate through Source folders
        for folder_info in folders:
            folder_info_str = folder_info.decode('utf-8')
            folder_name = normalize_folder_name(folder_info_str)
            
            # Get Counts
            src_count = get_email_count(src, folder_name)
            dest_count = get_email_count(dest, folder_name)

            # Format for display
            src_str = str(src_count) if src_count is not None else "Err"
            dest_str = str(dest_count) if dest_count is not None else "N/A" # N/A usually means folder doesn't exist

            diff_str = ""
            if src_count is not None and dest_count is not None:
                diff = src_count - dest_count
                diff_str = str(diff)
                total_src += src_count
                total_dest += dest_count
            elif src_count is not None:
                total_src += src_count

            print(f"{folder_name:<40} | {src_str:>10} | {dest_str:>10} | {diff_str:>10}")

        print("-" * len(header))
        print(f"{'TOTAL':<40} | {total_src:>10} | {total_dest:>10} | {total_src-total_dest:>10}")

    except Exception as e:
        print(f"\nFatal Error: {e}")
        if "Too many simultaneous connections" in str(e):
             print("Tip: Wait a few minutes for previous connections to timeout or check other active scripts.")

    finally:
        # Check source connection state and logout if possible
        if src:
            try:
                src.logout()
            except Exception:
                pass
        
        # Check dest connection state and logout if possible
        if dest:
            try:
                dest.logout()
            except Exception:
                pass

if __name__ == "__main__":
    main()
