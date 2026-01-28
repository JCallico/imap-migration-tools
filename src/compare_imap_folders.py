"""
IMAP Folder Comparison Script

This script compares email counts between a source IMAP account and a destination IMAP account.
It iterates through all folders found in the source account and checks the corresponding
folder in the destination account.

Configuration (Environment Variables):
  Source Account:
    SRC_IMAP_HOST       : Source IMAP Host
    SRC_IMAP_USERNAME   : Source Username/Email
    SRC_IMAP_PASSWORD   : Source Password

  Destination Account:
    DEST_IMAP_HOST      : Destination IMAP Host
    DEST_IMAP_USERNAME  : Destination Username/Email
    DEST_IMAP_PASSWORD  : Destination Password

Usage:
  python3 compare_imap_folders.py
"""

import argparse
import os
import sys

import imap_common


def get_email_count(conn, folder_name):
    try:
        # Select folder in read-only mode
        # Quote folder name handles spaces
        typ, data = conn.select(f'"{folder_name}"', readonly=True)
        if typ != "OK":
            return None

        # SELECT command returns the number of messages in data[0]
        # data[0] is bytes, e.g. b'123'
        if data and data[0]:
            return int(data[0])
        return 0

    except Exception:
        # print(f"Error checking {folder_name}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Compare email counts between two IMAP accounts.")

    # Source args
    parser.add_argument("--src-host", default=os.getenv("SRC_IMAP_HOST"), help="Source IMAP Server")
    parser.add_argument("--src-user", default=os.getenv("SRC_IMAP_USERNAME"), help="Source Username")
    parser.add_argument("--src-pass", default=os.getenv("SRC_IMAP_PASSWORD"), help="Source Password")

    # Dest args
    parser.add_argument("--dest-host", default=os.getenv("DEST_IMAP_HOST"), help="Destination IMAP Server")
    parser.add_argument("--dest-user", default=os.getenv("DEST_IMAP_USERNAME"), help="Destination Username")
    parser.add_argument("--dest-pass", default=os.getenv("DEST_IMAP_PASSWORD"), help="Destination Password")

    args = parser.parse_args()

    # Assign to variables
    SRC_HOST = args.src_host
    SRC_USER = args.src_user
    SRC_PASS = args.src_pass
    DEST_HOST = args.dest_host
    DEST_USER = args.dest_user
    DEST_PASS = args.dest_pass

    # Validation
    missing_vars = []
    if not SRC_HOST:
        missing_vars.append("SRC_IMAP_HOST")
    if not SRC_USER:
        missing_vars.append("SRC_IMAP_USERNAME")
    if not SRC_PASS:
        missing_vars.append("SRC_IMAP_PASSWORD")
    if not DEST_HOST:
        missing_vars.append("DEST_IMAP_HOST")
    if not DEST_USER:
        missing_vars.append("DEST_IMAP_USERNAME")
    if not DEST_PASS:
        missing_vars.append("DEST_IMAP_PASSWORD")

    if missing_vars:
        print(f"Error: Missing configuration variables: {', '.join(missing_vars)}")
        print("Please provide them via environment variables or command-line arguments.")
        sys.exit(1)

    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {SRC_HOST}")
    print(f"Source User     : {SRC_USER}")
    print(f"Destination Host: {DEST_HOST}")
    print(f"Destination User: {DEST_USER}")
    print("-----------------------------\n")

    src = None
    dest = None

    try:
        # Connect to Source
        print("Connecting to Source...")
        src = imap_common.get_imap_connection(SRC_HOST, SRC_USER, SRC_PASS)
        if not src:
            return

        # Connect to Dest
        print("Connecting to Destination...")
        dest = imap_common.get_imap_connection(DEST_HOST, DEST_USER, DEST_PASS)
        if not dest:
            return

        # List Source Folders
        print("Listing folders in Source...")
        folders = imap_common.list_selectable_folders(src)
        if not folders:
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
        for folder_name in folders:

            # Get Counts
            src_count = get_email_count(src, folder_name)
            dest_count = get_email_count(dest, folder_name)

            # Format for display
            src_str = str(src_count) if src_count is not None else "Err"
            dest_str = str(dest_count) if dest_count is not None else "N/A"  # N/A usually means folder doesn't exist

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
        print(f"{'TOTAL':<40} | {total_src:>10} | {total_dest:>10} | {total_src - total_dest:>10}")

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
