"""
IMAP Folder Comparison Script

This script compares email counts between a source and a destination.
Each side can be either an IMAP account or a local backup folder.
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

Also supports local folders as source and/or destination:
    SRC_LOCAL_PATH      : Source local folder (backup root)
    DEST_LOCAL_PATH     : Destination local folder (backup root)

Usage:
  python3 compare_imap_folders.py

Examples:
        # IMAP -> IMAP
        python3 compare_imap_folders.py \
            --src-host "imap.source.com" \
            --src-user "source@example.com" \
            --src-pass "source-app-password" \
            --dest-host "imap.dest.com" \
            --dest-user "dest@example.com" \
            --dest-pass "dest-app-password"

        # Local -> IMAP
        python3 compare_imap_folders.py \
            --src-path "./my_backup" \
            --dest-host "imap.dest.com" \
            --dest-user "dest@example.com" \
            --dest-pass "dest-app-password"

        # IMAP -> Local
        python3 compare_imap_folders.py \
            --src-host "imap.source.com" \
            --src-user "source@example.com" \
            --src-pass "source-app-password" \
            --dest-path "./my_backup"
"""

import argparse
import os
import sys
from typing import Optional

import imap_common


def get_email_count(conn, folder_name):
    """Return the IMAP message count for a folder, or None on error."""
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


def _is_ignored_local_dir(dirname: str) -> bool:
    return dirname.startswith(".") or dirname == "__pycache__"


def list_local_folders(local_root: str) -> list[str]:
    """List all folders under a local backup root in IMAP-style names.

    The local backup format is expected to mirror IMAP folder hierarchy using
    subdirectories (e.g. "[Gmail]/All Mail" becomes "[Gmail]/All Mail/").
    """
    folders: set[str] = set()

    for dirpath, dirnames, _filenames in os.walk(local_root):
        dirnames[:] = [d for d in dirnames if not _is_ignored_local_dir(d)]

        if os.path.abspath(dirpath) == os.path.abspath(local_root):
            continue

        rel = os.path.relpath(dirpath, local_root)
        if rel == ".":
            continue

        parts = [p for p in rel.split(os.sep) if p and not _is_ignored_local_dir(p)]
        if not parts:
            continue

        folders.add("/".join(parts))

    return sorted(folders)


def get_local_email_count(local_root: str, folder_name: str) -> Optional[int]:
    """Return the count of .eml files in a local folder, or None if missing/unreadable."""
    folder_path = os.path.join(local_root, *folder_name.split("/"))
    if not os.path.isdir(folder_path):
        return None

    try:
        count = 0
        for filename in os.listdir(folder_path):
            if not filename.endswith(".eml"):
                continue
            full_path = os.path.join(folder_path, filename)
            if os.path.isfile(full_path):
                count += 1
        return count
    except OSError:
        return None


def main():
    parser = argparse.ArgumentParser(description="Compare email counts between two IMAP accounts.")

    parser.add_argument(
        "--src-path",
        default=os.getenv("SRC_LOCAL_PATH"),
        help="Source local folder (backup root). If set, IMAP source args are ignored.",
    )
    parser.add_argument(
        "--dest-path",
        default=os.getenv("DEST_LOCAL_PATH"),
        help="Destination local folder (backup root). If set, IMAP destination args are ignored.",
    )

    # Source args
    parser.add_argument("--src-host", default=os.getenv("SRC_IMAP_HOST"), help="Source IMAP Server")
    parser.add_argument("--src-user", default=os.getenv("SRC_IMAP_USERNAME"), help="Source Username")
    parser.add_argument("--src-pass", default=os.getenv("SRC_IMAP_PASSWORD"), help="Source Password")

    # Dest args
    parser.add_argument("--dest-host", default=os.getenv("DEST_IMAP_HOST"), help="Destination IMAP Server")
    parser.add_argument("--dest-user", default=os.getenv("DEST_IMAP_USERNAME"), help="Destination Username")
    parser.add_argument("--dest-pass", default=os.getenv("DEST_IMAP_PASSWORD"), help="Destination Password")

    args = parser.parse_args()

    src_is_local = bool(args.src_path)
    dest_is_local = bool(args.dest_path)

    # Validation
    missing_vars = []

    if src_is_local:
        if not os.path.isdir(args.src_path):
            print(f"Error: Source local path does not exist or is not a directory: {args.src_path}")
            sys.exit(1)
    else:
        if not args.src_host:
            missing_vars.append("SRC_IMAP_HOST")
        if not args.src_user:
            missing_vars.append("SRC_IMAP_USERNAME")
        if not args.src_pass:
            missing_vars.append("SRC_IMAP_PASSWORD")

    if dest_is_local:
        if not os.path.isdir(args.dest_path):
            print(f"Error: Destination local path does not exist or is not a directory: {args.dest_path}")
            sys.exit(1)
    else:
        if not args.dest_host:
            missing_vars.append("DEST_IMAP_HOST")
        if not args.dest_user:
            missing_vars.append("DEST_IMAP_USERNAME")
        if not args.dest_pass:
            missing_vars.append("DEST_IMAP_PASSWORD")

    if missing_vars:
        print(f"Error: Missing configuration variables: {', '.join(missing_vars)}")
        print("Please provide them via environment variables or command-line arguments.")
        sys.exit(1)

    print("\n--- Configuration Summary ---")
    if src_is_local:
        print(f"Source (Local)  : {args.src_path}")
    else:
        print(f"Source Host     : {args.src_host}")
        print(f"Source User     : {args.src_user}")

    if dest_is_local:
        print(f"Destination (Local): {args.dest_path}")
    else:
        print(f"Destination Host: {args.dest_host}")
        print(f"Destination User: {args.dest_user}")
    print("-----------------------------\n")

    src = None
    dest = None

    try:
        if not src_is_local:
            # Connect to Source
            print("Connecting to Source...")
            src = imap_common.get_imap_connection(args.src_host, args.src_user, args.src_pass)
            if not src:
                return

        if not dest_is_local:
            # Connect to Dest
            print("Connecting to Destination...")
            dest = imap_common.get_imap_connection(args.dest_host, args.dest_user, args.dest_pass)
            if not dest:
                return

        # List Source Folders
        print("Listing folders in Source...")
        if src_is_local:
            folders = list_local_folders(args.src_path)
        else:
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
            if src_is_local:
                src_count = get_local_email_count(args.src_path, folder_name)
            else:
                src_count = get_email_count(src, folder_name)

            if dest_is_local:
                dest_count = get_local_email_count(args.dest_path, folder_name)
            else:
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
