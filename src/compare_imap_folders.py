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

    OAuth2 (Optional - instead of password):
    SRC_OAUTH2_CLIENT_ID     : OAuth2 Client ID
    SRC_OAUTH2_CLIENT_SECRET : OAuth2 Client Secret (required for Google)

  Destination Account:
    DEST_IMAP_HOST      : Destination IMAP Host
    DEST_IMAP_USERNAME  : Destination Username/Email
    DEST_IMAP_PASSWORD  : Destination Password

    OAuth2 (Optional - instead of password):
    DEST_OAUTH2_CLIENT_ID     : OAuth2 Client ID
    DEST_OAUTH2_CLIENT_SECRET : OAuth2 Client Secret (required for Google)

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
import imap_oauth2


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
    default_src_path = os.getenv("SRC_LOCAL_PATH")
    default_dest_path = os.getenv("DEST_LOCAL_PATH")

    # Phase 1: determine whether each side is local
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--src-path", default=default_src_path)
    pre_parser.add_argument("--dest-path", default=default_dest_path)
    pre_args, _ = pre_parser.parse_known_args()

    src_requires_imap = not bool(pre_args.src_path)
    dest_requires_imap = not bool(pre_args.dest_path)

    # Phase 2: full parser with conditional requirements
    parser = argparse.ArgumentParser(description="Compare email counts between two IMAP accounts.")
    parser.add_argument(
        "--src-path",
        default=default_src_path,
        help="Source local folder (backup root). If set, IMAP source args are ignored.",
    )
    parser.add_argument(
        "--dest-path",
        default=default_dest_path,
        help="Destination local folder (backup root). If set, IMAP destination args are ignored.",
    )

    # Source args
    default_src_host = os.getenv("SRC_IMAP_HOST")
    default_src_user = os.getenv("SRC_IMAP_USERNAME")
    default_src_pass = os.getenv("SRC_IMAP_PASSWORD")
    default_src_client_id = os.getenv("SRC_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--src-host",
        default=default_src_host,
        required=src_requires_imap and not bool(default_src_host),
        help="Source IMAP Server (or SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--src-user",
        default=default_src_user,
        required=src_requires_imap and not bool(default_src_user),
        help="Source Username (or SRC_IMAP_USERNAME)",
    )
    src_auth_required = src_requires_imap and not bool(default_src_pass or default_src_client_id)
    src_auth = parser.add_mutually_exclusive_group(required=src_auth_required)
    src_auth.add_argument("--src-pass", default=default_src_pass, help="Source Password (or SRC_IMAP_PASSWORD)")
    src_auth.add_argument(
        "--src-oauth2-client-id",
        default=default_src_client_id,
        dest="src_client_id",
        help="Source OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        default=os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        dest="src_client_secret",
        help="Source OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )

    # Dest args
    default_dest_host = os.getenv("DEST_IMAP_HOST")
    default_dest_user = os.getenv("DEST_IMAP_USERNAME")
    default_dest_pass = os.getenv("DEST_IMAP_PASSWORD")
    default_dest_client_id = os.getenv("DEST_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--dest-host",
        default=default_dest_host,
        required=dest_requires_imap and not bool(default_dest_host),
        help="Destination IMAP Server (or DEST_IMAP_HOST)",
    )
    parser.add_argument(
        "--dest-user",
        default=default_dest_user,
        required=dest_requires_imap and not bool(default_dest_user),
        help="Destination Username (or DEST_IMAP_USERNAME)",
    )
    dest_auth_required = dest_requires_imap and not bool(default_dest_pass or default_dest_client_id)
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

    args = parser.parse_args()

    src_is_local = bool(args.src_path)
    dest_is_local = bool(args.dest_path)

    SRC_HOST = args.src_host
    SRC_USER = args.src_user
    DEST_HOST = args.dest_host
    DEST_USER = args.dest_user

    src_use_oauth2 = bool(args.src_client_id) and not src_is_local
    dest_use_oauth2 = bool(args.dest_client_id) and not dest_is_local

    # Acquire OAuth2 tokens if configured
    src_oauth2_token = None
    src_oauth2_provider = None
    if src_use_oauth2:
        src_oauth2_provider = imap_oauth2.detect_oauth2_provider(SRC_HOST)
        if not src_oauth2_provider:
            print(f"Error: Could not detect OAuth2 provider from host '{SRC_HOST}'.")
            sys.exit(1)
        print(f"Acquiring OAuth2 token for source ({src_oauth2_provider})...")
        src_oauth2_token = imap_oauth2.acquire_oauth2_token_for_provider(
            src_oauth2_provider, args.src_client_id, SRC_USER, args.src_client_secret
        )
        if not src_oauth2_token:
            print("Error: Failed to acquire OAuth2 token for source.")
            sys.exit(1)
        print("Source OAuth2 token acquired successfully.\n")

    dest_oauth2_token = None
    dest_oauth2_provider = None
    if dest_use_oauth2:
        dest_oauth2_provider = imap_oauth2.detect_oauth2_provider(DEST_HOST)
        if not dest_oauth2_provider:
            print(f"Error: Could not detect OAuth2 provider from host '{DEST_HOST}'.")
            sys.exit(1)
        print(f"Acquiring OAuth2 token for destination ({dest_oauth2_provider})...")
        dest_oauth2_token = imap_oauth2.acquire_oauth2_token_for_provider(
            dest_oauth2_provider, args.dest_client_id, DEST_USER, args.dest_client_secret
        )
        if not dest_oauth2_token:
            print("Error: Failed to acquire OAuth2 token for destination.")
            sys.exit(1)
        print("Destination OAuth2 token acquired successfully.\n")

    print("\n--- Configuration Summary ---")
    if src_is_local:
        print(f"Source (Local)  : {args.src_path}")
    else:
        print(f"Source Host     : {args.src_host}")
        print(f"Source User     : {args.src_user}")
        print(
            f"Source Auth     : {'OAuth2/' + src_oauth2_provider + ' (XOAUTH2)' if src_use_oauth2 else 'Basic (password)'}"
        )

    if dest_is_local:
        print(f"Destination (Local): {args.dest_path}")
    else:
        print(f"Destination Host: {args.dest_host}")
        print(f"Destination User: {args.dest_user}")
        print(
            f"Destination Auth: {'OAuth2/' + dest_oauth2_provider + ' (XOAUTH2)' if dest_use_oauth2 else 'Basic (password)'}"
        )
    print("-----------------------------\n")

    src = None
    dest = None

    try:
        if not src_is_local:
            # Connect to Source
            print("Connecting to Source...")
            src = imap_common.get_imap_connection(args.src_host, args.src_user, args.src_pass, src_oauth2_token)
            if not src:
                return

        if not dest_is_local:
            # Connect to Dest
            print("Connecting to Destination...")
            dest = imap_common.get_imap_connection(args.dest_host, args.dest_user, args.dest_pass, dest_oauth2_token)
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
