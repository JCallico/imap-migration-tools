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
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")
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

    # Acquire OAuth2 tokens if configured
    src_oauth2_token = None
    src_oauth2_provider = None
    if not src_is_local and args.src_client_id:
        src_oauth2_token, src_oauth2_provider = imap_oauth2.acquire_token(
            SRC_HOST, args.src_client_id, SRC_USER, args.src_client_secret, "source"
        )

    dest_oauth2_token = None
    dest_oauth2_provider = None
    if not dest_is_local and args.dest_client_id:
        dest_oauth2_token, dest_oauth2_provider = imap_oauth2.acquire_token(
            DEST_HOST, args.dest_client_id, DEST_USER, args.dest_client_secret, "destination"
        )

    print("\n--- Configuration Summary ---")
    if src_is_local:
        print(f"Source (Local)  : {args.src_path}")
    else:
        print(f"Source Host     : {args.src_host}")
        print(f"Source User     : {args.src_user}")
        print(f"Source Auth     : {imap_oauth2.auth_description(src_oauth2_provider)}")

    if dest_is_local:
        print(f"Destination (Local): {args.dest_path}")
    else:
        print(f"Destination Host: {args.dest_host}")
        print(f"Destination User: {args.dest_user}")
        print(f"Destination Auth: {imap_oauth2.auth_description(dest_oauth2_provider)}")
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
            folders = imap_common.list_local_folders(args.src_path)
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
                src_count = imap_common.get_local_email_count(args.src_path, folder_name)
            else:
                src_count = get_email_count(src, folder_name)

            if dest_is_local:
                dest_count = imap_common.get_local_email_count(args.dest_path, folder_name)
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

    except KeyboardInterrupt:
        # Re-raise to be handled by the outer block, but ensure finally runs
        raise

    finally:
        # Check source connection state and logout if possible
        if src:
            try:
                src.logout()
            except BaseException:
                pass

        # Check dest connection state and logout if possible
        if dest:
            try:
                dest.logout()
            except BaseException:
                pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)
