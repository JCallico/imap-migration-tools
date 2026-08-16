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
  python3 imap_compare.py

Examples:
        # IMAP -> IMAP
        python3 imap_compare.py \
            --src-host "imap.source.com" \
            --src-user "source@example.com" \
            --src-pass "source-app-password" \
            --dest-host "imap.dest.com" \
            --dest-user "dest@example.com" \
            --dest-pass "dest-app-password"

        # Local -> IMAP
        python3 imap_compare.py \
            --src-path "./my_backup" \
            --dest-host "imap.dest.com" \
            --dest-user "dest@example.com" \
            --dest-pass "dest-app-password"

        # IMAP -> Local
        python3 imap_compare.py \
            --src-host "imap.source.com" \
            --src-user "source@example.com" \
            --src-pass "source-app-password" \
            --dest-path "./my_backup"
"""

import os
import sys

from auth import imap_oauth2
from cli.compare import parse_arguments
from utils import imap_common
from utils.dotenv import load_dotenv


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
    # Loading environment variables from .env file
    load_dotenv()

    args, src_is_local, dest_is_local = parse_arguments()

    SRC_HOST = args.src_host
    SRC_USER = args.src_user
    DEST_HOST = args.dest_host
    DEST_USER = args.dest_user

    # Acquire OAuth2 tokens if configured
    src_oauth2_token = None
    src_oauth2_provider = None
    if not src_is_local and args.src_client_id:
        src_oauth2_token, src_oauth2_provider = imap_oauth2.acquire_token(
            SRC_HOST,
            args.src_client_id,
            SRC_USER,
            args.src_client_secret,
            "source",
            args.src_account_type,
        )

    dest_oauth2_token = None
    dest_oauth2_provider = None
    if not dest_is_local and args.dest_client_id:
        dest_oauth2_token, dest_oauth2_provider = imap_oauth2.acquire_token(
            DEST_HOST,
            args.dest_client_id,
            DEST_USER,
            args.dest_client_secret,
            "destination",
            args.dest_account_type,
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
            detected_prefix, detected_sep = imap_common.detect_dest_namespace(dest)
            dest_prefix = os.getenv("DEST_FOLDER_PREFIX")
            dest_sep = os.getenv("DEST_FOLDER_SEP")
            dest.configure_folder_mapping(
                dest_prefix or detected_prefix,
                dest_sep or detected_sep,
            )

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
