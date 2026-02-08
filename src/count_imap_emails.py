"""IMAP Email Counting Script.

Counts emails per folder from either:
- An IMAP account, or
- A local backup folder created by ``backup_imap_emails.py`` (counts ``.eml`` files).

Configuration (Environment Variables):
    IMAP_HOST        : IMAP Host (e.g., imap.gmail.com)
    IMAP_USERNAME    : Username/Email
    IMAP_PASSWORD    : Password (or App Password)

    OAuth2 (Optional - instead of password):
    OAUTH2_CLIENT_ID        : OAuth2 Client ID
    OAUTH2_CLIENT_SECRET    : OAuth2 Client Secret (required for Google)
    SRC_OAUTH2_CLIENT_ID    : Alternate OAuth2 client ID env var
    SRC_OAUTH2_CLIENT_SECRET: Alternate OAuth2 client secret env var

Local backup counting:
    BACKUP_LOCAL_PATH : Local backup root (preferred)
    SRC_LOCAL_PATH    : Alternate local backup root

Examples:
    # Count an IMAP account
    export IMAP_HOST="imap.gmail.com"
    export IMAP_USERNAME="user@gmail.com"
    export IMAP_PASSWORD="secretpassword"
    python3 count_imap_emails.py

    # Count an IMAP account using OAuth2
    export IMAP_HOST="imap.gmail.com"
    export IMAP_USERNAME="user@gmail.com"
    export OAUTH2_CLIENT_ID="your-client-id"
    export OAUTH2_CLIENT_SECRET="your-client-secret"  # Required for Google
    python3 count_imap_emails.py

    # Count a local backup
    python3 count_imap_emails.py --path "./my_backup"

    # Or set a default local backup path via env var
    export BACKUP_LOCAL_PATH="./my_backup"
    python3 count_imap_emails.py
"""

import argparse
import imaplib
import os
import sys
from typing import Optional

import imap_common
import imap_oauth2


def count_emails(imap_server, username, password=None, oauth2_token=None):
    try:
        # Connect to the IMAP server (using SSL)
        print(f"Connecting to {imap_server}...")
        mail = imap_common.get_imap_connection(imap_server, username, password, oauth2_token)
        if not mail:
            return

        # List all mailboxes
        print("Listing mailboxes...")
        folders = imap_common.list_selectable_folders(mail)

        if not folders:
            print("Failed to list mailboxes.")
            return

        total_all_folders = 0
        print(f"{'Folder Name':<40} {'Count':>10}")
        print("-" * 52)

        for folder_name in folders:
            display_name = folder_name

            try:
                # Select the mailbox (read-only is sufficient for counting)
                # folder_name extracted from list usually handles quotes correctly for select
                rv, _ = mail.select(f'"{folder_name}"', readonly=True)
                if rv != "OK":
                    print(f"{display_name:<40} {'Skipped':>10}")
                    continue

                # Search for all emails
                status, data = mail.search(None, "ALL")

                if status == "OK":
                    # data[0] is space separated IDs
                    email_ids = data[0].split()
                    count = len(email_ids)
                    print(f"{display_name:<40} {count:>10}")
                    total_all_folders += count
                else:
                    print(f"{display_name:<40} {'Error':>10}")

            except imaplib.IMAP4.error:
                print(f"{display_name:<40} {'Error':>10}")

        print("-" * 52)
        print(f"{'TOTAL':<40} {total_all_folders:>10}")

        # Logout
        mail.logout()

    except imaplib.IMAP4.error as e:
        print(f"IMAP Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def count_local_emails(local_path: str) -> None:
    print(f"Scanning local backup: {local_path}")

    folders = imap_common.list_local_folders(local_path)
    if not folders:
        print("No folders found.")
        return

    total_all_folders = 0
    print(f"{'Folder Name':<40} {'Count':>10}")
    print("-" * 52)

    for folder_name in folders:
        count = imap_common.get_local_email_count(local_path, folder_name)
        if count is None:
            print(f"{folder_name:<40} {'N/A':>10}")
            continue

        print(f"{folder_name:<40} {count:>10}")
        total_all_folders += count

    print("-" * 52)
    print(f"{'TOTAL':<40} {total_all_folders:>10}")


def main(argv: Optional[list[str]] = None) -> None:
    # Phase 1: determine whether we're in local mode (--path)
    default_path = os.getenv("BACKUP_LOCAL_PATH") or os.getenv("SRC_LOCAL_PATH")
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--path", default=default_path)
    pre_args, _ = pre_parser.parse_known_args(argv)
    require_imap = not bool(pre_args.path)

    # Phase 2: full parser with conditional requirements
    parser = argparse.ArgumentParser(description="Count emails in IMAP account.")

    parser.add_argument(
        "--path",
        default=default_path,
        help="Local backup root to count (counts .eml files per folder). If set, IMAP args are ignored.",
    )

    # Try to unify var names for defaults. Priority: IMAP_* > SRC_IMAP_* > None
    default_host = os.getenv("IMAP_HOST") or os.getenv("SRC_IMAP_HOST")
    default_user = os.getenv("IMAP_USERNAME") or os.getenv("SRC_IMAP_USERNAME")
    default_pass = os.getenv("IMAP_PASSWORD") or os.getenv("SRC_IMAP_PASSWORD")
    default_client_id = os.getenv("OAUTH2_CLIENT_ID") or os.getenv("SRC_OAUTH2_CLIENT_ID")

    parser.add_argument(
        "--host",
        default=default_host,
        required=require_imap and not bool(default_host),
        help="IMAP Server (or IMAP_HOST / SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--user",
        default=default_user,
        required=require_imap and not bool(default_user),
        help="Username (or IMAP_USERNAME / SRC_IMAP_USERNAME)",
    )

    auth_required = require_imap and not bool(default_pass or default_client_id)
    auth_group = parser.add_mutually_exclusive_group(required=auth_required)
    auth_group.add_argument(
        "--pass", dest="password", default=default_pass, help="Password (or IMAP_PASSWORD / SRC_IMAP_PASSWORD)"
    )
    auth_group.add_argument(
        "--oauth2-client-id",
        default=default_client_id,
        dest="client_id",
        help="OAuth2 Client ID (or OAUTH2_CLIENT_ID / SRC_OAUTH2_CLIENT_ID)",
    )
    auth_group.add_argument(
        "--client-id",
        default=default_client_id,
        dest="client_id",
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--oauth2-client-secret",
        default=os.getenv("OAUTH2_CLIENT_SECRET") or os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        dest="client_secret",
        help="OAuth2 Client Secret (if required) (or OAUTH2_CLIENT_SECRET / SRC_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--client-secret",
        default=os.getenv("OAUTH2_CLIENT_SECRET") or os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        dest="client_secret",
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args(argv)

    if args.path:
        if not os.path.isdir(args.path):
            print(f"Error: Local path does not exist or is not a directory: {args.path}")
            sys.exit(1)

        print("\n--- Configuration Summary ---")
        print(f"Local Path      : {args.path}")
        print("-----------------------------\n")
        count_local_emails(args.path)
        raise SystemExit(0)

    IMAP_SERVER = args.host
    USERNAME = args.user
    PASSWORD = args.password

    # Acquire OAuth2 token if configured
    oauth2_token = None
    oauth2_provider = None
    if args.client_id:
        oauth2_token, oauth2_provider = imap_oauth2.acquire_token(
            IMAP_SERVER, args.client_id, USERNAME, args.client_secret
        )

    print("\n--- Configuration Summary ---")
    print(f"Host            : {IMAP_SERVER}")
    print(f"User            : {USERNAME}")
    print(f"Auth Method     : {imap_oauth2.auth_description(oauth2_provider)}")
    print("-----------------------------\n")

    count_emails(IMAP_SERVER, USERNAME, PASSWORD, oauth2_token)


if __name__ == "__main__":
    main()
