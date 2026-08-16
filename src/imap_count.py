"""IMAP Email Counting Script.

Counts emails per folder from either:
- An IMAP account, or
- A local backup folder created by ``imap_backup.py`` (counts ``.eml`` files).

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
    python3 imap_count.py

    # Count an IMAP account using OAuth2
    export IMAP_HOST="imap.gmail.com"
    export IMAP_USERNAME="user@gmail.com"
    export OAUTH2_CLIENT_ID="your-client-id"
    export OAUTH2_CLIENT_SECRET="your-client-secret"  # Required for Google
    python3 imap_count.py

    # Count a local backup
    python3 imap_count.py --path "./my_backup"

    # Or set a default local backup path via env var
    export BACKUP_LOCAL_PATH="./my_backup"
    python3 imap_count.py
"""

import imaplib
import sys
from typing import Optional

from auth import imap_oauth2
from cli.count import parse_arguments
from utils import imap_common
from utils.dotenv import load_dotenv


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
                    # Some servers return [None] for a successful search in an empty mailbox.
                    email_ids = data[0].split() if data and data[0] else []
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
    # Loading environment variables from .env file
    load_dotenv()

    args, local_mode = parse_arguments(argv)
    if local_mode:
        print("\n--- Configuration Summary ---")
        print(f"Local Path      : {args.path}")
        print("-----------------------------\n")
        count_local_emails(args.path)
        raise SystemExit(0)

    # Acquire OAuth2 token if configured
    oauth2_token = None
    oauth2_provider = None
    if args.client_id:
        oauth2_token, oauth2_provider = imap_oauth2.acquire_token(
            args.host,
            args.client_id,
            args.user,
            args.client_secret,
            account_type=args.account_type,
        )

    print("\n--- Configuration Summary ---")
    print(f"Host            : {args.host}")
    print(f"User            : {args.user}")
    print(f"Auth Method     : {imap_oauth2.auth_description(oauth2_provider)}")
    print("-----------------------------\n")

    count_emails(args.host, args.user, args.password, oauth2_token)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)
