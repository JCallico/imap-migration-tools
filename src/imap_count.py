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

    Source and destination targets:
    SRC_IMAP_* / SRC_OAUTH2_*   : Source account selected by --target source
    DEST_IMAP_* / DEST_OAUTH2_* : Destination account selected by --target destination

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

    # Or select the configured backup path
    export BACKUP_LOCAL_PATH="./my_backup"
    python3 imap_count.py --target local

    # Select an account when local/source/destination settings coexist
    python3 imap_count.py --target source
    python3 imap_count.py --target destination
"""

import sys
from typing import Optional

from auth import imap_oauth2
from cli.count import parse_arguments
from imap_services import AccountConfig, CountService, ImapTarget, LocalTarget, OAuth2Config
from imap_services._operations.count import count_emails, count_local_emails  # noqa: F401
from imap_services.exceptions import ImapServiceError
from utils.dotenv import load_dotenv


def _print_result(result, empty_message):
    if not result.folder_counts:
        print(empty_message)
        return
    print(f"{'Folder Name':<40} {'Count':>10}")
    print("-" * 52)
    for folder, count in result.folder_counts.items():
        print(f"{folder:<40} {count if count is not None else 'N/A':>10}")
    print("-" * 52)
    print(f"{'TOTAL':<40} {result.total:>10}")


def main(argv: Optional[list[str]] = None) -> None:
    """Parse CLI configuration and execute the reusable count service."""
    dotenv_result = load_dotenv()
    args, local_mode = parse_arguments(argv, dotenv_keys=dotenv_result.dotenv_keys)
    if local_mode:
        print("\n--- Configuration Summary ---")
        print(f"Local Path      : {args.path}")
        print("-----------------------------\n")
        events = []
        result = CountService(LocalTarget(args.path), events.append).run()
        print(events[0].message)
        _print_result(result, "No folders found.")
        raise SystemExit(0)

    oauth2 = None
    provider = None
    if args.client_id:
        token, provider = imap_oauth2.acquire_token(
            args.host, args.client_id, args.user, args.client_secret, account_type=args.account_type
        )
        oauth2 = OAuth2Config(args.client_id, args.client_secret, args.account_type, token, provider)
    account = AccountConfig(args.host, args.user, args.password, oauth2)
    print("\n--- Configuration Summary ---")
    print(f"Host            : {args.host}")
    print(f"User            : {args.user}")
    print(f"Auth Method     : {imap_oauth2.auth_description(provider)}")
    print("-----------------------------\n")
    events = []
    try:
        result = CountService(ImapTarget(account), events.append).run()
    except ImapServiceError as exc:
        print(f"An error occurred: {exc}")
        return
    for event in events:
        if event.phase in {"connect", "list"}:
            print(event.message)
    _print_result(result, "Failed to list mailboxes.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as exc:
        print(f"Fatal Error: {exc}")
        sys.exit(1)
