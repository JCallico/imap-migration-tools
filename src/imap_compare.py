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
from imap_services import AccountConfig, ComparisonService, ImapTarget, LocalTarget, OAuth2Config
from imap_services._operations.compare import get_email_count  # noqa: F401
from imap_services.exceptions import ImapServiceError
from utils.dotenv import load_dotenv


def _account(args, prefix, token, provider):
    client_id = getattr(args, f"{prefix}_client_id")
    oauth2 = (
        OAuth2Config(
            client_id,
            getattr(args, f"{prefix}_client_secret"),
            getattr(args, f"{prefix}_account_type"),
            token,
            provider,
        )
        if client_id
        else None
    )
    return AccountConfig(
        getattr(args, f"{prefix}_host"),
        getattr(args, f"{prefix}_user"),
        getattr(args, f"{prefix}_pass"),
        oauth2,
    )


def _oauth(args, prefix, label):
    client_id = getattr(args, f"{prefix}_client_id")
    if not client_id:
        return None, None
    return imap_oauth2.acquire_token(
        getattr(args, f"{prefix}_host"),
        client_id,
        getattr(args, f"{prefix}_user"),
        getattr(args, f"{prefix}_client_secret"),
        label,
        getattr(args, f"{prefix}_account_type"),
    )


def main():
    """Parse CLI configuration and execute the comparison service."""
    dotenv_result = load_dotenv()
    args, src_local, dest_local = parse_arguments(dotenv_keys=dotenv_result.dotenv_keys)
    src_token, src_provider = (None, None) if src_local else _oauth(args, "src", "source")
    dest_token, dest_provider = (None, None) if dest_local else _oauth(args, "dest", "destination")
    source = LocalTarget(args.src_path) if src_local else ImapTarget(_account(args, "src", src_token, src_provider))
    destination = (
        LocalTarget(args.dest_path) if dest_local else ImapTarget(_account(args, "dest", dest_token, dest_provider))
    )

    print("\n--- Configuration Summary ---")
    print(f"Source (Local)  : {args.src_path}" if src_local else f"Source Host     : {args.src_host}")
    if not src_local:
        print(f"Source User     : {args.src_user}")
        print(f"Source Auth     : {imap_oauth2.auth_description(src_provider)}")
    print(f"Destination (Local): {args.dest_path}" if dest_local else f"Destination Host: {args.dest_host}")
    if not dest_local:
        print(f"Destination User: {args.dest_user}")
        print(f"Destination Auth: {imap_oauth2.auth_description(dest_provider)}")
    print("-----------------------------\n")

    events = []
    try:
        result = ComparisonService(
            source,
            destination,
            events.append,
            destination_folder_prefix=os.getenv("DEST_FOLDER_PREFIX"),
            destination_folder_separator=os.getenv("DEST_FOLDER_SEP"),
        ).run()
    except ImapServiceError as exc:
        if "list source folders" in str(exc):
            print("Failed to list source folders.")
        return
    for event in events:
        if event.phase in {"connect", "list"}:
            print(event.message)
    header = f"{'Folder Name':<40} | {'Source':>10} | {'Dest':>10} | {'Diff':>10}"
    print("-" * len(header))
    print(header)
    print("-" * len(header))
    for row in result.rows:
        source_count = str(row.source) if row.source is not None else "Err"
        destination_count = str(row.destination) if row.destination is not None else "N/A"
        difference = str(row.difference) if row.difference is not None else ""
        print(f"{row.folder:<40} | {source_count:>10} | {destination_count:>10} | {difference:>10}")
    print("-" * len(header))
    print(
        f"{'TOTAL':<40} | {result.source_total:>10} | {result.destination_total:>10} | "
        f"{result.source_total - result.destination_total:>10}"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as exc:
        print(f"Fatal Error: {exc}")
        sys.exit(1)
