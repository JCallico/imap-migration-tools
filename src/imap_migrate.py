"""
IMAP Email Migration Script

This script migrates emails from a source IMAP account to a destination IMAP account.
It iterates through all folders in the source account and copies emails to the destination.
It effectively handles folder creation and duplication checks (based on Message-ID).

Features:
- Progressive migration (folder by folder, email by email).
- Safe duplicate detection (skips widely identical messages).
- Optional deletion from source (set DELETE_FROM_SOURCE=true or use --src-delete).
- Optional deletion from destination (--dest-delete): removes emails not in source.
- Optional flag preservation (--preserve-flags): copies Seen, Answered, Flagged, Draft flags.
    - If a message already exists on the destination, missing flags can be synced onto it.
- Optional Gmail mode (--gmail-mode): migrates only "[Gmail]/All Mail" (no duplicates) and
    applies additional Gmail labels by copying the message into label folders.
    - In Gmail mode, label preservation is enabled automatically.
    - Note: --dest-delete is not supported in --gmail-mode.
- Cached Incremental Migration (--migrate-cache):
    - Uses a local JSON cache to track migrated Message-IDs.
    - Dramatically speeds up re-runs by skipping already processed emails without server checks.
    - Use --full-migrate to ignore cache skipping (force check) while still updating cache.

Configuration (Environment Variables):
  Source Account:
    SRC_IMAP_HOST       : Source IMAP Host (e.g., imap.gmail.com)
    SRC_IMAP_USERNAME   : Source Username/Email
    SRC_IMAP_PASSWORD   : Source Password (or App Password)

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

  Options:
    DELETE_FROM_SOURCE  : Set to "true" to delete emails from source after successful transfer.
                          Default is "false" (Copy only).
    DEST_DELETE         : Set to "true" to delete emails from destination not found in source.
                          Default is "false".
    PRESERVE_LABELS     : Set to "true" to preserve Gmail labels during migration. Default is "false".
    PRESERVE_FLAGS      : Set to "true" to preserve IMAP flags during migration. Default is "false".
    GMAIL_MODE          : Set to "true" for Gmail migration mode. Default is "false".
    MAX_WORKERS         : Number of concurrent threads (default: 10).
    BATCH_SIZE          : Number of emails to process in a batch per thread (default: 10).

Usage Example:
    # Basic migration (all folders)
    python3 imap_migrate.py \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Migrate only one folder (positional argument)
    python3 imap_migrate.py "INBOX" \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Preserve IMAP flags (read/starred/answered/draft). If the message already exists on the
    # destination, missing flags may be synced on it.
    python3 imap_migrate.py \
        --preserve-flags \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Sync mode: delete emails from dest that aren't in the source folder (non-Gmail-mode only)
    python3 imap_migrate.py --dest-delete \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Move instead of copy: delete from source after successful migration
    python3 imap_migrate.py \
        --src-delete \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"

    # Gmail mode (recommended for Gmail -> Gmail): migrates only "[Gmail]/All Mail" and
    # applies labels by copying messages into label folders.
    python3 imap_migrate.py \
        --gmail-mode \
        --src-host "imap.gmail.com" \
        --src-user "source@gmail.com" \
        --src-pass "SOURCE_APP_PASSWORD" \
        --dest-host "imap.gmail.com" \
        --dest-user "dest@gmail.com" \
        --dest-pass "DEST_APP_PASSWORD"

    # Cached Incremental Migration (Recommended for large accounts):
    # Uses a local cache to track progress and skip already migrated emails.
    python3 imap_migrate.py \
        --migrate-cache "./migration_cache" \
        --src-host "imap.example.com" \
        --src-user "source@example.com" \
        --src-pass "SOURCE_PASSWORD" \
        --dest-host "imap.example.com" \
        --dest-user "dest@example.com" \
        --dest-pass "DEST_PASSWORD"
"""

import os
import sys
from pathlib import Path

from auth import imap_oauth2
from cli.migrate import parse_arguments
from imap_services import AccountConfig, MigrationOptions, MigrationService, OAuth2Config
from imap_services._operations import migrate as _operation
from imap_services._operations.migrate import *  # noqa: F403
from imap_services.exceptions import ImapServiceError
from utils.dotenv import load_dotenv


def migrate_folder(*args, **kwargs):
    """Call the legacy helper while honoring mutable compatibility settings."""
    _operation.MAX_WORKERS = MAX_WORKERS  # noqa: F405
    _operation.BATCH_SIZE = BATCH_SIZE  # noqa: F405
    return _operation.migrate_folder(*args, **kwargs)


def main():
    """Parse CLI configuration and execute the reusable migration service."""
    dotenv_result = load_dotenv()
    args = parse_arguments(dotenv_keys=dotenv_result.dotenv_keys)

    def account(host, user, password, client_id, client_secret, account_type, label):
        oauth2 = None
        provider = None
        if client_id:
            token, provider = imap_oauth2.acquire_token(host, client_id, user, client_secret, label, account_type)
            oauth2 = OAuth2Config(client_id, client_secret, account_type, token, provider)
        return AccountConfig(host, user, password, oauth2), provider

    source, source_provider = account(
        args.src_host,
        args.src_user,
        args.src_pass,
        args.src_client_id,
        args.src_client_secret,
        args.src_account_type,
        "source",
    )
    destination, destination_provider = account(
        args.dest_host,
        args.dest_user,
        args.dest_pass,
        args.dest_client_id,
        args.dest_client_secret,
        args.dest_account_type,
        "destination",
    )
    target_folder = args.folder or os.getenv("MIGRATE_ONLY_FOLDER")
    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {args.src_host}")
    print(f"Source User     : {args.src_user}")
    print(f"Source Auth     : {imap_oauth2.auth_description(source_provider)}")
    print(f"Destination Host: {args.dest_host}")
    print(f"Destination User: {args.dest_user}")
    print(f"Destination Auth: {imap_oauth2.auth_description(destination_provider)}")
    print(f"Delete fm Source: {args.delete}")
    print(f"Dest Delete     : {args.dest_delete}")
    print(f"Preserve Flags  : {bool(args.preserve_flags) or bool(args.gmail_mode)}")
    print(f"Gmail Mode      : {bool(args.gmail_mode)}")
    if target_folder:
        print(f"Target Folder   : {target_folder}")
    print("-----------------------------\n")
    options = MigrationOptions(
        target_folder,
        args.workers,
        args.batch,
        args.delete,
        args.dest_delete,
        args.preserve_flags,
        args.preserve_labels,
        args.gmail_mode,
        Path(args.migrate_cache).expanduser() if args.migrate_cache else None,
        args.full_migrate,
        os.getenv("DEST_FOLDER_PREFIX"),
        os.getenv("DEST_FOLDER_SEP"),
    )
    try:
        return MigrationService(source, destination, options, lambda event: print(event.message)).run()
    except ImapServiceError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as exc:
        print(f"Fatal Error: {exc}")
        sys.exit(1)
