"""
IMAP Email Backup Script

Backs up emails from an IMAP account to a local directory.
Stores each email as a separate .eml file (RFC 5322 format) which is compatible with
most email clients (Thunderbird, Apple Mail, Outlook, etc.).

Features:
- Incremental Backup: Skips messages that have already been downloaded (checks existing UIDs locally).
- Filename Sanitization: Saves files as "{UID}_{Subject}.eml" with unsafe characters removed.
- Folder Replication: Recreates the IMAP folder structure locally.
- Parallel Processing: Uses multithreading for fast downloads.
- Gmail Labels Preservation: Creates a manifest mapping Message-IDs to Gmail labels for restoration.

Configuration (Environment Variables):
    SRC_IMAP_HOST, SRC_IMAP_USERNAME: Source credentials.
    SRC_IMAP_PASSWORD: Source password (or App Password).

    OAuth2 (Optional - instead of password):
    SRC_OAUTH2_CLIENT_ID: OAuth2 Client ID
    SRC_OAUTH2_CLIENT_SECRET: OAuth2 Client Secret (required for Google)

  BACKUP_LOCAL_PATH: Destination local directory.
  MAX_WORKERS: Number of concurrent threads (default: 10).
  BATCH_SIZE: Number of emails to process per batch (default: 10).
  PRESERVE_LABELS: Set to "true" to create labels_manifest.json (Gmail). Default is "false".
  PRESERVE_FLAGS: Set to "true" to preserve IMAP flags in manifest. Default is "false".
  MANIFEST_ONLY: Set to "true" to only build manifest without downloading. Default is "false".
  GMAIL_MODE: Set to "true" for Gmail backup mode. Default is "false".
  DEST_DELETE: Set to "true" to delete local files not found on server (sync mode).
              Default is "false".

Usage:
    python3 imap_backup.py \
        --src-host "imap.example.com" \
        --src-user "you@example.com" \
        --src-pass "your-app-password" \
        --dest-path "./my_backup"

Gmail Labels:
    python3 imap_backup.py \
        --src-host "imap.gmail.com" \
        --src-user "you@gmail.com" \
        --src-pass "your-app-password" \
        --dest-path "./my_backup" \
        --preserve-labels \
        "[Gmail]/All Mail"
  This backs up all emails from [Gmail]/All Mail and creates a labels_manifest.json
  file that maps each email's Message-ID to its Gmail labels for later restoration.
"""

import os
import sys

from auth import imap_oauth2
from cli.backup import parse_arguments
from imap_services import AccountConfig, BackupOptions, BackupService, OAuth2Config
from imap_services._operations.backup import *  # noqa: F403
from imap_services.exceptions import ImapServiceError
from utils.dotenv import load_dotenv


def main():
    """Parse CLI configuration and execute the reusable backup service."""
    dotenv_result = load_dotenv()
    args = parse_arguments(dotenv_keys=dotenv_result.dotenv_keys)
    oauth2 = None
    provider = None
    if args.src_client_id:
        token, provider = imap_oauth2.acquire_token(
            args.src_host,
            args.src_client_id,
            args.src_user,
            args.src_client_secret,
            account_type=args.src_account_type,
        )
        oauth2 = OAuth2Config(args.src_client_id, args.src_client_secret, args.src_account_type, token, provider)
    account = AccountConfig(args.src_host, args.src_user, args.src_pass, oauth2)
    local_path = os.path.expanduser(args.dest_path)
    print("\n--- Configuration Summary ---")
    print(f"Source Host     : {args.src_host}")
    print(f"Source User     : {args.src_user}")
    print(f"Auth Method     : {imap_oauth2.auth_description(provider)}")
    print(f"Destination Path: {local_path}")
    print("-----------------------------\n")
    options = BackupOptions(
        args.folder,
        args.workers,
        args.batch,
        args.preserve_labels,
        args.preserve_flags,
        args.manifest_only,
        args.gmail_mode,
        args.dest_delete,
    )
    try:
        result = BackupService(account, local_path, options, lambda event: print(event.message)).run()
    except ImapServiceError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc
    if args.manifest_only:
        print("\nManifest-only mode complete.")
        raise SystemExit(0)
    return result


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as exc:
        print(f"Fatal Error: {exc}")
        sys.exit(1)
