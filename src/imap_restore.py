"""
IMAP Email Restore Script

Restores emails from a local backup to an IMAP account.
Reads .eml files from a local directory and uploads them to the destination server.

Features:
- Folder Restoration: Recreates the folder structure from the backup.
- Gmail Labels Restoration: Uses labels_manifest.json to apply Gmail labels.
- Incremental Restore: Skips emails that already exist (based on Message-ID).
- Parallel Processing: Uses multithreading for fast uploads.
- Date Preservation: Restores emails with their original dates.

Configuration (Environment Variables):
    DEST_IMAP_HOST, DEST_IMAP_USERNAME: Destination credentials.
    DEST_IMAP_PASSWORD: Destination password (or App Password).

    OAuth2 (Optional - instead of password):
    DEST_OAUTH2_CLIENT_ID: OAuth2 Client ID
    DEST_OAUTH2_CLIENT_SECRET: OAuth2 Client Secret (required for Google)

  BACKUP_LOCAL_PATH: Source local directory containing the backup.
  MAX_WORKERS: Number of concurrent threads (default: 4).
  BATCH_SIZE: Number of emails to process per batch (default: 10).
  APPLY_LABELS: Set to "true" to apply Gmail labels from manifest. Default is "false".
  APPLY_FLAGS: Set to "true" to apply IMAP flags from manifest. Default is "false".
  GMAIL_MODE: Set to "true" for Gmail restore mode. Default is "false".
  DEST_DELETE: Set to "true" to delete emails from destination not found in local backup.
              Default is "false".

Usage:
    python3 imap_restore.py \
        --src-path "./my_backup" \
        --dest-host "imap.gmail.com" \
        --dest-user "you@gmail.com" \
        --dest-pass "your-app-password"

Gmail Labels Restoration:
    python3 imap_restore.py \
        --src-path "./gmail_backup" \
        --dest-host "imap.gmail.com" \
        --dest-user "you@gmail.com" \
        --dest-pass "your-app-password" \
        --apply-labels
  This uploads emails and applies labels from labels_manifest.json to recreate
  the original Gmail label structure.
"""

import os
import sys

from auth import imap_oauth2
from cli.restore import parse_arguments
from imap_services import AccountConfig, OAuth2Config, RestoreOptions, RestoreService
from imap_services._operations.restore import *  # noqa: F403
from imap_services.exceptions import ImapServiceError
from utils.dotenv import load_dotenv


def main():
    """Parse CLI configuration and execute the reusable restore service."""
    dotenv_result = load_dotenv()
    args = parse_arguments(dotenv_keys=dotenv_result.dotenv_keys)
    oauth2 = None
    provider = None
    if args.dest_client_id:
        token, provider = imap_oauth2.acquire_token(
            args.dest_host,
            args.dest_client_id,
            args.dest_user,
            args.dest_client_secret,
            "destination",
            args.dest_account_type,
        )
        oauth2 = OAuth2Config(args.dest_client_id, args.dest_client_secret, args.dest_account_type, token, provider)
    account = AccountConfig(args.dest_host, args.dest_user, args.dest_pass, oauth2)
    local_path = os.path.expanduser(args.src_path)
    print("\n--- Configuration Summary ---")
    print(f"Source Path     : {local_path}")
    print(f"Destination Host: {args.dest_host}")
    print(f"Destination User: {args.dest_user}")
    print(f"Destination Auth: {imap_oauth2.auth_description(provider)}")
    print(f"Workers         : {args.workers}")
    print("-----------------------------\n")
    options = RestoreOptions(
        args.folder,
        args.workers,
        args.batch,
        args.apply_labels,
        args.apply_flags,
        args.gmail_mode,
        args.dest_delete,
        args.full_restore,
    )
    try:
        return RestoreService(local_path, account, options, lambda event: print(event.message)).run()
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
        import traceback

        traceback.print_exc()
        sys.exit(1)
