"""Argument parsing for the IMAP restore command."""

import argparse
import os

from cli.common import parse_account_arguments
from utils import imap_common


def parse_arguments(argv=None):
    """Parse restore command arguments using environment-backed defaults."""
    parser = argparse.ArgumentParser(description="Restore IMAP emails from local .eml files.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")

    env_path = os.getenv("BACKUP_LOCAL_PATH")
    parser.add_argument(
        "--src-path",
        default=env_path,
        required=not bool(env_path),
        help="Local source path containing backup (or BACKUP_LOCAL_PATH)",
    )

    default_dest_host = os.getenv("DEST_IMAP_HOST")
    default_dest_user = os.getenv("DEST_IMAP_USERNAME")
    default_dest_pass = os.getenv("DEST_IMAP_PASSWORD")
    default_dest_client_id = os.getenv("DEST_OAUTH2_CLIENT_ID")
    default_dest_client_secret = os.getenv("DEST_OAUTH2_CLIENT_SECRET")
    default_dest_account_type = os.getenv("DEST_ACCOUNT_TYPE", "auto")
    parser.add_argument(
        "--dest-host",
        default=argparse.SUPPRESS,
        help="Destination IMAP Server (or DEST_IMAP_HOST)",
    )
    parser.add_argument(
        "--dest-user",
        default=argparse.SUPPRESS,
        help="Destination Username (or DEST_IMAP_USERNAME)",
    )
    dest_auth = parser.add_mutually_exclusive_group()
    dest_auth.add_argument(
        "--dest-pass",
        default=argparse.SUPPRESS,
        help="Destination Password (or DEST_IMAP_PASSWORD)",
    )
    dest_auth.add_argument(
        "--dest-oauth2-client-id",
        default=argparse.SUPPRESS,
        dest="dest_client_id",
        help="Destination OAuth2 Client ID (or DEST_OAUTH2_CLIENT_ID)",
    )
    dest_auth.add_argument(
        "--dest-client-id",
        default=argparse.SUPPRESS,
        dest="dest_client_id",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dest-oauth2-client-secret",
        default=argparse.SUPPRESS,
        dest="dest_client_secret",
        help="Destination OAuth2 Client Secret (if required) (or DEST_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--dest-client-secret",
        default=argparse.SUPPRESS,
        dest="dest_client_secret",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dest-account-type",
        choices=("auto", "personal", "work"),
        default=argparse.SUPPRESS,
        help="Destination OAuth provider account type (auto, personal, or work; or DEST_ACCOUNT_TYPE)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("MAX_WORKERS", 4)),
        help="Thread count (default: 4)",
    )
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Emails per batch")
    parser.add_argument(
        "--apply-labels",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("APPLY_LABELS", "false").lower() == "true",
        help="Apply Gmail labels from labels_manifest.json",
    )
    parser.add_argument(
        "--apply-flags",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("APPLY_FLAGS", "false").lower() == "true",
        help="Apply IMAP flags (read/starred/answered/draft) from manifest",
    )
    parser.add_argument(
        "--gmail-mode",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GMAIL_MODE", "false").lower() == "true",
        help="Gmail restore mode: Upload to INBOX and apply labels + flags from manifest",
    )
    parser.add_argument(
        "--full-restore",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("FULL_RESTORE", "false").lower() == "true",
        help="Force full restore (legacy): process all emails and sync labels/flags for already-present messages.",
    )
    parser.add_argument(
        "--dest-delete",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("DEST_DELETE", "false").lower() == "true",
        help="Delete emails from destination that don't exist in local backup (sync mode)",
    )
    parser.add_argument("folder", nargs="?", help="Specific folder to restore")
    args = parser.parse_args(argv)
    parse_account_arguments(
        parser,
        args,
        host_dest="dest_host",
        user_dest="dest_user",
        password_dest="dest_pass",
        client_id_dest="dest_client_id",
        client_secret_dest="dest_client_secret",
        account_type_dest="dest_account_type",
        default_host=default_dest_host,
        default_user=default_dest_user,
        default_password=default_dest_pass,
        default_client_id=default_dest_client_id,
        default_client_secret=default_dest_client_secret,
        default_account_type=default_dest_account_type,
        host_option="--dest-host",
        user_option="--dest-user",
        password_option="--dest-pass",
        oauth_option="--dest-oauth2-client-id",
    )
    return args
