"""Argument parsing for the IMAP backup command."""

import argparse
import os

from cli.common import parse_account_arguments
from utils import imap_common


def parse_arguments(argv=None):
    """Parse backup command arguments using environment-backed defaults."""
    parser = argparse.ArgumentParser(description="Backup IMAP emails to local .eml files.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")

    default_src_host = os.getenv("SRC_IMAP_HOST")
    default_src_user = os.getenv("SRC_IMAP_USERNAME")
    default_src_pass = os.getenv("SRC_IMAP_PASSWORD")
    default_src_client_id = os.getenv("SRC_OAUTH2_CLIENT_ID")
    default_src_client_secret = os.getenv("SRC_OAUTH2_CLIENT_SECRET")
    default_src_account_type = os.getenv("SRC_ACCOUNT_TYPE", "auto")
    parser.add_argument(
        "--src-host",
        default=argparse.SUPPRESS,
        help="Source IMAP Server (or SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--src-user",
        default=argparse.SUPPRESS,
        help="Source Username (or SRC_IMAP_USERNAME)",
    )
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--src-pass", default=argparse.SUPPRESS, help="Source Password (or SRC_IMAP_PASSWORD)")
    auth_group.add_argument(
        "--src-oauth2-client-id",
        default=argparse.SUPPRESS,
        dest="src_client_id",
        help="OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        default=argparse.SUPPRESS,
        dest="src_client_secret",
        help="OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--src-account-type",
        choices=("auto", "personal", "work"),
        default=argparse.SUPPRESS,
        help="Source OAuth provider account type (auto, personal, or work; or SRC_ACCOUNT_TYPE)",
    )

    env_path = os.getenv("BACKUP_LOCAL_PATH")
    parser.add_argument(
        "--dest-path",
        default=env_path,
        required=not bool(env_path),
        help="Local destination path (or BACKUP_LOCAL_PATH)",
    )
    parser.add_argument("--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Thread count")
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Emails per batch")
    parser.add_argument(
        "--preserve-labels",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("PRESERVE_LABELS", "false").lower() == "true",
        help="Gmail only: Create a labels_manifest.json mapping Message-IDs to labels for restoration",
    )
    parser.add_argument(
        "--preserve-flags",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("PRESERVE_FLAGS", "false").lower() == "true",
        help="Preserve IMAP flags (read/unread, starred, answered, draft) in manifest for restoration",
    )
    parser.add_argument(
        "--manifest-only",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("MANIFEST_ONLY", "false").lower() == "true",
        help="Gmail only: Build the labels manifest and exit without downloading emails",
    )
    parser.add_argument(
        "--gmail-mode",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GMAIL_MODE", "false").lower() == "true",
        help="Gmail backup mode: Build labels manifest and backup [Gmail]/All Mail only (recommended)",
    )
    parser.add_argument(
        "--dest-delete",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("DEST_DELETE", "false").lower() == "true",
        help="Delete local .eml files that no longer exist on the IMAP server (sync mode)",
    )
    parser.add_argument("folder", nargs="?", help="Specific folder to backup")
    args = parser.parse_args(argv)
    parse_account_arguments(
        parser,
        args,
        host_dest="src_host",
        user_dest="src_user",
        password_dest="src_pass",
        client_id_dest="src_client_id",
        client_secret_dest="src_client_secret",
        account_type_dest="src_account_type",
        default_host=default_src_host,
        default_user=default_src_user,
        default_password=default_src_pass,
        default_client_id=default_src_client_id,
        default_client_secret=default_src_client_secret,
        default_account_type=default_src_account_type,
        host_option="--src-host",
        user_option="--src-user",
        password_option="--src-pass",
        oauth_option="--src-oauth2-client-id",
    )
    return args
