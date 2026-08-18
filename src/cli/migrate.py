"""Argument parsing for the direct IMAP migration command."""

import argparse
import os

from cli.common import resolve_and_validate_imap_account_arguments
from utils import imap_common


def parse_arguments(argv=None):
    """Parse migration command arguments using environment-backed defaults."""
    parser = argparse.ArgumentParser(description="Migrate emails between IMAP accounts.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")
    parser.add_argument("folder", nargs="?", help="Specific folder to migrate (e.g. '[Gmail]/Important')")

    default_src_host = os.getenv("SRC_IMAP_HOST")
    default_src_user = os.getenv("SRC_IMAP_USERNAME")
    default_src_pass = os.getenv("SRC_IMAP_PASSWORD")
    default_src_client_id = os.getenv("SRC_OAUTH2_CLIENT_ID")
    default_src_client_secret = os.getenv("SRC_OAUTH2_CLIENT_SECRET")
    default_src_account_type = os.getenv("SRC_ACCOUNT_TYPE", "auto")
    parser.add_argument(
        "--src-host",
        default=argparse.SUPPRESS,
        help="Source IMAP Host (or SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--src-user",
        default=argparse.SUPPRESS,
        help="Source Username (or SRC_IMAP_USERNAME)",
    )
    src_auth = parser.add_mutually_exclusive_group()
    src_auth.add_argument("--src-pass", default=argparse.SUPPRESS, help="Source Password (or SRC_IMAP_PASSWORD)")
    src_auth.add_argument(
        "--src-oauth2-client-id",
        default=argparse.SUPPRESS,
        dest="src_client_id",
        help="Source OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        default=argparse.SUPPRESS,
        dest="src_client_secret",
        help="Source OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--src-account-type",
        choices=("auto", "personal", "work"),
        default=argparse.SUPPRESS,
        help="Source OAuth provider account type (auto, personal, or work; or SRC_ACCOUNT_TYPE)",
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
        help="Destination IMAP Host (or DEST_IMAP_HOST)",
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
        "--src-delete",
        dest="delete",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("DELETE_FROM_SOURCE", "false").lower() == "true",
        help="Delete from source after migration (move semantics)",
    )
    parser.add_argument(
        "--dest-delete",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("DEST_DELETE", "false").lower() == "true",
        help="Delete emails from destination that don't exist in source (sync mode)",
    )
    parser.add_argument(
        "--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Number of concurrent threads"
    )
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Batch size per thread")
    parser.add_argument(
        "--preserve-labels",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("PRESERVE_LABELS", "false").lower() == "true",
        help="Preserve Gmail labels during migration",
    )
    parser.add_argument(
        "--preserve-flags",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("PRESERVE_FLAGS", "false").lower() == "true",
        help="Preserve IMAP flags during migration",
    )
    parser.add_argument(
        "--gmail-mode",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GMAIL_MODE", "false").lower() == "true",
        help="Gmail migration mode",
    )
    parser.add_argument(
        "--migrate-cache",
        help="Path to directory for migration progress cache (enables incremental migration)",
    )
    parser.add_argument(
        "--full-migrate",
        action="store_true",
        help="Force full migration (ignore cache for skipping), but still update cache if --migrate-cache provided",
    )
    args = parser.parse_args(argv)
    resolve_and_validate_imap_account_arguments(
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
    resolve_and_validate_imap_account_arguments(
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
