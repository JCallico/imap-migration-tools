"""Argument parsing for the direct IMAP migration command."""

import argparse
import os

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
    parser.add_argument(
        "--src-host",
        default=default_src_host,
        required=not bool(default_src_host),
        help="Source IMAP Host (or SRC_IMAP_HOST)",
    )
    parser.add_argument(
        "--src-user",
        default=default_src_user,
        required=not bool(default_src_user),
        help="Source Username (or SRC_IMAP_USERNAME)",
    )
    src_auth = parser.add_mutually_exclusive_group(required=not bool(default_src_pass or default_src_client_id))
    src_auth.add_argument("--src-pass", default=default_src_pass, help="Source Password (or SRC_IMAP_PASSWORD)")
    src_auth.add_argument(
        "--src-oauth2-client-id",
        default=default_src_client_id,
        dest="src_client_id",
        help="Source OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        default=os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        dest="src_client_secret",
        help="Source OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--src-account-type",
        choices=("auto", "personal", "work"),
        default=os.getenv("SRC_ACCOUNT_TYPE", "auto"),
        help="Source OAuth provider account type (auto, personal, or work; or SRC_ACCOUNT_TYPE)",
    )

    default_dest_host = os.getenv("DEST_IMAP_HOST")
    default_dest_user = os.getenv("DEST_IMAP_USERNAME")
    default_dest_pass = os.getenv("DEST_IMAP_PASSWORD")
    default_dest_client_id = os.getenv("DEST_OAUTH2_CLIENT_ID")
    parser.add_argument(
        "--dest-host",
        default=default_dest_host,
        required=not bool(default_dest_host),
        help="Destination IMAP Host (or DEST_IMAP_HOST)",
    )
    parser.add_argument(
        "--dest-user",
        default=default_dest_user,
        required=not bool(default_dest_user),
        help="Destination Username (or DEST_IMAP_USERNAME)",
    )
    dest_auth = parser.add_mutually_exclusive_group(required=not bool(default_dest_pass or default_dest_client_id))
    dest_auth.add_argument(
        "--dest-pass",
        default=default_dest_pass,
        help="Destination Password (or DEST_IMAP_PASSWORD)",
    )
    dest_auth.add_argument(
        "--dest-oauth2-client-id",
        default=default_dest_client_id,
        dest="dest_client_id",
        help="Destination OAuth2 Client ID (or DEST_OAUTH2_CLIENT_ID)",
    )
    dest_auth.add_argument(
        "--dest-client-id",
        default=default_dest_client_id,
        dest="dest_client_id",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dest-oauth2-client-secret",
        default=os.getenv("DEST_OAUTH2_CLIENT_SECRET"),
        dest="dest_client_secret",
        help="Destination OAuth2 Client Secret (if required) (or DEST_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--dest-client-secret",
        default=os.getenv("DEST_OAUTH2_CLIENT_SECRET"),
        dest="dest_client_secret",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dest-account-type",
        choices=("auto", "personal", "work"),
        default=os.getenv("DEST_ACCOUNT_TYPE", "auto"),
        help="Destination OAuth provider account type (auto, personal, or work; or DEST_ACCOUNT_TYPE)",
    )
    parser.add_argument(
        "--src-delete",
        dest="delete",
        action="store_true",
        default=os.getenv("DELETE_FROM_SOURCE", "false").lower() == "true",
        help="Delete from source after migration (move semantics)",
    )
    parser.add_argument(
        "--dest-delete",
        action="store_true",
        default=os.getenv("DEST_DELETE", "false").lower() == "true",
        help="Delete emails from destination that don't exist in source (sync mode)",
    )
    parser.add_argument(
        "--workers", type=int, default=int(os.getenv("MAX_WORKERS", 10)), help="Number of concurrent threads"
    )
    parser.add_argument("--batch", type=int, default=int(os.getenv("BATCH_SIZE", 10)), help="Batch size per thread")
    parser.add_argument(
        "--preserve-labels",
        action="store_true",
        default=os.getenv("PRESERVE_LABELS", "false").lower() == "true",
        help="Preserve Gmail labels during migration",
    )
    parser.add_argument(
        "--preserve-flags",
        action="store_true",
        default=os.getenv("PRESERVE_FLAGS", "false").lower() == "true",
        help="Preserve IMAP flags during migration",
    )
    parser.add_argument(
        "--gmail-mode",
        action="store_true",
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
    return parser.parse_args(argv)
