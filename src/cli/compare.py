"""Argument parsing for the folder comparison command."""

import argparse
import os

from cli.common import resolve_and_validate_imap_account_arguments
from utils import imap_common


def parse_arguments(argv=None):
    """Parse configuration and return resolved arguments with per-side local-mode flags."""
    default_src_path = os.getenv("SRC_LOCAL_PATH")
    default_dest_path = os.getenv("DEST_LOCAL_PATH")
    default_src_host = os.getenv("SRC_IMAP_HOST")
    default_src_user = os.getenv("SRC_IMAP_USERNAME")
    default_src_pass = os.getenv("SRC_IMAP_PASSWORD")
    default_src_client_id = os.getenv("SRC_OAUTH2_CLIENT_ID")
    default_src_client_secret = os.getenv("SRC_OAUTH2_CLIENT_SECRET")
    default_src_account_type = os.getenv("SRC_ACCOUNT_TYPE", "auto")
    default_dest_host = os.getenv("DEST_IMAP_HOST")
    default_dest_user = os.getenv("DEST_IMAP_USERNAME")
    default_dest_pass = os.getenv("DEST_IMAP_PASSWORD")
    default_dest_client_id = os.getenv("DEST_OAUTH2_CLIENT_ID")
    default_dest_client_secret = os.getenv("DEST_OAUTH2_CLIENT_SECRET")
    default_dest_account_type = os.getenv("DEST_ACCOUNT_TYPE", "auto")

    parser = argparse.ArgumentParser(
        description="Compare email counts between two IMAP accounts.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")
    parser.add_argument(
        "--src-path",
        help="Source local folder (backup root); cannot be combined with source IMAP arguments.",
    )
    parser.add_argument(
        "--dest-path",
        help="Destination local folder (backup root); cannot be combined with destination IMAP arguments.",
    )
    parser.add_argument("--src-host", help="Source IMAP Server (or SRC_IMAP_HOST)")
    parser.add_argument("--src-user", help="Source Username (or SRC_IMAP_USERNAME)")
    src_auth = parser.add_mutually_exclusive_group()
    src_auth.add_argument("--src-pass", help="Source Password (or SRC_IMAP_PASSWORD)")
    src_auth.add_argument(
        "--src-oauth2-client-id",
        dest="src_client_id",
        help="Source OAuth2 Client ID (or SRC_OAUTH2_CLIENT_ID)",
    )
    parser.add_argument(
        "--src-oauth2-client-secret",
        dest="src_client_secret",
        help="Source OAuth2 Client Secret (if required) (or SRC_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--src-account-type",
        choices=("auto", "personal", "work"),
        help="Source OAuth provider account type (auto, personal, or work; or SRC_ACCOUNT_TYPE)",
    )
    parser.add_argument("--dest-host", help="Destination IMAP Server (or DEST_IMAP_HOST)")
    parser.add_argument("--dest-user", help="Destination Username (or DEST_IMAP_USERNAME)")
    dest_auth = parser.add_mutually_exclusive_group()
    dest_auth.add_argument("--dest-pass", help="Destination Password (or DEST_IMAP_PASSWORD)")
    dest_auth.add_argument(
        "--dest-oauth2-client-id",
        dest="dest_client_id",
        help="Destination OAuth2 Client ID (or DEST_OAUTH2_CLIENT_ID)",
    )
    dest_auth.add_argument("--dest-client-id", dest="dest_client_id", help=argparse.SUPPRESS)
    parser.add_argument(
        "--dest-oauth2-client-secret",
        dest="dest_client_secret",
        help="Destination OAuth2 Client Secret (if required) (or DEST_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument("--dest-client-secret", dest="dest_client_secret", help=argparse.SUPPRESS)
    parser.add_argument(
        "--dest-account-type",
        choices=("auto", "personal", "work"),
        help="Destination OAuth provider account type (auto, personal, or work; or DEST_ACCOUNT_TYPE)",
    )

    args = parser.parse_args(argv)
    explicit_src_path = hasattr(args, "src_path")
    explicit_dest_path = hasattr(args, "dest_path")
    explicit_src_imap = any(
        hasattr(args, name)
        for name in ("src_host", "src_user", "src_pass", "src_client_id", "src_client_secret", "src_account_type")
    )
    explicit_dest_imap = any(
        hasattr(args, name)
        for name in (
            "dest_host",
            "dest_user",
            "dest_pass",
            "dest_client_id",
            "dest_client_secret",
            "dest_account_type",
        )
    )
    if explicit_src_path and explicit_src_imap:
        parser.error("--src-path cannot be combined with explicit source IMAP connection arguments")
    if explicit_dest_path and explicit_dest_imap:
        parser.error("--dest-path cannot be combined with explicit destination IMAP connection arguments")

    src_is_local = explicit_src_path or (not explicit_src_imap and bool(default_src_path))
    dest_is_local = explicit_dest_path or (not explicit_dest_imap and bool(default_dest_path))
    args.src_path = getattr(args, "src_path", default_src_path if src_is_local else None)
    args.dest_path = getattr(args, "dest_path", default_dest_path if dest_is_local else None)
    if src_is_local and not args.src_path:
        parser.error("--src-path must specify a non-empty local backup root")
    if dest_is_local and not args.dest_path:
        parser.error("--dest-path must specify a non-empty local backup root")
    if not src_is_local:
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
    else:
        args.src_host = default_src_host
        args.src_user = default_src_user
        args.src_client_secret = default_src_client_secret
        args.src_account_type = default_src_account_type
    if not dest_is_local:
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
    else:
        args.dest_host = default_dest_host
        args.dest_user = default_dest_user
        args.dest_client_secret = default_dest_client_secret
        args.dest_account_type = default_dest_account_type

    return args, src_is_local, dest_is_local
