"""Argument parsing for the folder comparison command."""

import argparse
import os

from cli.common import parse_account_arguments, read_account_defaults
from utils import imap_common


def parse_arguments(argv=None, *, dotenv_keys=frozenset()):
    """Parse configuration and return resolved arguments with per-side local-mode flags."""
    default_src_path = os.getenv("SRC_LOCAL_PATH")
    default_dest_path = os.getenv("DEST_LOCAL_PATH")
    source_defaults = read_account_defaults("SRC")
    destination_defaults = read_account_defaults("DEST")

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
        parse_account_arguments(
            parser,
            args,
            host_dest="src_host",
            user_dest="src_user",
            password_dest="src_pass",
            client_id_dest="src_client_id",
            client_secret_dest="src_client_secret",
            account_type_dest="src_account_type",
            defaults=source_defaults,
            dotenv_keys=dotenv_keys,
            host_option="--src-host",
            user_option="--src-user",
            password_option="--src-pass",
            oauth_option="--src-oauth2-client-id",
        )
    else:
        args.src_host = source_defaults.host.value
        args.src_user = source_defaults.user.value
        args.src_client_secret = source_defaults.client_secret.value
        args.src_account_type = source_defaults.account_type.value
    if not dest_is_local:
        parse_account_arguments(
            parser,
            args,
            host_dest="dest_host",
            user_dest="dest_user",
            password_dest="dest_pass",
            client_id_dest="dest_client_id",
            client_secret_dest="dest_client_secret",
            account_type_dest="dest_account_type",
            defaults=destination_defaults,
            dotenv_keys=dotenv_keys,
            host_option="--dest-host",
            user_option="--dest-user",
            password_option="--dest-pass",
            oauth_option="--dest-oauth2-client-id",
        )
    else:
        args.dest_host = destination_defaults.host.value
        args.dest_user = destination_defaults.user.value
        args.dest_client_secret = destination_defaults.client_secret.value
        args.dest_account_type = destination_defaults.account_type.value

    return args, src_is_local, dest_is_local
