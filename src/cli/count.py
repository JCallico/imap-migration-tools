"""Argument parsing for the email count command."""

import argparse
import os
import sys
from typing import Optional

from utils import imap_common


def parse_arguments(argv: Optional[list[str]] = None) -> tuple[argparse.Namespace, bool]:
    """Parse configuration and return the resolved arguments and local-mode flag."""
    default_path = os.getenv("BACKUP_LOCAL_PATH") or os.getenv("SRC_LOCAL_PATH")
    default_host = os.getenv("IMAP_HOST") or os.getenv("SRC_IMAP_HOST")
    default_user = os.getenv("IMAP_USERNAME") or os.getenv("SRC_IMAP_USERNAME")
    default_pass = os.getenv("IMAP_PASSWORD") or os.getenv("SRC_IMAP_PASSWORD")
    default_client_id = os.getenv("OAUTH2_CLIENT_ID") or os.getenv("SRC_OAUTH2_CLIENT_ID")
    default_client_secret = os.getenv("OAUTH2_CLIENT_SECRET") or os.getenv("SRC_OAUTH2_CLIENT_SECRET")
    default_account_type = os.getenv("ACCOUNT_TYPE", "auto")

    parser = argparse.ArgumentParser(
        description="Count emails in IMAP account.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")
    parser.add_argument(
        "--path",
        help="Local backup root to count (counts .eml files per folder); cannot be combined with IMAP arguments.",
    )
    parser.add_argument("--host", help="IMAP Server (or IMAP_HOST / SRC_IMAP_HOST)")
    parser.add_argument("--user", help="Username (or IMAP_USERNAME / SRC_IMAP_USERNAME)")

    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--pass", dest="password", help="Password (or IMAP_PASSWORD / SRC_IMAP_PASSWORD)")
    auth_group.add_argument(
        "--oauth2-client-id",
        dest="client_id",
        help="OAuth2 Client ID (or OAUTH2_CLIENT_ID / SRC_OAUTH2_CLIENT_ID)",
    )
    auth_group.add_argument("--client-id", dest="client_id", help=argparse.SUPPRESS)
    parser.add_argument(
        "--oauth2-client-secret",
        dest="client_secret",
        help="OAuth2 Client Secret (if required) (or OAUTH2_CLIENT_SECRET / SRC_OAUTH2_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--account-type",
        choices=("auto", "personal", "work"),
        help="OAuth provider account type (auto, personal, or work; or ACCOUNT_TYPE)",
    )
    parser.add_argument("--client-secret", dest="client_secret", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)
    explicit_path = hasattr(args, "path")
    explicit_imap = any(
        hasattr(args, name) for name in ("host", "user", "password", "client_id", "client_secret", "account_type")
    )
    if explicit_path and explicit_imap:
        parser.error("--path cannot be combined with explicit IMAP connection arguments")

    local_mode = explicit_path or (not explicit_imap and bool(default_path))
    if local_mode:
        path = getattr(args, "path", default_path)
        if not path:
            parser.error("--path must specify a non-empty local backup root")
        if not os.path.isdir(path):
            print(f"Error: Local path does not exist or is not a directory: {path}")
            sys.exit(1)
        args.path = path
        return args, True

    args.host = getattr(args, "host", default_host)
    args.user = getattr(args, "user", default_user)
    args.password = getattr(args, "password", default_pass)
    args.client_id = getattr(args, "client_id", default_client_id)
    args.client_secret = getattr(args, "client_secret", default_client_secret)
    args.account_type = getattr(args, "account_type", default_account_type)

    if not args.host:
        parser.error("--host is required when IMAP_HOST and SRC_IMAP_HOST are not set")
    if not args.user:
        parser.error("--user is required when IMAP_USERNAME and SRC_IMAP_USERNAME are not set")
    if not args.password and not args.client_id:
        parser.error("one of --pass or --oauth2-client-id is required when authentication is not configured")

    return args, False
