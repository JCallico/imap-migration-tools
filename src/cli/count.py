"""Argument parsing for the email count command."""

import argparse
import os
import sys
from typing import Optional

from cli.common import parse_account_arguments
from utils import imap_common


def parse_arguments(argv: Optional[list[str]] = None) -> tuple[argparse.Namespace, bool]:
    """Parse configuration and return the resolved arguments and local-mode flag."""
    default_path = os.getenv("BACKUP_LOCAL_PATH") or os.getenv("SRC_LOCAL_PATH")
    source_defaults = {
        "host": os.getenv("SRC_IMAP_HOST"),
        "user": os.getenv("SRC_IMAP_USERNAME"),
        "password": os.getenv("SRC_IMAP_PASSWORD"),
        "client_id": os.getenv("SRC_OAUTH2_CLIENT_ID"),
        "client_secret": os.getenv("SRC_OAUTH2_CLIENT_SECRET"),
        "account_type": os.getenv("SRC_ACCOUNT_TYPE", "auto"),
    }
    destination_defaults = {
        "host": os.getenv("DEST_IMAP_HOST"),
        "user": os.getenv("DEST_IMAP_USERNAME"),
        "password": os.getenv("DEST_IMAP_PASSWORD"),
        "client_id": os.getenv("DEST_OAUTH2_CLIENT_ID"),
        "client_secret": os.getenv("DEST_OAUTH2_CLIENT_SECRET"),
        "account_type": os.getenv("DEST_ACCOUNT_TYPE", "auto"),
    }
    count_defaults = {
        "host": os.getenv("IMAP_HOST") or source_defaults["host"],
        "user": os.getenv("IMAP_USERNAME") or source_defaults["user"],
        "password": os.getenv("IMAP_PASSWORD") or source_defaults["password"],
        "client_id": os.getenv("OAUTH2_CLIENT_ID") or source_defaults["client_id"],
        "client_secret": os.getenv("OAUTH2_CLIENT_SECRET") or source_defaults["client_secret"],
        "account_type": os.getenv("ACCOUNT_TYPE", source_defaults["account_type"]),
    }

    parser = argparse.ArgumentParser(
        description="Count emails in IMAP account.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {imap_common.get_version()}")
    parser.add_argument(
        "--target",
        choices=("local", "source", "destination"),
        help="Configured target to count when local, source, or destination settings are ambiguous.",
    )
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
    explicit_target = hasattr(args, "target")
    explicit_path = hasattr(args, "path")
    explicit_imap = any(
        hasattr(args, name) for name in ("host", "user", "password", "client_id", "client_secret", "account_type")
    )
    if explicit_path and explicit_target:
        parser.error("--path cannot be combined with --target")
    if explicit_path and explicit_imap:
        parser.error("--path cannot be combined with explicit IMAP connection arguments")
    if explicit_target and args.target == "local" and explicit_imap:
        parser.error("--target local cannot be combined with explicit IMAP connection arguments")

    source_configured = any(count_defaults[name] for name in ("host", "user", "password", "client_id"))
    destination_configured = any(destination_defaults[name] for name in ("host", "user", "password", "client_id"))
    if not explicit_target and not explicit_path and not explicit_imap:
        configured_targets = [
            name
            for name, configured in (
                ("local", bool(default_path)),
                ("source", source_configured),
                ("destination", destination_configured),
            )
            if configured
        ]
        if len(configured_targets) > 1:
            choices = ", ".join(configured_targets)
            parser.error(
                f"multiple count targets are configured ({choices}); select one with "
                "--target local, --target source, or --target destination"
            )
        selected_target = configured_targets[0] if configured_targets else "source"
    else:
        selected_target = getattr(args, "target", None)

    local_mode = explicit_path or selected_target == "local"
    if local_mode:
        path = getattr(args, "path", default_path)
        if not path:
            parser.error("--path must specify a non-empty local backup root")
        if not os.path.isdir(path):
            print(f"Error: Local path does not exist or is not a directory: {path}")
            sys.exit(1)
        args.path = path
        return args, True

    if selected_target == "destination":
        defaults = destination_defaults
    else:
        defaults = count_defaults

    parse_account_arguments(
        parser,
        args,
        host_dest="host",
        user_dest="user",
        password_dest="password",
        client_id_dest="client_id",
        client_secret_dest="client_secret",
        account_type_dest="account_type",
        default_host=defaults["host"],
        default_user=defaults["user"],
        default_password=defaults["password"],
        default_client_id=defaults["client_id"],
        default_client_secret=defaults["client_secret"],
        default_account_type=defaults["account_type"],
        host_option="--host",
        user_option="--user",
        password_option="--pass",
        oauth_option="--oauth2-client-id",
    )
    return args, False
