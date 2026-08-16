"""Shared command-line configuration resolution."""

import argparse
from typing import Optional


def resolve_authentication(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    *,
    password_dest: str,
    client_id_dest: str,
    default_password: Optional[str],
    default_client_id: Optional[str],
    password_option: str,
    oauth_option: str,
) -> None:
    """Resolve one explicit or inherited authentication method onto ``args``."""
    explicit_password = hasattr(args, password_dest)
    explicit_oauth = hasattr(args, client_id_dest)

    if explicit_password:
        setattr(args, client_id_dest, None)
    elif explicit_oauth:
        setattr(args, password_dest, None)
    elif default_client_id:
        setattr(args, password_dest, None)
        setattr(args, client_id_dest, default_client_id)
    else:
        setattr(args, password_dest, default_password)
        setattr(args, client_id_dest, None)

    if not getattr(args, password_dest) and not getattr(args, client_id_dest):
        parser.error(f"one of {password_option} or {oauth_option} is required when authentication is not configured")
