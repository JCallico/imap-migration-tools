"""Shared command-line configuration resolution."""

import argparse
from typing import Optional


def parse_authentication_arguments(
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
    """Resolve and validate authentication arguments, modifying ``args`` in place."""
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


def parse_account_arguments(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    *,
    host_dest: str,
    user_dest: str,
    password_dest: str,
    client_id_dest: str,
    client_secret_dest: str,
    account_type_dest: str,
    default_host: Optional[str],
    default_user: Optional[str],
    default_password: Optional[str],
    default_client_id: Optional[str],
    default_client_secret: Optional[str],
    default_account_type: str,
    host_option: str,
    user_option: str,
    password_option: str,
    oauth_option: str,
) -> None:
    """Resolve and validate an IMAP account, modifying ``args`` in place."""
    explicit_host = hasattr(args, host_dest)
    if explicit_host and (
        not hasattr(args, user_dest) or not any(hasattr(args, name) for name in (password_dest, client_id_dest))
    ):
        parser.error(
            f"{host_option} selects a different account and must be accompanied by {user_option} and one of "
            f"{password_option} or {oauth_option}; otherwise update the account in the environment or .env"
        )

    setattr(args, host_dest, getattr(args, host_dest, default_host))
    setattr(args, user_dest, getattr(args, user_dest, default_user))
    # OAuth adjuncts belong to the inherited account too. Do not carry them to an explicit host.
    setattr(
        args, client_secret_dest, getattr(args, client_secret_dest, None if explicit_host else default_client_secret)
    )
    setattr(
        args, account_type_dest, getattr(args, account_type_dest, "auto" if explicit_host else default_account_type)
    )
    parse_authentication_arguments(
        parser,
        args,
        password_dest=password_dest,
        client_id_dest=client_id_dest,
        default_password=default_password,
        default_client_id=default_client_id,
        password_option=password_option,
        oauth_option=oauth_option,
    )

    if not getattr(args, host_dest):
        parser.error(f"{host_option} is required when it is not configured in the environment or .env")
    if not getattr(args, user_dest):
        parser.error(f"{user_option} is required when it is not configured in the environment or .env")
