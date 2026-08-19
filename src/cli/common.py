"""Shared command-line configuration resolution."""

import argparse
import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class EnvironmentValue:
    """An environment-backed value and the variable that supplied it."""

    value: Optional[str]
    variable: str


@dataclass(frozen=True)
class AccountDefaults:
    """Environment-backed defaults for one IMAP account."""

    host: EnvironmentValue
    user: EnvironmentValue
    password: EnvironmentValue
    client_id: EnvironmentValue
    client_secret: EnvironmentValue
    account_type: EnvironmentValue


def read_account_defaults(prefix: str, fallback: Optional[AccountDefaults] = None) -> AccountDefaults:
    """Read an account namespace, optionally falling back field-by-field to another account."""
    variable_prefix = f"{prefix}_" if prefix else ""
    names = {
        "host": f"{variable_prefix}IMAP_HOST",
        "user": f"{variable_prefix}IMAP_USERNAME",
        "password": f"{variable_prefix}IMAP_PASSWORD",
        "client_id": f"{variable_prefix}OAUTH2_CLIENT_ID",
        "client_secret": f"{variable_prefix}OAUTH2_CLIENT_SECRET",
        "account_type": f"{variable_prefix}ACCOUNT_TYPE",
    }

    def read(name: str, default: Optional[EnvironmentValue] = None) -> EnvironmentValue:
        value = os.getenv(names[name])
        if value or default is None:
            return EnvironmentValue(value, names[name])
        return default

    account_type = read("account_type", fallback.account_type if fallback else None)
    if account_type.value is None:
        account_type = EnvironmentValue("auto", account_type.variable)
    return AccountDefaults(
        host=read("host", fallback.host if fallback else None),
        user=read("user", fallback.user if fallback else None),
        password=read("password", fallback.password if fallback else None),
        client_id=read("client_id", fallback.client_id if fallback else None),
        client_secret=read("client_secret", fallback.client_secret if fallback else None),
        account_type=account_type,
    )


def parse_authentication_arguments(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    *,
    password_dest: str,
    client_id_dest: str,
    default_password: EnvironmentValue,
    default_client_id: EnvironmentValue,
    dotenv_keys: frozenset[str],
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
    elif default_password.value and default_password.variable not in dotenv_keys:
        setattr(args, password_dest, default_password.value)
        setattr(args, client_id_dest, None)
    elif default_client_id.value and default_client_id.variable not in dotenv_keys:
        setattr(args, password_dest, None)
        setattr(args, client_id_dest, default_client_id.value)
    elif default_client_id.value:
        setattr(args, password_dest, None)
        setattr(args, client_id_dest, default_client_id.value)
    else:
        setattr(args, password_dest, default_password.value)
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
    defaults: AccountDefaults,
    dotenv_keys: frozenset[str] = frozenset(),
    host_option: str,
    user_option: str,
    password_option: str,
    oauth_option: str,
) -> None:
    """Resolve and validate an IMAP account, modifying ``args`` in place."""
    explicit_host = hasattr(args, host_dest)
    os_host = bool(defaults.host.value) and defaults.host.variable not in dotenv_keys
    user_from_cli_or_os = hasattr(args, user_dest) or (
        bool(defaults.user.value) and defaults.user.variable not in dotenv_keys
    )
    auth_from_cli_or_os = any(hasattr(args, name) for name in (password_dest, client_id_dest)) or (
        (bool(defaults.password.value) and defaults.password.variable not in dotenv_keys)
        or (bool(defaults.client_id.value) and defaults.client_id.variable not in dotenv_keys)
    )
    complete_os_account = user_from_cli_or_os and auth_from_cli_or_os
    if (
        explicit_host
        and (not hasattr(args, user_dest) or not any(hasattr(args, name) for name in (password_dest, client_id_dest)))
    ) or (not explicit_host and os_host and not complete_os_account):
        parser.error(
            f"{host_option} selects a different account and must be accompanied by {user_option} and one of "
            f"{password_option} or {oauth_option} from the same or a higher-precedence source"
        )

    setattr(args, host_dest, getattr(args, host_dest, defaults.host.value))
    setattr(args, user_dest, getattr(args, user_dest, defaults.user.value))
    # OAuth adjuncts belong to the inherited account too. Do not carry them to an explicit host.
    reset_inherited_account = explicit_host or os_host
    inherited_secret = defaults.client_secret.value
    if reset_inherited_account and defaults.client_secret.variable in dotenv_keys:
        inherited_secret = None
    inherited_account_type = defaults.account_type.value
    if reset_inherited_account and defaults.account_type.variable in dotenv_keys:
        inherited_account_type = "auto"
    setattr(args, client_secret_dest, getattr(args, client_secret_dest, None if explicit_host else inherited_secret))
    setattr(
        args, account_type_dest, getattr(args, account_type_dest, "auto" if explicit_host else inherited_account_type)
    )
    parse_authentication_arguments(
        parser,
        args,
        password_dest=password_dest,
        client_id_dest=client_id_dest,
        default_password=defaults.password,
        default_client_id=defaults.client_id,
        dotenv_keys=dotenv_keys,
        password_option=password_option,
        oauth_option=oauth_option,
    )

    if not getattr(args, host_dest):
        parser.error(f"{host_option} is required when it is not configured in the environment or .env")
    if not getattr(args, user_dest):
        parser.error(f"{user_option} is required when it is not configured in the environment or .env")
