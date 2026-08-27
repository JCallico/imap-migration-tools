"""Tests for shared CLI configuration resolution."""

import argparse

import pytest

from cli.backup import parse_arguments as parse_backup_arguments
from cli.common import AccountDefaults, EnvironmentValue, parse_account_arguments, parse_authentication_arguments
from cli.compare import parse_arguments as parse_compare_arguments
from cli.count import parse_arguments as parse_count_arguments
from cli.migrate import parse_arguments as parse_migrate_arguments
from cli.restore import parse_arguments as parse_restore_arguments
from conftest import temp_env


def test_explicit_oauth_overrides_inherited_password():
    """An explicit OAuth client ID clears an inherited password."""
    parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--password")
    auth.add_argument("--oauth-client", dest="client_id")
    args = parser.parse_args(["--oauth-client", "explicit-client"])

    parse_authentication_arguments(
        parser,
        args,
        password_dest="password",
        client_id_dest="client_id",
        default_password=EnvironmentValue("inherited-password", "PASSWORD"),
        default_client_id=EnvironmentValue(None, "OAUTH_CLIENT"),
        dotenv_keys=frozenset(),
        password_option="--password",
        oauth_option="--oauth-client",
    )

    assert args.password is None
    assert args.client_id == "explicit-client"


def test_dotenv_oauth_wins_when_both_authentication_methods_are_configured():
    """OAuth remains the compatibility choice when both methods come from dotenv."""
    parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    args = parser.parse_args([])

    parse_authentication_arguments(
        parser,
        args,
        password_dest="password",
        client_id_dest="client_id",
        default_password=EnvironmentValue("dotenv-password", "PASSWORD"),
        default_client_id=EnvironmentValue("dotenv-client", "OAUTH_CLIENT"),
        dotenv_keys=frozenset({"PASSWORD", "OAUTH_CLIENT"}),
        password_option="--password",
        oauth_option="--oauth-client",
    )

    assert args.password is None
    assert args.client_id == "dotenv-client"


def _account_defaults(*, host=None, user=None, password="password"):
    return AccountDefaults(
        host=EnvironmentValue(host, "HOST"),
        user=EnvironmentValue(user, "USER"),
        password=EnvironmentValue(password, "PASSWORD"),
        client_id=EnvironmentValue(None, "OAUTH_CLIENT"),
        client_secret=EnvironmentValue(None, "OAUTH_SECRET"),
        account_type=EnvironmentValue("auto", "ACCOUNT_TYPE"),
    )


def _parse_account(parser, args, defaults, *, dotenv_keys=frozenset()):
    parse_account_arguments(
        parser,
        args,
        host_dest="host",
        user_dest="user",
        password_dest="password",
        client_id_dest="client_id",
        client_secret_dest="client_secret",
        account_type_dest="account_type",
        defaults=defaults,
        dotenv_keys=dotenv_keys,
        host_option="--host",
        user_option="--user",
        password_option="--password",
        oauth_option="--oauth-client",
    )


def test_account_requires_configured_host(capsys):
    parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)

    with pytest.raises(SystemExit) as exc_info:
        _parse_account(parser, parser.parse_args([]), _account_defaults(user="user"))

    assert exc_info.value.code == 2
    assert "--host is required" in capsys.readouterr().err


def test_account_requires_configured_username(capsys):
    parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    dotenv_keys = frozenset({"HOST", "PASSWORD"})

    with pytest.raises(SystemExit) as exc_info:
        _parse_account(
            parser,
            parser.parse_args([]),
            _account_defaults(host="imap.example.com"),
            dotenv_keys=dotenv_keys,
        )

    assert exc_info.value.code == 2
    assert "--user is required" in capsys.readouterr().err


def test_compare_rejects_destination_path_with_destination_imap_arguments(tmp_path, capsys):
    with temp_env({}), pytest.raises(SystemExit) as exc_info:
        parse_compare_arguments(["--dest-path", str(tmp_path), "--dest-host", "imap.example.com"])

    assert exc_info.value.code == 2
    assert "--dest-path cannot be combined" in capsys.readouterr().err


def test_compare_rejects_empty_source_path(capsys):
    with temp_env({}), pytest.raises(SystemExit) as exc_info:
        parse_compare_arguments(["--src-path", ""])

    assert exc_info.value.code == 2
    assert "--src-path must specify a non-empty" in capsys.readouterr().err


def test_compare_rejects_empty_destination_path(tmp_path, capsys):
    with temp_env({}), pytest.raises(SystemExit) as exc_info:
        parse_compare_arguments(["--src-path", str(tmp_path), "--dest-path", ""])

    assert exc_info.value.code == 2
    assert "--dest-path must specify a non-empty" in capsys.readouterr().err


def test_count_rejects_empty_local_path(capsys):
    with temp_env({}), pytest.raises(SystemExit) as exc_info:
        parse_count_arguments(["--path", ""])

    assert exc_info.value.code == 2
    assert "--path must specify a non-empty" in capsys.readouterr().err


def test_count_rejects_missing_local_path(tmp_path, capsys):
    missing_path = tmp_path / "missing"

    with temp_env({}), pytest.raises(SystemExit) as exc_info:
        parse_count_arguments(["--path", str(missing_path)])

    assert exc_info.value.code == 1
    assert f"Local path does not exist or is not a directory: {missing_path}" in capsys.readouterr().out


def test_backup_host_override_rejects_inherited_password_account():
    """A backup host override cannot send an inherited password to another server."""
    environment = {
        "SRC_IMAP_HOST": "imap.gmail.com",
        "SRC_IMAP_USERNAME": "user@gmail.com",
        "SRC_IMAP_PASSWORD": "gmail-app-password",
        "BACKUP_LOCAL_PATH": "/tmp/backup",
    }

    with temp_env(environment), pytest.raises(SystemExit) as exc_info:
        parse_backup_arguments(["--src-host", "imap.example.com"])

    assert exc_info.value.code == 2


def test_backup_host_override_rejects_inherited_microsoft_oauth_account():
    """A Gmail host override cannot silently reuse a Microsoft OAuth account."""
    environment = {
        "SRC_IMAP_HOST": "outlook.office365.com",
        "SRC_IMAP_USERNAME": "old@example.com",
        "SRC_OAUTH2_CLIENT_ID": "microsoft-client",
        "SRC_ACCOUNT_TYPE": "work",
        "BACKUP_LOCAL_PATH": "/tmp/backup",
    }

    with temp_env(environment), pytest.raises(SystemExit) as exc_info:
        parse_backup_arguments(["--src-host", "imap.gmail.com"])

    assert exc_info.value.code == 2


def test_complete_host_override_does_not_inherit_oauth_adjuncts():
    """A complete account override resets the old account's secret and provider options."""
    environment = {
        "SRC_IMAP_HOST": "outlook.office365.com",
        "SRC_IMAP_USERNAME": "old@example.com",
        "SRC_OAUTH2_CLIENT_ID": "microsoft-client",
        "SRC_OAUTH2_CLIENT_SECRET": "old-secret",
        "SRC_ACCOUNT_TYPE": "work",
        "BACKUP_LOCAL_PATH": "/tmp/backup",
    }

    with temp_env(environment):
        args = parse_backup_arguments(
            [
                "--src-host",
                "imap.gmail.com",
                "--src-user",
                "new@gmail.com",
                "--src-oauth2-client-id",
                "google-client",
            ]
        )

    assert args.src_client_id == "google-client"
    assert args.src_client_secret is None
    assert args.src_account_type == "auto"


def test_migration_destination_host_override_rejects_inherited_credentials():
    """A migration destination override cannot reuse the old destination password."""
    environment = {
        "SRC_IMAP_HOST": "imap.source.example",
        "SRC_IMAP_USERNAME": "source@example.com",
        "SRC_IMAP_PASSWORD": "source-password",
        "DEST_IMAP_HOST": "imap.old-provider.example",
        "DEST_IMAP_USERNAME": "user@old-provider.example",
        "DEST_IMAP_PASSWORD": "old-password",
    }

    with temp_env(environment), pytest.raises(SystemExit) as exc_info:
        parse_migrate_arguments(["--dest-host", "imap.new-provider.example"])

    assert exc_info.value.code == 2


def test_count_host_override_rejects_inherited_icloud_credentials():
    """A count host override cannot redirect inherited iCloud credentials."""
    environment = {
        "IMAP_HOST": "imap.mail.me.com",
        "IMAP_USERNAME": "user@icloud.com",
        "IMAP_PASSWORD": "icloud-password",
    }

    with temp_env(environment), pytest.raises(SystemExit) as exc_info:
        parse_count_arguments(["--host", "imap.example.com"])

    assert exc_info.value.code == 2


def test_compare_source_host_override_rejects_inherited_credentials():
    """A comparison source override cannot reuse the configured source credentials."""
    environment = {
        "SRC_IMAP_HOST": "imap.source.example",
        "SRC_IMAP_USERNAME": "source@example.com",
        "SRC_IMAP_PASSWORD": "source-password",
        "DEST_IMAP_HOST": "imap.destination.example",
        "DEST_IMAP_USERNAME": "destination@example.com",
        "DEST_IMAP_PASSWORD": "destination-password",
    }

    with temp_env(environment), pytest.raises(SystemExit) as exc_info:
        parse_compare_arguments(["--src-host", "imap.different-provider.example"])

    assert exc_info.value.code == 2


def test_partial_username_and_password_override_keeps_inherited_host():
    """Username and password may be changed together when the configured host is retained."""
    environment = {
        "SRC_IMAP_HOST": "imap.gmail.com",
        "SRC_IMAP_USERNAME": "original@gmail.com",
        "SRC_IMAP_PASSWORD": "original-password",
        "BACKUP_LOCAL_PATH": "/tmp/backup",
    }

    with temp_env(environment):
        args = parse_backup_arguments(["--src-user", "another-user@gmail.com", "--src-pass", "new-password"])

    assert args.src_host == "imap.gmail.com"
    assert args.src_user == "another-user@gmail.com"
    assert args.src_pass == "new-password"


def test_explicit_password_keeps_inherited_host_and_clears_oauth_selection():
    """Selecting password authentication remains valid without repeating the inherited host."""
    environment = {
        "SRC_IMAP_HOST": "imap.gmail.com",
        "SRC_IMAP_USERNAME": "user@gmail.com",
        "SRC_OAUTH2_CLIENT_ID": "inherited-client",
        "SRC_OAUTH2_CLIENT_SECRET": "inherited-secret",
        "BACKUP_LOCAL_PATH": "/tmp/backup",
    }

    with temp_env(environment):
        args = parse_backup_arguments(["--src-pass", "temporary-app-password"])

    assert args.src_host == "imap.gmail.com"
    assert args.src_pass == "temporary-app-password"
    assert args.src_client_id is None


def test_negative_boolean_options_override_enabled_environment():
    """Every environment-backed boolean can be disabled explicitly."""
    environment = {
        "SRC_IMAP_HOST": "source.example.com",
        "SRC_IMAP_USERNAME": "source",
        "SRC_IMAP_PASSWORD": "source-password",
        "DEST_IMAP_HOST": "destination.example.com",
        "DEST_IMAP_USERNAME": "destination",
        "DEST_IMAP_PASSWORD": "destination-password",
        "BACKUP_LOCAL_PATH": "/tmp/backup",
        "DELETE_FROM_SOURCE": "true",
        "DEST_DELETE": "true",
        "PRESERVE_LABELS": "true",
        "PRESERVE_FLAGS": "true",
        "GMAIL_MODE": "true",
        "MANIFEST_ONLY": "true",
        "APPLY_LABELS": "true",
        "APPLY_FLAGS": "true",
        "FULL_RESTORE": "true",
        "FULL_MIGRATE": "true",
        "MIGRATE_CACHE_DIR": "/tmp/migration-cache",
    }

    with temp_env(environment):
        backup_args = parse_backup_arguments(
            [
                "--no-preserve-labels",
                "--no-preserve-flags",
                "--no-manifest-only",
                "--no-gmail-mode",
                "--no-dest-delete",
            ]
        )
        restore_args = parse_restore_arguments(
            [
                "--no-apply-labels",
                "--no-apply-flags",
                "--no-gmail-mode",
                "--no-full-restore",
                "--no-dest-delete",
            ]
        )
        migrate_args = parse_migrate_arguments(
            [
                "--no-src-delete",
                "--no-dest-delete",
                "--no-preserve-labels",
                "--no-preserve-flags",
                "--no-gmail-mode",
                "--no-full-migrate",
            ]
        )

    assert backup_args.preserve_labels is False
    assert backup_args.preserve_flags is False
    assert backup_args.manifest_only is False
    assert backup_args.gmail_mode is False
    assert backup_args.dest_delete is False
    assert restore_args.apply_labels is False
    assert restore_args.apply_flags is False
    assert restore_args.gmail_mode is False
    assert restore_args.full_restore is False
    assert restore_args.dest_delete is False
    assert migrate_args.delete is False
    assert migrate_args.dest_delete is False
    assert migrate_args.preserve_labels is False
    assert migrate_args.preserve_flags is False
    assert migrate_args.gmail_mode is False
    assert migrate_args.full_migrate is False
    assert migrate_args.migrate_cache == "/tmp/migration-cache"
