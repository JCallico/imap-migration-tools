"""Tests for shared CLI configuration resolution."""

import argparse

import pytest

from cli.backup import parse_arguments as parse_backup_arguments
from cli.common import parse_authentication_arguments
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
        default_password="inherited-password",
        default_client_id=None,
        password_option="--password",
        oauth_option="--oauth-client",
    )

    assert args.password is None
    assert args.client_id == "explicit-client"


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
