"""Tests for shared CLI configuration resolution."""

import argparse

from cli.backup import parse_arguments as parse_backup_arguments
from cli.common import resolve_authentication
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

    resolve_authentication(
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
