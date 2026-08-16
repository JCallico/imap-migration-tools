"""Tests for shared CLI configuration resolution."""

import argparse

from cli.common import resolve_authentication


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
