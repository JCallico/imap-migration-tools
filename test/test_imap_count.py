"""
Tests for count_imap_emails.py

Tests cover:
- Basic email counting
- Multiple folder counting
- Empty folder handling
- Error handling
- Configuration validation
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_count as count_imap_emails
from conftest import temp_argv, temp_env
from utils import imap_common


def _mock_imap_env(port):
    return {
        "IMAP_HOST": f"imap://localhost:{port}",
        "IMAP_USERNAME": "user",
        "IMAP_PASSWORD": "pass",
    }


def _account_env(prefix, port):
    return {
        f"{prefix}_IMAP_HOST": f"imap://localhost:{port}",
        f"{prefix}_IMAP_USERNAME": "user",
        f"{prefix}_IMAP_PASSWORD": "pass",
    }


@pytest.fixture
def dotenv_file(tmp_path):
    """Create a .env file and run the test from its directory."""
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:

        def write(values):
            (tmp_path / ".env").write_text(
                "\n".join(f'{name}="{value}"' for name, value in values.items()), encoding="utf-8"
            )

        yield write
    finally:
        os.chdir(original_cwd)


class TestEmailCounting:
    """Tests for email counting functionality."""

    def test_count_single_folder(self, single_mock_server, capsys):
        """Test counting emails in a single folder."""
        src_data = {
            "INBOX": [
                b"Subject: Email 1\r\n\r\nBody",
                b"Subject: Email 2\r\n\r\nBody",
                b"Subject: Email 3\r\n\r\nBody",
            ]
        }
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env):
            count_imap_emails.count_emails(env["IMAP_HOST"], env["IMAP_USERNAME"], env["IMAP_PASSWORD"])

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "3" in captured.out

    def test_count_multiple_folders(self, single_mock_server, capsys):
        """Test counting emails across multiple folders."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
            "Archive": [b"Subject: 4\r\n\r\nB", b"Subject: 5\r\n\r\nB", b"Subject: 6\r\n\r\nB"],
        }
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env):
            count_imap_emails.count_emails(env["IMAP_HOST"], env["IMAP_USERNAME"], env["IMAP_PASSWORD"])

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out
        assert "Archive" in captured.out
        # Total should be 6
        assert "6" in captured.out

    def test_empty_folder(self, single_mock_server, capsys):
        """Test counting in empty folders."""
        src_data = {"INBOX": [], "Empty": []}
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env):
            count_imap_emails.count_emails(env["IMAP_HOST"], env["IMAP_USERNAME"], env["IMAP_PASSWORD"])

        captured = capsys.readouterr()
        assert "0" in captured.out

    def test_empty_search_payload_counts_as_zero(self, monkeypatch, capsys):
        """Treat a successful SEARCH response with no payload as an empty folder."""

        class FakeConn:
            def select(self, _folder, readonly=False):
                return "OK", [b"0"]

            def search(self, _charset, _criteria):
                return "OK", [None]

            def logout(self):
                return "BYE", [b"Logged out"]

        monkeypatch.setattr(imap_common, "get_imap_connection", lambda *_args: FakeConn())
        monkeypatch.setattr(imap_common, "list_selectable_folders", lambda _conn: ["Empty"])

        count_imap_emails.count_emails("imap.example.com", "user", "password")

        captured = capsys.readouterr()
        assert "Empty" in captured.out
        assert "TOTAL" in captured.out
        assert "An error occurred" not in captured.out


class TestLocalEmailCounting:
    """Tests for counting emails from a local backup folder."""

    def test_count_local_folders(self, tmp_path, capsys):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")
        (inbox_path / "2_b.eml").write_bytes(b"Subject: B\r\n\r\nBody")

        gmail_all_mail = tmp_path / "[Gmail]" / "All Mail"
        gmail_all_mail.mkdir(parents=True)
        (gmail_all_mail / "1_c.eml").write_bytes(b"Subject: C\r\n\r\nBody")

        count_imap_emails.count_local_emails(str(tmp_path))

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "[Gmail]/All Mail" in captured.out
        assert "TOTAL" in captured.out
        assert "3" in captured.out

    def test_count_local_ignores_hidden_dirs(self, tmp_path, capsys):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")
        (inbox_path / "note.txt").write_text("ignore")

        hidden_path = tmp_path / ".hidden"
        hidden_path.mkdir()
        (hidden_path / "1_hidden.eml").write_bytes(b"Subject: Hidden\r\n\r\nBody")

        cache_path = tmp_path / "__pycache__"
        cache_path.mkdir()
        (cache_path / "1_cache.eml").write_bytes(b"Subject: Cache\r\n\r\nBody")

        nested_path = tmp_path / "Projects" / "Sub"
        nested_path.mkdir(parents=True)
        (nested_path / "1_sub.eml").write_bytes(b"Subject: Sub\r\n\r\nBody")

        count_imap_emails.count_local_emails(str(tmp_path))

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Projects/Sub" in captured.out
        assert ".hidden" not in captured.out
        assert "__pycache__" not in captured.out

    def test_get_local_email_count_unreadable_folder(self, tmp_path):
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")

        os.chmod(inbox_path, 0)
        try:
            result = imap_common.get_local_email_count(str(tmp_path), "INBOX")
            assert result is None
        finally:
            os.chmod(inbox_path, 0o700)


class TestImapCommonHelpers:
    """Tests for imap_common helpers via script tests."""

    def test_list_selectable_folders_filters_noselect(self):
        class FakeConn:
            def list(self):
                return (
                    "OK",
                    [
                        b'(\\Noselect) "/" "Archive"',
                        b'(\\HasNoChildren) "/" "INBOX"',
                        '(\\HasNoChildren) "/" "Sent"',
                    ],
                )

        result = imap_common.list_selectable_folders(FakeConn())
        assert result == ["INBOX", "Sent"]

    def test_list_selectable_folders_list_error(self):
        class FakeConn:
            def list(self):
                return ("NO", [])

        result = imap_common.list_selectable_folders(FakeConn())
        assert result == []

    def test_list_selectable_folders_exception(self):
        class FakeConn:
            def list(self):
                raise Exception("list failed")

        result = imap_common.list_selectable_folders(FakeConn())
        assert result == []

    def test_get_imap_connection_oauth2_uses_authenticate(self):
        from unittest.mock import patch

        class FakeIMAP:
            def __init__(self, _host):
                self.auth_called = False
                self.login_called = False

            def authenticate(self, _mechanism, auth_cb):
                self.auth_called = True
                auth_cb(None)

            def login(self, _user, _password):
                self.login_called = True

        with patch.object(imap_common.imaplib, "IMAP4_SSL", FakeIMAP):
            conn = imap_common.get_imap_connection("host", "user", oauth2_token="token")

        assert conn.auth_called is True
        assert conn.login_called is False

    def test_get_imap_connection_basic_login(self):
        from unittest.mock import patch

        class FakeIMAP:
            def __init__(self, _host):
                self.auth_called = False
                self.login_called = False

            def authenticate(self, _mechanism, _auth_cb):
                self.auth_called = True

            def login(self, _user, _password):
                self.login_called = True

        with patch.object(imap_common.imaplib, "IMAP4_SSL", FakeIMAP):
            conn = imap_common.get_imap_connection("host", "user", password="pass")

        assert conn.login_called is True
        assert conn.auth_called is False

    def test_ensure_connection_returns_same_conn_when_healthy(self):
        class GoodConn:
            def __init__(self):
                self.noop_calls = 0

            def noop(self):
                self.noop_calls += 1

        conn = GoodConn()
        result = imap_common.ensure_connection(conn, "host", "user", "pass")
        assert result is conn
        assert conn.noop_calls == 1

    def test_ensure_connection_reconnects_on_noop_error(self):
        from unittest.mock import patch

        class BadConn:
            def noop(self):
                raise Exception("fail")

        new_conn = object()
        with patch.object(imap_common, "get_imap_connection", return_value=new_conn):
            result = imap_common.ensure_connection(BadConn(), "host", "user", "pass")
        assert result is new_conn

    def test_ensure_connection_from_conf_reconnects_on_noop_error(self):
        from unittest.mock import patch

        class BadConn:
            def noop(self):
                raise Exception("fail")

        new_conn = object()
        with patch.object(imap_common, "get_imap_connection_from_conf", return_value=new_conn):
            result = imap_common.ensure_connection_from_conf(BadConn(), {"host": "h", "user": "u"})
        assert result is new_conn


class TestMainFunction:
    """Tests for main function and CLI."""

    def test_main_with_env_vars(self, single_mock_server, capsys):
        """Test main function with environment variables."""
        src_data = {"INBOX": [b"Subject: Test\r\n\r\nBody"]}
        _, port = single_mock_server(src_data)

        env = _mock_imap_env(port)
        with temp_env(env), temp_argv(["count_imap_emails.py"]):
            count_imap_emails.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out

    def test_main_uses_dotenv_configuration(self, single_mock_server, capsys, dotenv_file):
        """End-to-end: .env credentials drive IMAP counting."""
        _, port = single_mock_server({"INBOX": [b"Subject: Dotenv\r\n\r\nBody"]})

        dotenv_file(_mock_imap_env(port))
        with temp_env({}), temp_argv(["count_imap_emails.py"]):
            count_imap_emails.main()

        assert "INBOX" in capsys.readouterr().out

    def test_os_account_overrides_dotenv_endpoint(self, single_mock_server, capsys, dotenv_file):
        """A complete count-specific OS account wins over a conflicting .env account."""
        _, port = single_mock_server({"INBOX": [b"Subject: OS\r\n\r\nBody"]})
        dotenv_file(
            {
                "IMAP_HOST": "imap://localhost:1",
                "IMAP_USERNAME": "dotenv-user",
                "IMAP_PASSWORD": "dotenv-password",
            }
        )

        with temp_env(_mock_imap_env(port)):
            count_imap_emails.main([])

        assert f"Host            : imap://localhost:{port}" in capsys.readouterr().out

    def test_explicit_password_overrides_dotenv_oauth(self, single_mock_server, capsys, dotenv_file):
        """An explicit password prevents an inherited OAuth client ID from selecting OAuth."""
        _, port = single_mock_server({"INBOX": [b"Subject: Password\r\n\r\nBody"]})
        dotenv_file({**_mock_imap_env(port), "OAUTH2_CLIENT_ID": "inherited-oauth-client"})

        with temp_env({}):
            count_imap_emails.main(["--pass", "pass"])

        assert "INBOX" in capsys.readouterr().out

    def test_cli_oauth_overrides_dotenv_password(self, single_mock_server, capsys, dotenv_file, monkeypatch):
        """An explicit OAuth client selects OAuth over a lower-precedence .env password."""
        _, port = single_mock_server({"INBOX": [b"Subject: OAuth\r\n\r\nBody"]})
        dotenv_file(_mock_imap_env(port))
        monkeypatch.setattr(
            count_imap_emails.imap_oauth2, "acquire_token", lambda *_args, **_kwargs: ("token", "microsoft")
        )

        with temp_env({}):
            count_imap_emails.main(["--oauth2-client-id", "cli-client"])

        assert "INBOX" in capsys.readouterr().out

    def test_os_password_overrides_dotenv_oauth(self, single_mock_server, capsys, dotenv_file, monkeypatch):
        """An OS password selects password authentication over .env OAuth."""
        _, port = single_mock_server({"INBOX": [b"Subject: OS\r\n\r\nBody"]})
        dotenv_file(
            {
                "IMAP_HOST": f"imap://localhost:{port}",
                "IMAP_USERNAME": "user",
                "OAUTH2_CLIENT_ID": "dotenv-client",
            }
        )
        monkeypatch.setattr(
            count_imap_emails.imap_oauth2,
            "acquire_token",
            lambda *_args, **_kwargs: pytest.fail("OAuth must not be selected"),
        )

        with temp_env({"IMAP_PASSWORD": "pass"}):
            count_imap_emails.main([])

        assert "INBOX" in capsys.readouterr().out

    def test_os_oauth_overrides_dotenv_password(self, single_mock_server, capsys, dotenv_file, monkeypatch):
        """An OS OAuth client selects OAuth over a lower-precedence .env password."""
        _, port = single_mock_server({"INBOX": [b"Subject: OS OAuth\r\n\r\nBody"]})
        dotenv_file(
            {
                "IMAP_HOST": f"imap://localhost:{port}",
                "IMAP_USERNAME": "user",
                "IMAP_PASSWORD": "dotenv-password",
            }
        )
        monkeypatch.setattr(
            count_imap_emails.imap_oauth2,
            "acquire_token",
            lambda *_args, **_kwargs: ("token", "microsoft"),
        )

        with temp_env({"OAUTH2_CLIENT_ID": "os-client"}):
            count_imap_emails.main([])

        output = capsys.readouterr().out
        assert "Auth Method     : OAuth2/microsoft (XOAUTH2)" in output
        assert "INBOX" in output

    def test_explicit_imap_arguments_override_dotenv_local_path(
        self, single_mock_server, tmp_path, capsys, dotenv_file
    ):
        """Explicit IMAP configuration selects IMAP mode over a .env local path."""
        _, port = single_mock_server({"INBOX": [b"Subject: IMAP wins\r\n\r\nBody"]})
        local_path = tmp_path / "local-backup"
        local_path.mkdir()
        dotenv_file({"BACKUP_LOCAL_PATH": str(local_path)})

        with temp_env({}):
            count_imap_emails.main(
                [
                    f"--ho=imap://localhost:{port}",
                    "--user",
                    "user",
                    "--pass",
                    "pass",
                ]
            )

        captured = capsys.readouterr().out
        assert f"Host            : imap://localhost:{port}" in captured
        assert "INBOX" in captured
        assert "Local Path" not in captured

    def test_explicit_path_and_imap_arguments_are_rejected(self, tmp_path, capsys):
        """Conflicting explicit mode selectors produce an actionable parser error."""
        with temp_env({}):
            with pytest.raises(SystemExit) as exc_info:
                count_imap_emails.main(
                    [
                        "--path",
                        str(tmp_path),
                        "--host",
                        "imap.example.com",
                        "--user",
                        "user",
                        "--pass",
                        "pass",
                    ]
                )

        assert exc_info.value.code == 2
        assert "cannot be combined" in capsys.readouterr().err


class TestTargetSelection:
    """Tests for deterministic selection between configured count targets."""

    def test_local_path_and_source_account_require_target(self, tmp_path, capsys):
        env = {"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("SRC", 10143)}

        with temp_env(env), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.parse_arguments([])

        assert exc_info.value.code == 2
        assert "multiple count targets are configured (local, source)" in capsys.readouterr().err

    def test_local_path_and_destination_account_require_target(self, tmp_path, capsys):
        env = {"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("DEST", 10143)}

        with temp_env(env), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.parse_arguments([])

        assert exc_info.value.code == 2
        assert "multiple count targets are configured (local, destination)" in capsys.readouterr().err

    def test_source_and_destination_accounts_require_target(self, capsys):
        env = {**_account_env("SRC", 10143), **_account_env("DEST", 10144)}

        with temp_env(env), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.parse_arguments([])

        assert exc_info.value.code == 2
        assert "multiple count targets are configured (source, destination)" in capsys.readouterr().err

    def test_dotenv_with_local_and_source_targets_requires_selection(self, tmp_path, dotenv_file, capsys):
        dotenv_file({"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("SRC", 10143)})

        with temp_env({}), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.main([])

        assert exc_info.value.code == 2
        assert "select one with --target local" in capsys.readouterr().err

    def test_target_local_counts_configured_backup(self, tmp_path, capsys):
        inbox = tmp_path / "INBOX"
        inbox.mkdir()
        (inbox / "message.eml").write_text("Subject: Local\n\nBody", encoding="utf-8")
        env = {"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("SRC", 10143)}

        with temp_env(env), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.main(["--target", "local"])

        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert f"Local Path      : {tmp_path}" in output
        assert "INBOX" in output

    def test_target_source_counts_source_account(self, single_mock_server, tmp_path, capsys):
        _, port = single_mock_server({"INBOX": [b"Subject: Source\r\n\r\nBody"]})
        env = {"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("SRC", port)}

        with temp_env(env):
            count_imap_emails.main(["--target", "source"])

        output = capsys.readouterr().out
        assert f"Host            : imap://localhost:{port}" in output
        assert "INBOX" in output

    def test_target_destination_counts_destination_account(self, single_mock_server, tmp_path, capsys):
        _, port = single_mock_server({"INBOX": [b"Subject: Destination\r\n\r\nBody"]})
        env = {"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("DEST", port)}

        with temp_env(env):
            count_imap_emails.main(["--target", "destination"])

        output = capsys.readouterr().out
        assert f"Host            : imap://localhost:{port}" in output
        assert "INBOX" in output

    def test_explicit_path_resolves_configured_target_ambiguity(self, tmp_path):
        env = {"BACKUP_LOCAL_PATH": "/unused", **_account_env("SRC", 10143), **_account_env("DEST", 10144)}

        with temp_env(env):
            args, local_mode = count_imap_emails.parse_arguments(["--path", str(tmp_path)])

        assert local_mode is True
        assert args.path == str(tmp_path)

    def test_explicit_imap_account_resolves_configured_target_ambiguity(self, tmp_path):
        env = {"BACKUP_LOCAL_PATH": str(tmp_path), **_account_env("SRC", 10143), **_account_env("DEST", 10144)}

        with temp_env(env):
            args, local_mode = count_imap_emails.parse_arguments(
                ["--host", "imap.example.com", "--user", "explicit", "--pass", "explicit-password"]
            )

        assert local_mode is False
        assert args.host == "imap.example.com"
        assert args.user == "explicit"

    def test_source_target_accepts_partial_account_overrides(self):
        with temp_env(_account_env("SRC", 10143)):
            args, local_mode = count_imap_emails.parse_arguments(
                ["--target", "source", "--user", "another-user", "--pass", "another-password"]
            )

        assert local_mode is False
        assert args.host == "imap://localhost:10143"
        assert args.user == "another-user"
        assert args.password == "another-password"

    def test_target_cannot_be_combined_with_explicit_path(self, tmp_path, capsys):
        with temp_env({}), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.parse_arguments(["--target", "local", "--path", str(tmp_path)])

        assert exc_info.value.code == 2
        assert "--path cannot be combined with --target" in capsys.readouterr().err

    def test_local_target_cannot_be_combined_with_imap_arguments(self, tmp_path, capsys):
        with temp_env({"BACKUP_LOCAL_PATH": str(tmp_path)}), pytest.raises(SystemExit) as exc_info:
            count_imap_emails.parse_arguments(["--target", "local", "--pass", "password"])

        assert exc_info.value.code == 2
        assert "--target local cannot be combined" in capsys.readouterr().err

    def test_path_only_legacy_configuration_selects_local(self, tmp_path):
        with temp_env({"BACKUP_LOCAL_PATH": str(tmp_path)}):
            args, local_mode = count_imap_emails.parse_arguments([])

        assert local_mode is True
        assert args.path == str(tmp_path)

    def test_source_only_legacy_configuration_selects_source(self):
        with temp_env(_account_env("SRC", 10143)):
            args, local_mode = count_imap_emails.parse_arguments([])

        assert local_mode is False
        assert args.host == "imap://localhost:10143"
        assert args.password == "pass"

    def test_count_specific_imap_aliases_remain_supported(self):
        with temp_env(_mock_imap_env(10143)):
            args, local_mode = count_imap_emails.parse_arguments([])

        assert local_mode is False
        assert args.host == "imap://localhost:10143"
        assert args.user == "user"

    def test_source_target_preserves_count_specific_alias_precedence(self, tmp_path):
        env = {
            "BACKUP_LOCAL_PATH": str(tmp_path),
            **_account_env("SRC", 10143),
            **_mock_imap_env(10144),
        }

        with temp_env(env):
            args, local_mode = count_imap_emails.parse_arguments(["--target", "source"])

        assert local_mode is False
        assert args.host == "imap://localhost:10144"

    def test_missing_credentials(self, capsys):
        """Test that missing auth is rejected by argparse (neither password nor OAuth2 client-id)."""
        with temp_env({}), temp_argv(["count_imap_emails.py", "--host", "localhost", "--user", "user"]):
            with pytest.raises(SystemExit) as exc_info:
                count_imap_emails.main()

        assert exc_info.value.code == 2


class TestSrcImapFallback:
    """Tests for SRC_IMAP_* environment variable fallback."""

    def test_src_imap_vars_fallback(self, capsys):
        """Test that SRC_IMAP_* vars work as fallback."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "user",
            "SRC_IMAP_PASSWORD": "pass",
        }
        with temp_env(env):
            # The fallback logic: IMAP_* or SRC_IMAP_*
            default_host = os.getenv("IMAP_HOST") or os.getenv("SRC_IMAP_HOST")
            default_user = os.getenv("IMAP_USERNAME") or os.getenv("SRC_IMAP_USERNAME")
            default_pass = os.getenv("IMAP_PASSWORD") or os.getenv("SRC_IMAP_PASSWORD")

            assert default_host == "localhost"
            assert default_user == "user"
            assert default_pass == "pass"
