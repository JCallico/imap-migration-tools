"""
Tests for compare_imap_folders.py

Tests cover:
- Basic folder comparison between accounts
- Matching counts
- Mismatched counts
- Missing folders on destination
- Empty folder handling
- Configuration validation
"""

import imaplib
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_compare as compare_imap_folders
from conftest import temp_argv, temp_env


def _mock_compare_env(src_port, dest_port):
    return {
        "SRC_IMAP_HOST": f"imap://localhost:{src_port}",
        "SRC_IMAP_USERNAME": "src_user",
        "SRC_IMAP_PASSWORD": "p",
        "DEST_IMAP_HOST": f"imap://localhost:{dest_port}",
        "DEST_IMAP_USERNAME": "dest_user",
        "DEST_IMAP_PASSWORD": "p",
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


class TestFolderComparison:
    """Tests for folder comparison functionality."""

    def test_matching_counts(self, mock_server_factory, capsys):
        """Test comparison when source and destination have matching counts."""
        data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(data, data.copy())

        env = _mock_compare_env(p1, p2)
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out

    def test_mismatched_counts(self, mock_server_factory, capsys):
        """Test comparison when counts differ."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB", b"Subject: 3\r\n\r\nB"],
        }
        dest_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_compare_env(p1, p2)
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        # Source has 3, dest has 1
        assert "3" in captured.out
        assert "1" in captured.out

    def test_compare_uses_dotenv_configuration(self, mock_server_factory, capsys, dotenv_file):
        """End-to-end: .env credentials drive a successful account comparison."""
        data = {"INBOX": [b"Subject: Dotenv\r\n\r\nBody"]}
        _, _, src_port, dest_port = mock_server_factory(data, data.copy())

        dotenv_file(_mock_compare_env(src_port, dest_port))
        with temp_env({}), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        assert "INBOX" in capsys.readouterr().out

    def test_explicit_passwords_override_dotenv_oauth(self, mock_server_factory, capsys, dotenv_file):
        """Explicit passwords select basic authentication for both comparison accounts."""
        data = {"INBOX": [b"Subject: Password\r\n\r\nBody"]}
        _, _, src_port, dest_port = mock_server_factory(data, data.copy())
        dotenv_file(
            {
                **_mock_compare_env(src_port, dest_port),
                "SRC_OAUTH2_CLIENT_ID": "inherited-source-oauth",
                "DEST_OAUTH2_CLIENT_ID": "inherited-destination-oauth",
            }
        )

        with temp_env({}), temp_argv(["compare_imap_folders.py", "--src-pass", "p", "--dest-pass", "p"]):
            compare_imap_folders.main()

        assert "INBOX" in capsys.readouterr().out

    def test_explicit_imap_arguments_override_dotenv_local_paths(
        self, mock_server_factory, tmp_path, capsys, dotenv_file
    ):
        """Explicit IMAP configuration selects IMAP mode for both comparison sides."""
        data = {"INBOX": [b"Subject: IMAP wins\r\n\r\nBody"]}
        _, _, src_port, dest_port = mock_server_factory(data, data.copy())
        src_path = tmp_path / "local-source"
        dest_path = tmp_path / "local-destination"
        src_path.mkdir()
        dest_path.mkdir()
        dotenv_file({"SRC_LOCAL_PATH": str(src_path), "DEST_LOCAL_PATH": str(dest_path)})

        with (
            temp_env({}),
            temp_argv(
                [
                    "compare_imap_folders.py",
                    f"--src-host=imap://localhost:{src_port}",
                    "--src-user",
                    "src_user",
                    "--src-pass",
                    "p",
                    "--dest-host",
                    f"imap://localhost:{dest_port}",
                    "--dest-user",
                    "dest_user",
                    "--dest-pass",
                    "p",
                ]
            ),
        ):
            compare_imap_folders.main()

        captured = capsys.readouterr().out
        assert "Source Host" in captured
        assert "Destination Host" in captured
        assert "Source (Local)" not in captured
        assert "Destination (Local)" not in captured
        assert "INBOX" in captured

    def test_explicit_source_path_and_imap_arguments_are_rejected(self, tmp_path, capsys):
        """Conflicting explicit source modes produce an actionable parser error."""
        env = {
            "DEST_IMAP_HOST": "imap.example.com",
            "DEST_IMAP_USERNAME": "dest",
            "DEST_IMAP_PASSWORD": "pass",
        }
        with (
            temp_env(env),
            temp_argv(
                [
                    "compare_imap_folders.py",
                    "--src-path",
                    str(tmp_path),
                    "--src-host",
                    "imap.example.com",
                    "--src-user",
                    "src",
                    "--src-pass",
                    "pass",
                ]
            ),
        ):
            with pytest.raises(SystemExit) as exc_info:
                compare_imap_folders.main()

        assert exc_info.value.code == 2
        assert "cannot be combined" in capsys.readouterr().err

    def test_folder_missing_on_destination(self, mock_server_factory, capsys):
        """Test when a folder exists on source but not destination."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
            "Archive": [b"Subject: 2\r\n\r\nB"],
        }
        dest_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_compare_env(p1, p2)
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        # Archive should show N/A for destination
        assert "Archive" in captured.out
        assert "N/A" in captured.out

    def test_destination_namespace_prefix_is_used(self, mock_server_factory, capsys):
        """Comparison selects the destination's mapped mailbox name."""
        src_data = {"INBOX": [], "Sent": [b"Subject: Sent\r\n\r\nBody"]}
        dest_data = {"INBOX": [], "INBOX.Sent": [b"Subject: Sent\r\n\r\nBody"]}
        _, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)
        dest_server.namespace_prefix = "INBOX."
        dest_server.namespace_separator = "."

        env = _mock_compare_env(p1, p2)
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        sent_row = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("Sent"))
        assert "N/A" not in sent_row
        assert sent_row.count("1") == 2


class TestEmptyFolders:
    """Tests for empty folder handling."""

    def test_empty_folders(self, mock_server_factory, capsys):
        """Test comparison with empty folders."""
        src_data = {"INBOX": [], "Empty": []}
        dest_data = {"INBOX": [], "Empty": []}

        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_compare_env(p1, p2)
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "0" in captured.out


class TestGetEmailCount:
    """Tests for get_email_count function."""

    def test_successful_count(self, single_mock_server):
        """Test successful email count."""
        data = {"INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"]}
        _, port = single_mock_server(data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        result = compare_imap_folders.get_email_count(conn, "INBOX")
        assert result == 2

        conn.logout()

    def test_nonexistent_folder(self, single_mock_server):
        """Test count for non-existent folder returns None."""
        data = {"INBOX": []}
        _, port = single_mock_server(data)

        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        result = compare_imap_folders.get_email_count(conn, "NonExistent")
        assert result is None

        conn.logout()


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_source_credentials(self, capsys):
        """Test that missing source credentials cause exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest",
            "DEST_IMAP_PASSWORD": "p",
        }
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            with pytest.raises(SystemExit) as exc_info:
                compare_imap_folders.main()

        assert exc_info.value.code == 2

    def test_missing_dest_credentials(self, capsys):
        """Test that missing destination credentials cause exit."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src",
            "SRC_IMAP_PASSWORD": "p",
        }
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            with pytest.raises(SystemExit) as exc_info:
                compare_imap_folders.main()

        assert exc_info.value.code == 2


class TestTotals:
    """Tests for total calculation."""

    def test_total_calculation(self, mock_server_factory, capsys):
        """Test that totals are calculated correctly."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB", b"Subject: 4\r\n\r\nB", b"Subject: 5\r\n\r\nB"],
        }
        dest_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = _mock_compare_env(p1, p2)
        with temp_env(env), temp_argv(["compare_imap_folders.py"]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        # Total source: 5, Total dest: 2, Diff: 3
        assert "TOTAL" in captured.out
        assert "5" in captured.out
        assert "2" in captured.out


class TestLocalFolderComparison:
    """Tests for comparing IMAP folders to local backup folders."""

    def test_local_source_to_imap_dest(self, single_mock_server, tmp_path, capsys):
        """Local source folder list drives the comparison; destination is IMAP."""
        # Local source: INBOX has 2 emails, Archive has 1
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")
        (inbox_path / "2_b.eml").write_bytes(b"Subject: B\r\n\r\nBody")

        archive_path = tmp_path / "Archive"
        archive_path.mkdir()
        (archive_path / "1_c.eml").write_bytes(b"Subject: C\r\n\r\nBody")

        # Destination IMAP: INBOX has 1, Archive is missing
        dest_data = {"INBOX": [b"Subject: 1\r\n\r\nB"]}
        _, port = single_mock_server(dest_data)

        env = {
            "DEST_IMAP_HOST": f"imap://localhost:{port}",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        with temp_env(env), temp_argv(["compare_imap_folders.py", "--src-path", str(tmp_path)]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Archive" in captured.out
        # Destination should show N/A for missing Archive
        assert "N/A" in captured.out

    def test_imap_source_to_local_dest(self, single_mock_server, tmp_path, capsys):
        """IMAP source folder list drives the comparison; destination is local."""
        # Source IMAP: INBOX has 2, Sent has 1
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
        }
        _, port = single_mock_server(src_data)

        # Local dest: INBOX has 1, Sent missing
        inbox_path = tmp_path / "INBOX"
        inbox_path.mkdir()
        (inbox_path / "1_a.eml").write_bytes(b"Subject: A\r\n\r\nBody")
        env = {
            "SRC_IMAP_HOST": f"imap://localhost:{port}",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
        }
        with temp_env(env), temp_argv(["compare_imap_folders.py", "--dest-path", str(tmp_path)]):
            compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out
        assert "N/A" in captured.out
