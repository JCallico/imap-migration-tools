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
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import compare_imap_folders
from conftest import make_mock_connection, make_single_mock_connection


class TestFolderComparison:
    """Tests for folder comparison functionality."""

    def test_matching_counts(self, mock_server_factory, monkeypatch, capsys):
        """Test comparison when source and destination have matching counts."""
        data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB"],
            "Sent": [b"Subject: 3\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(data, data.copy())

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out

    def test_mismatched_counts(self, mock_server_factory, monkeypatch, capsys):
        """Test comparison when counts differ."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB", b"Subject: 2\r\n\r\nB", b"Subject: 3\r\n\r\nB"],
        }
        dest_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        compare_imap_folders.main()

        captured = capsys.readouterr()
        # Source has 3, dest has 1
        assert "3" in captured.out
        assert "1" in captured.out

    def test_folder_missing_on_destination(self, mock_server_factory, monkeypatch, capsys):
        """Test when a folder exists on source but not destination."""
        src_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
            "Archive": [b"Subject: 2\r\n\r\nB"],
        }
        dest_data = {
            "INBOX": [b"Subject: 1\r\n\r\nB"],
        }
        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        compare_imap_folders.main()

        captured = capsys.readouterr()
        # Archive should show N/A for destination
        assert "Archive" in captured.out
        assert "N/A" in captured.out


class TestEmptyFolders:
    """Tests for empty folder handling."""

    def test_empty_folders(self, mock_server_factory, monkeypatch, capsys):
        """Test comparison with empty folders."""
        src_data = {"INBOX": [], "Empty": []}
        dest_data = {"INBOX": [], "Empty": []}

        _, _, p1, p2 = mock_server_factory(src_data, dest_data)

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

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


class TestCompareFoldersErrorHandling:
    """Tests for error handling in compare_imap_folders.py"""

    def test_connection_failure(self, monkeypatch):
        """Test graceful exit when connection fails."""
        mock_get = MagicMock(return_value=None)
        monkeypatch.setattr("imap_common.get_imap_connection", mock_get)

        # Test source fail
        env = {
            "SRC_IMAP_HOST": "h",
            "SRC_IMAP_USERNAME": "u",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "h",
            "DEST_IMAP_USERNAME": "u",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])

        compare_imap_folders.main()
        # Should call once and exit
        assert mock_get.call_count == 1

    def test_dest_connection_failure(self, monkeypatch):
        """Test graceful exit when destination connection fails."""
        # Source OK, Dest None
        mock_src = MagicMock()
        mock_src.list.return_value = ("OK", [rb'(\HasNoChildren) "/" "INBOX"'])

        def side_effect(h, u, p):
            if u == "src_u":
                return mock_src
            return None

        monkeypatch.setattr("imap_common.get_imap_connection", side_effect)

        env = {
            "SRC_IMAP_HOST": "h",
            "SRC_IMAP_USERNAME": "src_u",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "h",
            "DEST_IMAP_USERNAME": "dest_u",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])

        compare_imap_folders.main()

    def test_list_failure(self, monkeypatch, capsys):
        """Test handling of LIST command failure."""
        mock_src = MagicMock()
        mock_src.list.return_value = ("NO", [])
        mock_dest = MagicMock()

        monkeypatch.setattr(
            "imap_common.get_imap_connection", lambda h, u, p, oauth2_token=None: mock_src if u == "s" else mock_dest
        )

        env = {
            "SRC_IMAP_HOST": "h",
            "SRC_IMAP_USERNAME": "s",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "h",
            "DEST_IMAP_USERNAME": "d",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])

        compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "Failed to list source folders" in captured.out

    def test_select_failure(self, single_mock_server):
        """Test get_email_count handles select failure."""
        data = {"INBOX": []}
        _, port = single_mock_server(data)
        conn = imaplib.IMAP4("localhost", port)
        conn.login("user", "pass")

        # Mocking select failure on a real connection object is hard without
        # using a pure mock. So let's use a Mock object instead of real conn.
        mock_conn = MagicMock()
        mock_conn.select.return_value = ("NO", [b"Error"])

        result = compare_imap_folders.get_email_count(mock_conn, "INBOX")
        assert result is None

    def test_search_failure(self, single_mock_server):
        """Test get_email_count handles search failure."""
        mock_conn = MagicMock()
        mock_conn.select.return_value = ("OK", [b"Selected"])
        mock_conn.search.return_value = ("NO", [b"Error"])

        result = compare_imap_folders.get_email_count(mock_conn, "INBOX")
        assert result is None

    def test_imap_exception_in_count(self):
        """Test exception handling in get_email_count."""
        mock_conn = MagicMock()
        mock_conn.select.side_effect = imaplib.IMAP4.error("Crash")

        result = compare_imap_folders.get_email_count(mock_conn, "INBOX")
        assert result is None


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_missing_source_credentials(self, monkeypatch, capsys):
        """Test that missing source credentials cause exit."""
        env = {
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])

        with pytest.raises(SystemExit) as exc_info:
            compare_imap_folders.main()

        assert exc_info.value.code == 2

    def test_missing_dest_credentials(self, monkeypatch, capsys):
        """Test that missing destination credentials cause exit."""
        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src",
            "SRC_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])

        with pytest.raises(SystemExit) as exc_info:
            compare_imap_folders.main()

        assert exc_info.value.code == 2


class TestTotals:
    """Tests for total calculation."""

    def test_total_calculation(self, mock_server_factory, monkeypatch, capsys):
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

        env = {
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(sys, "argv", ["compare_imap_folders.py"])
        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))

        compare_imap_folders.main()

        captured = capsys.readouterr()
        # Total source: 5, Total dest: 2, Diff: 3
        assert "TOTAL" in captured.out
        assert "5" in captured.out
        assert "2" in captured.out


class TestLocalFolderComparison:
    """Tests for comparing IMAP folders to local backup folders."""

    def test_local_source_to_imap_dest(self, single_mock_server, monkeypatch, tmp_path, capsys):
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
            "DEST_IMAP_HOST": "localhost",
            "DEST_IMAP_USERNAME": "dest_user",
            "DEST_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["compare_imap_folders.py", "--src-path", str(tmp_path)],
        )
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Archive" in captured.out
        # Destination should show N/A for missing Archive
        assert "N/A" in captured.out

    def test_imap_source_to_local_dest(self, single_mock_server, monkeypatch, tmp_path, capsys):
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
            "SRC_IMAP_HOST": "localhost",
            "SRC_IMAP_USERNAME": "src_user",
            "SRC_IMAP_PASSWORD": "p",
        }
        monkeypatch.setattr(os, "environ", env)
        monkeypatch.setattr(
            sys,
            "argv",
            ["compare_imap_folders.py", "--dest-path", str(tmp_path)],
        )
        monkeypatch.setattr("imap_common.get_imap_connection", make_single_mock_connection(port))

        compare_imap_folders.main()

        captured = capsys.readouterr()
        assert "INBOX" in captured.out
        assert "Sent" in captured.out
        assert "N/A" in captured.out
