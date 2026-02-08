"""End-to-end tests for migrate_imap_emails.py cache behavior."""

import imaplib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_common
import migrate_imap_emails
import restore_cache
from conftest import make_mock_connection


def _run_migrate(monkeypatch, cache_dir, src_port, dest_port, full_migrate=False, extra_env=None):
    env = {
        "SRC_IMAP_HOST": "localhost",
        "SRC_IMAP_USERNAME": "src",
        "SRC_IMAP_PASSWORD": "p",
        "DEST_IMAP_HOST": "localhost",
        "DEST_IMAP_USERNAME": "dest",
        "DEST_IMAP_PASSWORD": "p",
        "MAX_WORKERS": "1",
    }
    if extra_env:
        env.update(extra_env)
    monkeypatch.setattr(os, "environ", env)

    argv = [
        "migrate_imap_emails.py",
        "--src-host",
        "localhost",
        "--src-user",
        "src",
        "--src-pass",
        "p",
        "--dest-host",
        "localhost",
        "--dest-user",
        "dest",
        "--dest-pass",
        "p",
        "--migrate-cache",
        str(cache_dir),
        "--workers",
        "1",
    ]
    if full_migrate:
        argv.append("--full-migrate")

    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(
        migrate_imap_emails.imap_common,
        "get_imap_connection",
        make_mock_connection(src_port, dest_port, "src", "dest"),
    )

    migrate_imap_emails.main()


@pytest.mark.usefixtures("mock_server_factory")
class TestMigrationCache:
    """End-to-end tests for incremental migration using local cache."""

    def test_migrate_skips_cached_items(self, mock_server_factory, monkeypatch, tmp_path):
        msg_id = "<cached@test>"
        msg = f"Subject: Cached\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": []}

        _src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # First run populates cache and copies message.
        _run_migrate(monkeypatch, cache_dir, p1, p2)
        assert len(dest_server.folders["INBOX"]) == 1

        # Second run against a fresh destination should skip based on cache.
        _src_server2, dest_server2, p3, p4 = mock_server_factory(src_data, {"INBOX": []})
        _run_migrate(monkeypatch, cache_dir, p3, p4)
        assert len(dest_server2.folders["INBOX"]) == 0

    def test_migrate_writes_to_cache(self, mock_server_factory, monkeypatch, tmp_path):
        msg_id = "<new@test>"
        msg = f"Subject: New\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": []}

        _src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        _run_migrate(monkeypatch, cache_dir, p1, p2)

        assert len(dest_server.folders["INBOX"]) == 1

        cache_path = restore_cache.get_dest_index_cache_path(str(cache_dir), "localhost", "dest")
        assert os.path.exists(cache_path)

        with open(cache_path, encoding="utf-8") as f:
            cache_data = json.load(f)

        msg_ids = set(cache_data.get("folders", {}).get("INBOX", {}).get("message_ids", []))
        assert msg_id in msg_ids

    def test_full_migrate_ignores_cache(self, mock_server_factory, monkeypatch, tmp_path):
        msg_id = "<cached@test>"
        msg = f"Subject: Cached\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Populate cache with an initial run.
        _src_server, _dest_server, p1, p2 = mock_server_factory(src_data, {"INBOX": []})
        _run_migrate(monkeypatch, cache_dir, p1, p2)

        # Fresh destination should still copy when --full-migrate is set.
        _src_server2, dest_server2, p3, p4 = mock_server_factory(src_data, {"INBOX": []})
        _run_migrate(monkeypatch, cache_dir, p3, p4, full_migrate=True)

        assert len(dest_server2.folders["INBOX"]) == 1

    def test_cached_skip_with_preserve_flags(self, mock_server_factory, monkeypatch, tmp_path):
        msg_id = "<cached-preserve@test>"
        msg = f"Subject: Cached\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Populate cache with initial run.
        _src_server, _dest_server, p1, p2 = mock_server_factory(src_data, {"INBOX": []})
        _run_migrate(monkeypatch, cache_dir, p1, p2)

        # Preserve flags disables pre-filtering, so cache skip happens per message.
        _src_server2, dest_server2, p3, p4 = mock_server_factory(src_data, {"INBOX": []})
        _run_migrate(monkeypatch, cache_dir, p3, p4, extra_env={"PRESERVE_FLAGS": "true"})

        assert len(dest_server2.folders["INBOX"]) == 0

    def test_load_progress_cache_warns_on_unusable_root(self, tmp_path):
        cache_file = tmp_path / "cachefile"
        cache_file.write_text("not a directory")

        messages = []
        _cache_path, _cache_data, _cache_lock = imap_common.load_progress_cache(
            str(cache_file),
            "host",
            "user",
            log_fn=messages.append,
        )

        assert any("unable to create cache directory" in msg for msg in messages)

    def test_migrate_folder_logs_cache_load_failure(self, mock_server_factory, monkeypatch, tmp_path, capsys):
        msg_id = "<cache-fail@test>"
        msg = f"Subject: Cached\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": []}

        _src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))
        monkeypatch.setattr(
            imap_common, "load_progress_cache", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        src = imaplib.IMAP4("localhost", p1)
        dest = imaplib.IMAP4("localhost", p2)
        src.login("src", "p")
        dest.login("dest", "p")

        monkeypatch.setattr(migrate_imap_emails, "get_thread_connections", lambda _src_conf, _dest_conf: (src, dest))

        migrate_imap_emails.MAX_WORKERS = 1
        migrate_imap_emails.BATCH_SIZE = 1

        migrate_imap_emails.migrate_folder(
            src,
            dest,
            "INBOX",
            False,
            {"host": "localhost", "user": "src", "password": "p"},
            {"host": "localhost", "user": "dest", "password": "p"},
            progress_cache_path=str(tmp_path / "cache"),
            progress_cache_file=None,
            progress_cache_data=None,
            progress_cache_lock=None,
        )

        captured = capsys.readouterr()
        assert "Warning: Failed to load cache" in captured.out
        assert len(dest_server.folders["INBOX"]) == 1

        src.logout()
        dest.logout()

    def test_migrate_folder_logs_cache_read_failure(self, mock_server_factory, monkeypatch, tmp_path, capsys):
        msg_id = "<cache-read-fail@test>"
        msg = f"Subject: Cached\r\nMessage-ID: {msg_id}\r\n\r\nBody".encode()
        src_data = {"INBOX": [msg]}
        dest_data = {"INBOX": []}

        _src_server, dest_server, p1, p2 = mock_server_factory(src_data, dest_data)

        monkeypatch.setattr("imap_common.get_imap_connection", make_mock_connection(p1, p2))
        monkeypatch.setattr(
            restore_cache,
            "get_cached_message_ids",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("read fail")),
        )

        src = imaplib.IMAP4("localhost", p1)
        dest = imaplib.IMAP4("localhost", p2)
        src.login("src", "p")
        dest.login("dest", "p")

        monkeypatch.setattr(migrate_imap_emails, "get_thread_connections", lambda _src_conf, _dest_conf: (src, dest))

        migrate_imap_emails.MAX_WORKERS = 1
        migrate_imap_emails.BATCH_SIZE = 1

        migrate_imap_emails.migrate_folder(
            src,
            dest,
            "INBOX",
            False,
            {"host": "localhost", "user": "src", "password": "p"},
            {"host": "localhost", "user": "dest", "password": "p"},
            progress_cache_path=str(tmp_path / "cache"),
            progress_cache_file=None,
            progress_cache_data=None,
            progress_cache_lock=None,
        )

        captured = capsys.readouterr()
        assert "Warning: Failed to read cache for folder 'INBOX'" in captured.out
        assert len(dest_server.folders["INBOX"]) == 1

        src.logout()
        dest.logout()
