"""
Tests for imap_retry.py

Tests cover:
- Transient error detection
- ConnectionProxy transparent proxying
- Retry with exponential backoff on transient errors
- Pass-through for non-retryable methods
- Pass-through for non-transient errors
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import imap_retry


class TestIsTransientError:
    def test_unavailable(self):
        assert imap_retry._is_transient_error([b"NO [UNAVAILABLE] Server Busy"]) is True

    def test_server_busy(self):
        assert imap_retry._is_transient_error([b"NO Server Busy"]) is True

    def test_try_again(self):
        assert imap_retry._is_transient_error([b"NO try again later"]) is True

    def test_throttled(self):
        assert imap_retry._is_transient_error([b"NO [THROTTLED]"]) is True

    def test_not_transient(self):
        assert imap_retry._is_transient_error([b"NO [AUTHENTICATIONFAILED]"]) is False

    def test_empty_data(self):
        assert imap_retry._is_transient_error([]) is False

    def test_non_bytes_ignored(self):
        assert imap_retry._is_transient_error(["UNAVAILABLE"]) is False

    def test_multiple_items_matches_second(self):
        assert imap_retry._is_transient_error([b"OK", b"NO [UNAVAILABLE]"]) is True


class TestConnectionProxy:
    def test_ok_response_returns_immediately(self):
        conn = MagicMock()
        conn.select.return_value = ("OK", [b"1234"])
        wrapper = imap_retry.ConnectionProxy(conn)

        result = wrapper.select('"INBOX"')

        assert result == ("OK", [b"1234"])
        assert conn.select.call_count == 1

    def test_non_transient_error_not_retried(self):
        conn = MagicMock()
        conn.select.return_value = ("NO", [b"AUTHENTICATIONFAILED"])
        wrapper = imap_retry.ConnectionProxy(conn)

        result = wrapper.select('"INBOX"')

        assert result == ("NO", [b"AUTHENTICATIONFAILED"])
        assert conn.select.call_count == 1

    @patch("imap_retry.time.sleep")
    def test_transient_error_retried_then_succeeds(self, mock_sleep):
        conn = MagicMock()
        conn.select.side_effect = [
            ("NO", [b"[UNAVAILABLE] Server Busy"]),
            ("OK", [b"1234"]),
        ]
        wrapper = imap_retry.ConnectionProxy(conn, max_retries=3, initial_wait=5)

        result = wrapper.select('"INBOX"')

        assert result == ("OK", [b"1234"])
        assert conn.select.call_count == 2
        mock_sleep.assert_called_once_with(5)

    @patch("imap_retry.time.sleep")
    def test_exponential_backoff(self, mock_sleep):
        conn = MagicMock()
        conn.fetch.side_effect = [
            ("NO", [b"[UNAVAILABLE] Server Busy"]),
            ("NO", [b"[UNAVAILABLE] Server Busy"]),
            ("OK", [b"data"]),
        ]
        wrapper = imap_retry.ConnectionProxy(conn, max_retries=3, initial_wait=5)

        result = wrapper.fetch("1", "(RFC822)")

        assert result == ("OK", [b"data"])
        assert conn.fetch.call_count == 3
        assert mock_sleep.call_args_list[0][0] == (5,)
        assert mock_sleep.call_args_list[1][0] == (10,)

    @patch("imap_retry.time.sleep")
    def test_max_retries_exhausted_returns_last_error(self, mock_sleep):
        conn = MagicMock()
        conn.store.return_value = ("NO", [b"[UNAVAILABLE] Server Busy"])
        wrapper = imap_retry.ConnectionProxy(conn, max_retries=3, initial_wait=5)

        result = wrapper.store("1", "+FLAGS", "(\\Seen)")

        assert result == ("NO", [b"[UNAVAILABLE] Server Busy"])
        assert conn.store.call_count == 3
        assert mock_sleep.call_count == 2  # sleeps between attempts, not after last

    def test_non_retryable_method_passes_through(self):
        conn = MagicMock()
        conn.login.return_value = ("NO", [b"[UNAVAILABLE] Server Busy"])
        wrapper = imap_retry.ConnectionProxy(conn)

        result = wrapper.login("user", "pass")

        assert result == ("NO", [b"[UNAVAILABLE] Server Busy"])
        assert conn.login.call_count == 1

    def test_non_callable_attribute_passes_through(self):
        conn = MagicMock()
        conn.state = "AUTH"
        wrapper = imap_retry.ConnectionProxy(conn)

        assert wrapper.state == "AUTH"

    def test_non_tuple_return_passes_through(self):
        conn = MagicMock()
        conn.noop.return_value = "unexpected"
        wrapper = imap_retry.ConnectionProxy(conn)

        result = wrapper.noop()

        assert result == "unexpected"
        assert conn.noop.call_count == 1

    def test_uid_method_retried(self):
        conn = MagicMock()
        conn.uid.side_effect = [
            ("NO", [b"[THROTTLED]"]),
            ("OK", [b"1 2 3"]),
        ]
        wrapper = imap_retry.ConnectionProxy(conn, max_retries=3, initial_wait=0)

        result = wrapper.uid("search", None, "ALL")

        assert result == ("OK", [b"1 2 3"])
        assert conn.uid.call_count == 2

    def test_append_method_retried(self):
        conn = MagicMock()
        conn.append.side_effect = [
            ("NO", [b"try again later"]),
            ("OK", [b"APPENDUID"]),
        ]
        wrapper = imap_retry.ConnectionProxy(conn, max_retries=3, initial_wait=0)

        result = wrapper.append('"INBOX"', None, None, b"message data")

        assert result == ("OK", [b"APPENDUID"])
        assert conn.append.call_count == 2

    def test_max_retries_zero_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            imap_retry.ConnectionProxy(MagicMock(), max_retries=0)

    def test_max_retries_negative_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            imap_retry.ConnectionProxy(MagicMock(), max_retries=-1)

    def test_initial_wait_negative_raises(self):
        with pytest.raises(ValueError, match="initial_wait must be >= 0"):
            imap_retry.ConnectionProxy(MagicMock(), initial_wait=-1)
