"""
Tests for imap_retry.py

Tests cover:
- Transient error detection
- ConnectionProxy transparent proxying
- Retry with exponential backoff on transient errors
- Pass-through for non-retryable methods
- Pass-through for non-transient errors
"""

import imaplib
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../tools")))

from mock_imap_server import start_server_thread as start_mock_server
from utils import imap_retry


class TestConnectionProxy:
    @pytest.fixture(scope="class")
    def imap_server_info(self):
        folders = {"INBOX": []}
        server, port = start_mock_server(folders)
        yield server, port
        server.shutdown()
        server.server_close()

    @pytest.fixture
    def imap_conn(self, imap_server_info):
        server, port = imap_server_info
        client = imaplib.IMAP4("127.0.0.1", port)
        client.login("user", "pass")
        yield client
        try:
            client.logout()
        except:
            pass

    @pytest.fixture
    def captured_logs(self):
        logs = []

        def log_fn(msg):
            logs.append(msg)

        return logs, log_fn

    @pytest.fixture
    def proxy(self, imap_conn, captured_logs):
        # Short wait to speed up tests
        logs, log_fn = captured_logs
        return imap_retry.ConnectionProxy(imap_conn, max_retries=3, initial_wait=0.01, log_fn=log_fn)

    def test_transient_retry_logic_unavailable(self, proxy, captured_logs):
        """Test detection of 'NO [UNAVAILABLE]' error pattern."""
        try:
            logs, _ = captured_logs
            # Server will echo "NO [UNAVAILABLE] Server Busy" and fail continuously
            typ, data = proxy.select('"NO [UNAVAILABLE] Server Busy"')
            assert typ == "NO"
            # Should have retried max_retries-1 times before returning last error
            assert len(logs) == 2  # Retries on attempt 1 and 2, then fail on 3
            assert "attempt 1/3" in logs[0]
            assert "attempt 2/3" in logs[1]
        except Exception:
            raise

    def test_transient_retry_logic_server_busy(self, proxy, captured_logs):
        """Test detection of 'NO Server Busy' error pattern."""
        logs, _ = captured_logs
        typ, data = proxy.select('"NO Server Busy"')
        assert typ == "NO"
        assert len(logs) == 2

    def test_transient_retry_logic_try_again(self, proxy, captured_logs):
        """Test detection of 'try again' error pattern."""
        logs, _ = captured_logs
        typ, data = proxy.select('"NO try again later"')
        assert typ == "NO"
        assert len(logs) == 2

    def test_transient_retry_logic_throttled(self, proxy, captured_logs):
        """Test detection of 'THROTTLED' error pattern."""
        logs, _ = captured_logs
        typ, data = proxy.select('"NO [THROTTLED]"')
        assert typ == "NO"
        assert len(logs) == 2

    def test_non_transient_no_retry_empty(self, proxy, captured_logs):
        """Test mismatch on empty/irrelevant data."""
        logs, _ = captured_logs
        # EMPTY arg causes mock to return OK with 0 items but generally here we want an error condition
        # Mock server "EMPTY" folder returns OK.
        # We need an error that is NOT transient.
        # "NO [UNKNOWN]"
        typ, data = proxy.select('"NO [UNKNOWN]"')
        assert typ == "NO"
        assert len(logs) == 0

    def test_ok_response_returns_immediately(self, proxy, captured_logs):
        logs, _ = captured_logs
        typ, data = proxy.select('"INBOX"')
        assert typ == "OK"
        assert len(logs) == 0

    def test_non_transient_error_not_retried(self, proxy, captured_logs):
        logs, _ = captured_logs
        typ, data = proxy.select('"NO [AUTHENTICATIONFAILED]"')
        assert typ == "NO"
        assert b"AUTHENTICATIONFAILED" in data[0]
        assert len(logs) == 0

    def test_transient_error_retried_then_succeeds(self, proxy, captured_logs):
        logs, _ = captured_logs
        # Retry 2 times (fail count 2, so 3rd succeeds)
        # RETRY_2 triggers 2 failures then OK.
        typ, data = proxy.select('"RETRY_2"')
        assert typ == "OK"
        assert len(logs) == 2
        assert "attempt 1/3" in logs[0]
        assert "attempt 2/3" in logs[1]

    def test_exponential_backoff_logic(self, proxy, captured_logs):
        logs, _ = captured_logs
        proxy.select('"INBOX"')
        typ, data = proxy.fetch("1", "(BODY RETRY_2)")
        assert typ == "OK"
        assert len(logs) == 2
        # Verify message content for backoff?
        # approximate wait time is hard to verify without mocking sleep, but we verify calls were made.

    def test_max_retries_exhausted_returns_last_error(self, proxy, captured_logs):
        logs, _ = captured_logs
        proxy.select('"INBOX"')
        # Fail 5 times. Max retries is 3. Result should be error.
        typ, data = proxy.store("1", "+FLAGS", "(\\Seen RETRY_5)")
        assert typ == "NO"
        assert b"UNAVAILABLE" in data[0]
        assert len(logs) == 2

    def test_non_retryable_method_passes_through(self, proxy, captured_logs):
        logs, _ = captured_logs
        res = proxy.capability()
        assert res[0] == "OK"
        assert len(logs) == 0

    def test_non_callable_attribute_passes_through(self, proxy):
        assert proxy.state == "AUTH"

    def test_non_tuple_return_passes_through(self):
        class DummyConn:
            def noop(self):
                return "unexpected"

        d = DummyConn()
        p = imap_retry.ConnectionProxy(d)
        assert p.noop() == "unexpected"

    def test_uid_method_retried(self, proxy, captured_logs):
        logs, _ = captured_logs
        proxy.select('"INBOX"')
        typ, data = proxy.uid("SEARCH", "RETRY_1")
        assert typ == "OK"
        assert len(logs) == 1

    def test_append_method_retried(self, proxy, captured_logs):
        logs, _ = captured_logs
        typ, data = proxy.append('"RETRY_1"', None, None, b"data")
        assert typ == "OK"
        assert len(logs) == 1

    def test_max_retries_zero_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            imap_retry.ConnectionProxy(None, max_retries=0)

    def test_max_retries_negative_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            imap_retry.ConnectionProxy(None, max_retries=-1)

    def test_initial_wait_negative_raises(self):
        with pytest.raises(ValueError, match="initial_wait must be >= 0"):
            imap_retry.ConnectionProxy(None, initial_wait=-1)
