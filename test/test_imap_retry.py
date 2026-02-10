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
import os
import threading
import imaplib
import time
from typing import Tuple

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../tools")))

import imap_retry
from mock_imap_server import start_server_thread as start_mock_server


class TestIsTransientError:
    @pytest.fixture(scope="class")
    def imap_server_info(self):
        """Starts a background IMAP server for the test class."""
        folders = {"INBOX": []}
        server, port = start_mock_server(folders)
        yield server, port
        server.shutdown()
        server.server_close()

    @pytest.fixture
    def imap_conn(self, imap_server_info):
        """Returns a connected IMAP4 client instance."""
        server, port = imap_server_info
        client = imaplib.IMAP4("127.0.0.1", port)
        client.login("user", "pass")
        yield client
        try:
            client.logout()
        except:
            pass

    def _get_error_data_from_conn(self, client, command_arg: str):
        try:
            typ, data = client.select(f'"{command_arg}"')
            if typ == "NO":
                return data
            return []
        except imaplib.IMAP4.error as e:
            msg = str(e)
            return [msg.encode("utf-8")]

    def test_unavailable(self, imap_conn):
        data = self._get_error_data_from_conn(imap_conn, "NO [UNAVAILABLE] Server Busy")
        assert imap_retry._is_transient_error(data) is True

    def test_server_busy(self, imap_conn):
        data = self._get_error_data_from_conn(imap_conn, "NO Server Busy")
        assert imap_retry._is_transient_error(data) is True

    def test_try_again(self, imap_conn):
        data = self._get_error_data_from_conn(imap_conn, "NO try again later")
        assert imap_retry._is_transient_error(data) is True

    def test_throttled(self, imap_conn):
        data = self._get_error_data_from_conn(imap_conn, "NO [THROTTLED]")
        assert imap_retry._is_transient_error(data) is True

    def test_not_transient(self, imap_conn):
        data = self._get_error_data_from_conn(imap_conn, "NO [AUTHENTICATIONFAILED]")
        assert imap_retry._is_transient_error(data) is False

    def test_empty_data(self, imap_conn):
        data = self._get_error_data_from_conn(imap_conn, "EMPTY")
        assert imap_retry._is_transient_error(data) is False

    def test_non_bytes_ignored(self, imap_conn):
        data = ["UNAVAILABLE", b"NO [AUTHENTICATIONFAILED]"] 
        assert imap_retry._is_transient_error(data) is False

    def test_multiple_items_matches_second(self, imap_conn):
        data = [b"OK", b"NO [UNAVAILABLE]"]
        assert imap_retry._is_transient_error(data) is True


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
    def proxy(self, imap_conn):
        # Short wait to speed up tests
        return imap_retry.ConnectionProxy(imap_conn, max_retries=3, initial_wait=0.01)

    def test_ok_response_returns_immediately(self, proxy):
        typ, data = proxy.select('"INBOX"')
        assert typ == "OK"

    def test_non_transient_error_not_retried(self, proxy):
        typ, data = proxy.select('"NO [AUTHENTICATIONFAILED]"')
        assert typ == "NO"
        assert b"AUTHENTICATIONFAILED" in data[0]

    def test_transient_error_retried_then_succeeds(self, proxy):
        # Retry 2 times (fail count 2, so 3rd succeeds)
        # We use a unique mailbox name to separate test cases or rely on new connection
        # RETRY_2 triggers 2 failures then OK.
        typ, data = proxy.select('"RETRY_2"')
        assert typ == "OK"

    def test_exponential_backoff_logic(self, proxy):
        # Must be selected to fetch
        proxy.select('"INBOX"')
        # RETRY_2 covers that it engages the retry loop twice then succeeds
        typ, data = proxy.fetch('1', '(BODY RETRY_2)')
        assert typ == "OK"

    def test_max_retries_exhausted_returns_last_error(self, proxy):
        # Must be selected to store
        proxy.select('"INBOX"')
        # Fail 5 times. Max retries is 3. Result should be error.
        typ, data = proxy.store('1', '+FLAGS', '(\\Seen RETRY_5)')
        assert typ == "NO"
        assert b"UNAVAILABLE" in data[0]

    def test_non_retryable_method_passes_through(self, proxy):
        # Instead of login (which fails in AUTH state), use capability
        # capability is NOT in _RETRYABLE_METHODS
        res = proxy.capability()
        assert res[0] == "OK"

    def test_non_callable_attribute_passes_through(self, proxy):
        # IMAP4 has 'state' attribute
        assert proxy.state == "AUTH"

    def test_non_tuple_return_passes_through(self):
        # Create a dummy class that returns non-tuple
        class DummyConn:
            def noop(self):
                return "unexpected"
        
        d = DummyConn()
        p = imap_retry.ConnectionProxy(d)
        assert p.noop() == "unexpected"

    def test_uid_method_retried(self, proxy):
        # Must be selected (most UID commands)
        proxy.select('"INBOX"')
        # UID SEARCH RETRY_1
        # Mock server needs to parse RETRY_1 from args.
        typ, data = proxy.uid('SEARCH', 'RETRY_1')
        assert typ == "OK"

    def test_append_method_retried(self, proxy):
        # APPEND "INBOX" {7}
        # retry logic based on mailbox name or args?
        # args passed to proxy.append: mailbox, flags, date_time, message
        # We pass mailbox="RETRY_1"
        typ, data = proxy.append('"RETRY_1"', None, None, b"data")
        assert typ == "OK"

    def test_max_retries_zero_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            imap_retry.ConnectionProxy(None, max_retries=0)

    def test_max_retries_negative_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            imap_retry.ConnectionProxy(None, max_retries=-1)

    def test_initial_wait_negative_raises(self):
        with pytest.raises(ValueError, match="initial_wait must be >= 0"):
            imap_retry.ConnectionProxy(None, initial_wait=-1)
