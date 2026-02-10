"""
Shared pytest fixtures and utilities for IMAP migration tools tests.
"""

import imaplib
import os
import socket
import sys
import time
from contextlib import contextmanager

import pytest

# Ensure src/tools are in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../tools")))

from mock_imap_server import start_server_thread
from mock_oauth_server import start_server_thread as start_oauth_server_thread


def get_free_port():
    """Get a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def create_server_pair(src_data=None, dest_data=None):
    """Create a pair of mock IMAP servers with given initial data."""
    p1 = get_free_port()
    p2 = get_free_port()
    while p2 == p1:
        p2 = get_free_port()

    src_s, p1_actual = start_server_thread(p1, src_data)
    dest_s, p2_actual = start_server_thread(p2, dest_data)
    time.sleep(0.3)

    # We don't have direct access to thread object anymore as it is managed internally by TCPServer/ThreadingMixin or start_server_thread wrapper?
    # Actually start_server_thread in tools/mock_imap_server.py now returns (server, port).
    # The server object is a ThreadingMixIn so it handles per-request threads, but the main serve_forever loop is in a thread we created.
    # But wait, my modified start_server_thread does: t.start(), return server, actual_port.
    # It dropped returning 't'. I need to fix that or update consumers to not need 't'.
    # Shutdown() stops serve_forever loop. join() is nice but maybe not strictly required if we trust shutdown.
    # However, to avoid ResourceWarnings, we might want 't'.

    return (None, src_s, p1_actual), (None, dest_s, p2_actual)


def shutdown_server_pair(src_tuple, dest_tuple):
    """Shutdown a pair of mock servers."""
    src_t, src_s, _ = src_tuple
    dest_t, dest_s, _ = dest_tuple
    src_s.shutdown()
    src_s.server_close()  # Explicitly close socket
    dest_s.shutdown()
    dest_s.server_close()
    if src_t:
        src_t.join(timeout=2)
    if dest_t:
        dest_t.join(timeout=2)


@pytest.fixture
def mock_server_factory():
    """
    Factory fixture that creates mock IMAP server pairs.
    Automatically cleans up all servers after the test.
    """
    servers = []

    def _create(src_data=None, dest_data=None):
        src_tuple, dest_tuple = create_server_pair(src_data, dest_data)
        servers.append((src_tuple, dest_tuple))
        src_server = src_tuple[1]
        dest_server = dest_tuple[1]
        src_port = src_tuple[2]
        dest_port = dest_tuple[2]
        return src_server, dest_server, src_port, dest_port

    yield _create

    for src_tuple, dest_tuple in servers:
        shutdown_server_pair(src_tuple, dest_tuple)


@pytest.fixture
def single_mock_server():
    """
    Creates a single mock IMAP server for testing scripts that only need one server.
    """
    servers = []

    def _create(initial_data=None):
        port = get_free_port()
        server, actual_port = start_server_thread(port, initial_data)
        time.sleep(0.3)
        servers.append(server)
        return server, actual_port

    yield _create

    for server in servers:
        server.shutdown()
        server.server_close()


@contextmanager
def temp_env(env):
    original = os.environ.copy()
    os.environ.clear()
    os.environ.update(env)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


@contextmanager
def temp_argv(args):
    original = sys.argv[:]
    sys.argv = list(args)
    try:
        yield
    finally:
        sys.argv = original


@pytest.fixture(autouse=True)
def clean_sys_argv():
    """Ensure sys.argv is clean for all tests."""
    original = sys.argv[:]
    sys.argv = ["test_script.py"]
    yield
    sys.argv = original


def make_mock_connection(src_port, dest_port, src_user="src_user", dest_user="dest_user"):
    """
    Creates a mock connection function that routes to the correct server based on username.
    """

    def mock_conn(host, user, pwd, oauth2_token=None):
        if user == src_user:
            port = src_port
        elif user == dest_user:
            port = dest_port
        else:
            raise ValueError(f"Unknown user: {user}")
        c = imaplib.IMAP4("localhost", port)
        c.login(user, pwd or "")
        return c

    return mock_conn


def make_single_mock_connection(port):
    """
    Creates a mock connection function for a single server.
    """

    def mock_conn(host, user, pwd, oauth2_token=None):
        c = imaplib.IMAP4("localhost", port)
        c.login(user, pwd or "")
        return c

    return mock_conn


@pytest.fixture
def mock_oauth_server():
    """Starts a mock OAuth2 server for token and discovery endpoints."""
    thread, server = start_oauth_server_thread(0)
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    yield base_url

    server.shutdown()
    thread.join(timeout=2)


__all__ = [
    "mock_server_factory",
    "single_mock_server",
    "make_mock_connection",
    "make_single_mock_connection",
    "mock_oauth_server",
    "temp_env",
    "temp_argv",
]
