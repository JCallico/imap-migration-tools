"""Tests for IMAP COMPRESS=DEFLATE support."""

import zlib
from unittest.mock import MagicMock, patch

from utils import imap_compress


class TestCompressedSocket:
    """Tests for the _CompressedSocket wrapper."""

    def _make_compressed(self, plaintext: bytes) -> bytes:
        """Compress data using raw DEFLATE with Z_SYNC_FLUSH (server-side)."""
        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        return c.compress(plaintext) + c.flush(zlib.Z_SYNC_FLUSH)

    def test_sendall_compresses_data(self):
        sock = MagicMock()
        ws = imap_compress._CompressedSocket(sock)

        ws.sendall(b"AAAA0 SELECT INBOX\r\n")

        sock.sendall.assert_called_once()
        compressed = sock.sendall.call_args[0][0]
        # Verify round-trip: decompress the sent data
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        assert d.decompress(compressed) == b"AAAA0 SELECT INBOX\r\n"

    def test_send_compresses_and_returns_length(self):
        sock = MagicMock()
        ws = imap_compress._CompressedSocket(sock)

        result = ws.send(b"hello")
        assert result == 5
        sock.sendall.assert_called_once()

    def test_recv_decompresses_data(self):
        plaintext = b"* OK IMAP ready\r\n"
        compressed = self._make_compressed(plaintext)

        sock = MagicMock()
        sock.recv.return_value = compressed

        ws = imap_compress._CompressedSocket(sock)
        result = ws.recv(4096)

        assert result == plaintext

    def test_recv_buffers_excess(self):
        plaintext = b"A" * 100
        compressed = self._make_compressed(plaintext)

        sock = MagicMock()
        sock.recv.return_value = compressed

        ws = imap_compress._CompressedSocket(sock)
        # Request only 30 bytes — rest should be buffered
        chunk1 = ws.recv(30)
        assert chunk1 == b"A" * 30
        assert len(ws._recv_buf) == 70

        # Next recv should return from buffer without hitting socket
        chunk2 = ws.recv(70)
        assert chunk2 == b"A" * 70
        sock.recv.assert_called_once()  # Only one real socket read

    def test_recv_empty_returns_empty(self):
        sock = MagicMock()
        sock.recv.return_value = b""

        ws = imap_compress._CompressedSocket(sock)
        assert ws.recv(4096) == b""

    def test_initial_compressed_data_decompressed(self):
        plaintext = b"* 5 EXISTS\r\n"
        compressed = self._make_compressed(plaintext)

        sock = MagicMock()
        ws = imap_compress._CompressedSocket(sock, initial_compressed=compressed)

        # Should return the pre-decompressed data without hitting socket
        result = ws.recv(4096)
        assert result == plaintext
        sock.recv.assert_not_called()

    def test_shutdown_proxied(self):
        sock = MagicMock()
        ws = imap_compress._CompressedSocket(sock)
        ws.shutdown(2)
        sock.shutdown.assert_called_once_with(2)

    def test_close_proxied(self):
        sock = MagicMock()
        ws = imap_compress._CompressedSocket(sock)
        ws.close()
        sock.close.assert_called_once()

    def test_makefile_returns_buffered_reader(self):
        import io

        plaintext = b"* OK ready\r\n"
        compressed = self._make_compressed(plaintext)

        sock = MagicMock()
        sock.recv.return_value = compressed

        ws = imap_compress._CompressedSocket(sock)
        f = ws.makefile("rb")
        assert isinstance(f, io.BufferedReader)
        assert f.readline() == plaintext

    def test_getattr_proxied(self):
        sock = MagicMock()
        sock.gettimeout.return_value = 30
        ws = imap_compress._CompressedSocket(sock)
        assert ws.gettimeout() == 30

    def test_multiple_sendall_share_compressor_state(self):
        """Verify the compressor maintains state across calls (streaming)."""
        sock = MagicMock()
        ws = imap_compress._CompressedSocket(sock)

        ws.sendall(b"first ")
        ws.sendall(b"second")

        assert sock.sendall.call_count == 2
        # Both calls should produce decompressible data
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        result = b""
        for call in sock.sendall.call_args_list:
            result += d.decompress(call[0][0])
        assert result == b"first second"

    def test_recv_loops_on_partial_deflate_block(self):
        """Decompress can return b'' for partial blocks; recv must not return that as EOF."""
        sock = MagicMock()
        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)

        # Build a compressed stream, then split it mid-block so the first
        # chunk decompresses to b"" and the second completes the block.
        full_compressed = c.compress(b"hello\r\n") + c.flush(zlib.Z_SYNC_FLUSH)
        # Split at byte 1 — the first fragment is too short to produce output
        part1 = full_compressed[:1]
        part2 = full_compressed[1:]
        sock.recv.side_effect = [part1, part2]

        ws = imap_compress._CompressedSocket(sock)
        result = ws.recv(4096)

        assert result == b"hello\r\n"
        assert sock.recv.call_count == 2

    def test_recv_returns_empty_on_real_eof(self):
        """True socket EOF (b'') should still return b''."""
        sock = MagicMock()
        sock.recv.return_value = b""

        ws = imap_compress._CompressedSocket(sock)
        assert ws.recv(4096) == b""

    def test_recv_multiple_chunks(self):
        """Simulate receiving data across multiple socket reads."""
        chunk1 = b"line one\r\n"
        chunk2 = b"line two\r\n"

        sock = MagicMock()
        # Server compressor maintains state across writes
        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        compressed1 = c.compress(chunk1) + c.flush(zlib.Z_SYNC_FLUSH)
        compressed2 = c.compress(chunk2) + c.flush(zlib.Z_SYNC_FLUSH)
        sock.recv.side_effect = [compressed1, compressed2]

        ws = imap_compress._CompressedSocket(sock)
        assert ws.recv(4096) == chunk1
        assert ws.recv(4096) == chunk2


class TestEnableCompression:
    """Tests for the enable_compression() function."""

    def test_returns_false_when_capability_missing(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "IDLE")
        assert imap_compress.enable_compression(conn) is False

    def test_returns_false_when_capability_missing_bytes(self):
        conn = MagicMock()
        conn.capabilities = (b"IMAP4REV1", b"IDLE")
        assert imap_compress.enable_compression(conn) is False

    def test_returns_false_when_no_capabilities_attr(self):
        conn = MagicMock(spec=[])
        assert imap_compress.enable_compression(conn) is False

    def test_returns_false_when_command_fails(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("NO", [b"compression not available"])

        assert imap_compress.enable_compression(conn) is False

    def test_returns_false_when_command_raises(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.side_effect = Exception("network error")

        assert imap_compress.enable_compression(conn) is False

    def test_enables_compression_with_bytes_capabilities(self):
        """Real imaplib stores capabilities as bytes; verify they are handled."""
        conn = MagicMock()
        conn.capabilities = (b"IMAP4REV1", b"COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"DEFLATE active"])
        conn._readbuf = []
        conn.sock = MagicMock()

        result = imap_compress.enable_compression(conn)

        assert result is True
        assert isinstance(conn.sock, imap_compress._CompressedSocket)

    def test_enables_compression_on_success(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"DEFLATE active"])
        conn._readbuf = []
        conn.sock = MagicMock()

        result = imap_compress.enable_compression(conn)

        assert result is True
        assert isinstance(conn.sock, imap_compress._CompressedSocket)

    def test_drains_readbuf_on_success(self):
        # Simulate leftover compressed data in the read buffer
        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        compressed = c.compress(b"* 1 EXISTS\r\n") + c.flush(zlib.Z_SYNC_FLUSH)

        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"ok"])
        conn._readbuf = [compressed]
        conn.sock = MagicMock()

        imap_compress.enable_compression(conn)

        # readbuf should have been cleared
        assert len(conn._readbuf) == 0
        # The compressed leftover should be pre-decompressed in the wrapper
        assert conn.sock._recv_buf == b"* 1 EXISTS\r\n"

    def test_drains_bytearray_readbuf(self):
        """Real imaplib uses bytearray for _readbuf; verify drain handles it."""
        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        compressed = c.compress(b"* 2 EXISTS\r\n") + c.flush(zlib.Z_SYNC_FLUSH)

        conn = MagicMock()
        conn.capabilities = (b"IMAP4REV1", b"COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"ok"])
        conn._readbuf = bytearray(compressed)
        conn.sock = MagicMock()

        imap_compress.enable_compression(conn)

        assert len(conn._readbuf) == 0
        assert conn.sock._recv_buf == b"* 2 EXISTS\r\n"

    def test_drains_bytes_readbuf(self):
        """Some imaplib versions use bytes for _readbuf; verify drain handles it."""
        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        compressed = c.compress(b"* 3 EXISTS\r\n") + c.flush(zlib.Z_SYNC_FLUSH)

        conn = MagicMock()
        conn.capabilities = (b"IMAP4REV1", b"COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"ok"])
        conn._readbuf = bytes(compressed)
        conn.sock = MagicMock()

        imap_compress.enable_compression(conn)

        assert conn._readbuf == b""
        assert conn.sock._recv_buf == b"* 3 EXISTS\r\n"

    def test_drains_file_buffer(self):
        """BufferedReader may have read-ahead bytes beyond the OK response."""
        import io

        c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        compressed = c.compress(b"* 4 EXISTS\r\n") + c.flush(zlib.Z_SYNC_FLUSH)

        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"ok"])
        conn._readbuf = b""
        conn.sock = MagicMock()

        # Simulate a BufferedReader with read-ahead compressed bytes
        old_file = io.BufferedReader(io.BytesIO(compressed))
        old_file.peek(65536)  # fill the buffer
        conn._file = old_file

        imap_compress.enable_compression(conn)

        assert conn.sock._recv_buf == b"* 4 EXISTS\r\n"

    def test_calls_log_fn(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"ok"])
        conn._readbuf = []
        conn.sock = MagicMock()

        messages = []
        imap_compress.enable_compression(conn, log_fn=messages.append)

        assert len(messages) == 1
        assert "compression enabled" in messages[0]

    def test_logs_when_not_supported(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1",)  # No COMPRESS

        messages = []
        imap_compress.enable_compression(conn, log_fn=messages.append)

        assert len(messages) == 1
        assert "not supported" in messages[0]

    def test_logs_when_rejected(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("NO", [b"not available"])

        messages = []
        imap_compress.enable_compression(conn, log_fn=messages.append)

        assert len(messages) == 1
        assert "rejected" in messages[0]

    def test_logs_when_negotiation_fails(self):
        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.side_effect = Exception("network error")

        messages = []
        imap_compress.enable_compression(conn, log_fn=messages.append)

        assert len(messages) == 1
        assert "failed" in messages[0]

    def test_recreates_file(self):
        import io

        conn = MagicMock()
        conn.capabilities = ("IMAP4REV1", "COMPRESS=DEFLATE")
        conn._simple_command.return_value = ("OK", [b"ok"])
        conn._readbuf = []
        real_sock = MagicMock()
        conn.sock = real_sock

        imap_compress.enable_compression(conn)

        # _file should be a BufferedReader over the compressed socket
        assert isinstance(conn._file, io.BufferedReader)


class TestIntegrationWithGetImapConnection:
    """Test that enable_compression is called during connection setup."""

    @patch("utils.imap_common.imaplib")
    @patch("utils.imap_compress.enable_compression")
    def test_compression_attempted_after_login(self, mock_compress, mock_imaplib):
        from utils import imap_common

        mock_conn = MagicMock()
        mock_imaplib.IMAP4_SSL.return_value = mock_conn

        imap_common.get_imap_connection("imap.example.com", "user", password="pass")

        mock_conn.login.assert_called_once()
        mock_compress.assert_called_once_with(mock_conn, log_fn=imap_common.safe_print)

    @patch("utils.imap_common.imaplib")
    @patch("utils.imap_compress.enable_compression")
    def test_compression_attempted_after_oauth2(self, mock_compress, mock_imaplib):
        from utils import imap_common

        mock_conn = MagicMock()
        mock_imaplib.IMAP4_SSL.return_value = mock_conn

        imap_common.get_imap_connection("imap.example.com", "user", oauth2_token="token123")

        mock_conn.authenticate.assert_called_once()
        mock_compress.assert_called_once_with(mock_conn, log_fn=imap_common.safe_print)
