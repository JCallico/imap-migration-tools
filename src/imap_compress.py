"""IMAP COMPRESS=DEFLATE support (RFC 4978).

Provides a transparent compression wrapper for stdlib imaplib connections.
After authentication, call ``enable_compression(conn)`` to negotiate
COMPRESS=DEFLATE with the server.  All subsequent IMAP traffic is then
compressed/decompressed automatically via zlib.

The implementation follows imaplib's own STARTTLS pattern: send the
command, and on OK replace ``self.sock`` with a wrapper.
"""

from __future__ import annotations

import io
import zlib
from collections.abc import Callable


class _CompressedRawIO(io.RawIOBase):
    """Minimal RawIOBase adapter so ``makefile()`` can return a BufferedReader
    that reads through the decompression layer."""

    def __init__(self, compressed_sock: _CompressedSocket):
        self._sock = compressed_sock

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray | memoryview) -> int:
        data = self._sock.recv(len(b))
        if not data:
            return 0
        n = len(data)
        b[:n] = data
        return n


class _CompressedSocket:
    """Socket wrapper that adds zlib DEFLATE compression/decompression.

    Wraps a real socket (typically SSL) so that:
    - ``sendall()`` compresses data before sending
    - ``recv()`` decompresses data after receiving

    Python 3.13's imaplib reads via ``self.sock.recv()`` directly,
    so intercepting at the socket level is sufficient.
    """

    def __init__(self, sock, initial_compressed: bytes = b""):
        self._sock = sock
        self._compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        # Buffer for decompressed data not yet consumed by recv()
        self._recv_buf = b""
        # If there was read-ahead data in imaplib's buffer after the
        # COMPRESS OK response, it is already compressed and must be
        # fed to the decompressor.
        if initial_compressed:
            self._recv_buf = self._decompressor.decompress(initial_compressed)

    # -- outgoing (compress) ---------------------------------------------------

    def sendall(self, data: bytes) -> None:
        compressed = self._compressor.compress(data)
        compressed += self._compressor.flush(zlib.Z_SYNC_FLUSH)
        self._sock.sendall(compressed)

    def send(self, data: bytes) -> int:
        self.sendall(data)
        return len(data)

    # -- incoming (decompress) -------------------------------------------------

    def recv(self, bufsize: int) -> bytes:
        # Return buffered decompressed data first
        if self._recv_buf:
            chunk = self._recv_buf[:bufsize]
            self._recv_buf = self._recv_buf[bufsize:]
            return chunk

        # Read and decompress until we have at least 1 byte or true EOF.
        # zlib can produce b"" for partial DEFLATE blocks; returning that
        # would signal EOF to imaplib and break the connection.
        decompressed = b""
        while not decompressed:
            raw = self._sock.recv(max(bufsize, 16384))
            if not raw:
                return b""  # real EOF
            decompressed = self._decompressor.decompress(raw)

        if len(decompressed) > bufsize:
            self._recv_buf = decompressed[bufsize:]
            return decompressed[:bufsize]
        return decompressed

    # -- lifecycle / proxy -----------------------------------------------------

    def shutdown(self, how: int) -> None:
        self._sock.shutdown(how)

    def close(self) -> None:
        self._sock.close()

    def makefile(self, *args, **kwargs):
        # Older Python imaplib reads from conn._file (a file object)
        # rather than conn.sock.recv() directly.  The file must read
        # through the decompression layer, not from the raw socket.
        return io.BufferedReader(_CompressedRawIO(self))

    def __getattr__(self, name: str):
        return getattr(self._sock, name)


def enable_compression(
    conn,
    *,
    log_fn: Callable[[str], None] | None = None,
) -> bool:
    """Negotiate COMPRESS=DEFLATE on a raw imaplib IMAP4/IMAP4_SSL connection.

    Must be called **after** authentication (login/XOAUTH2).

    Returns True if compression was successfully enabled, False otherwise
    (e.g. server does not advertise the capability, or the command failed).
    """
    raw_caps = getattr(conn, "capabilities", ())
    caps = {c.decode() if isinstance(c, bytes) else c for c in raw_caps}
    if "COMPRESS=DEFLATE" not in caps:
        if log_fn is not None:
            log_fn("Deflate compression not supported by server")
        return False

    try:
        typ, _data = conn._simple_command("COMPRESS", "DEFLATE")
    except Exception:
        if log_fn is not None:
            log_fn("Deflate compression negotiation failed")
        return False

    if typ != "OK":
        if log_fn is not None:
            log_fn("Deflate compression rejected by server")
        return False

    # Drain any read-ahead data from imaplib's internal buffers.
    # After the server sends OK, all subsequent data is compressed.
    # If recv() read past the OK response, the leftover bytes are
    # already compressed and must be fed to the decompressor.
    leftover = b""

    # conn._file (BufferedReader) may have read-ahead bytes beyond
    # the OK response that are already compressed.  Drain them.
    old_file = getattr(conn, "_file", None)
    if old_file is not None:
        try:
            buffered = old_file.peek(65536)
            if isinstance(buffered, (bytes, bytearray)) and buffered:
                leftover += bytes(buffered)
        except Exception:
            pass

    readbuf = getattr(conn, "_readbuf", None)
    if readbuf:
        if isinstance(readbuf, (bytes, bytearray)):
            leftover += bytes(readbuf)
        else:
            leftover += b"".join(readbuf)
        if isinstance(readbuf, bytes):
            conn._readbuf = b""
        else:
            readbuf.clear()

    # Replace the socket (follows the STARTTLS pattern in imaplib).
    conn.sock = _CompressedSocket(conn.sock, initial_compressed=leftover)
    conn._file = conn.sock.makefile("rb")

    if log_fn is not None:
        log_fn("Deflate compression enabled")

    return True
