"""CLI worker entry point for desktop bundles and cooperative cancellation."""

from __future__ import annotations

import _thread
import os
import runpy
import sys
import threading

MODULES = frozenset({"imap_count", "imap_compare", "imap_backup", "imap_restore", "imap_migrate"})


def main(argv=None):
    """Dispatch only supported commands, without requiring a Python executable."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in MODULES:
        raise SystemExit("Unknown IMAP worker operation")
    module, *arguments = args
    sys.argv = [module, *arguments]

    def watch_cancel():
        pending = b""
        try:
            while chunk := os.read(0, 128):
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if line.strip() == b"cancel":
                        _thread.interrupt_main()
                        return
        except OSError:
            return

    threading.Thread(target=watch_cancel, daemon=True, name="imap-cancel").start()
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
